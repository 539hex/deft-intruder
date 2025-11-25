/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_monitor.c - Process monitoring implementation
 * 
 * This module monitors running processes by periodically scanning
 * the /proc filesystem. This approach works on all Linux kernels
 * without requiring eBPF or kernel modules.
 * 
 * The monitor detects:
 * - New process creation
 * - Process termination
 * - Suspicious process behavior
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <time.h>

#include "deft_types.h"
#include "deft_monitor.h"
#include "deft_features.h"
#include "deft_log.h"

/* ============================================================================
 * Private Constants
 * ============================================================================ */

/* Path to the proc filesystem */
#define PROC_PATH   "/proc"

/* Maximum number of PIDs we can track */
#define MAX_TRACKED_PIDS    65536

/* Whitelist maximum entries */
#define MAX_WHITELIST_ENTRIES   1024

/* Suspicious paths - processes running from these locations are flagged */
static const char *SUSPICIOUS_PATHS[] = {
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/.hidden",
    "/...",               /* Common malware hiding trick */
    NULL
};

/* Paths that should never be blocked (critical system processes) */
static const char *CRITICAL_PATHS[] = {
    "/lib/systemd/",
    "/usr/lib/systemd/",
    "/sbin/init",
    "/usr/sbin/",
    "/bin/",
    "/usr/bin/",
    "/lib/",
    "/usr/lib/",
    NULL
};

/* ============================================================================
 * Private State
 * ============================================================================ */

/* Tracking structure for known PIDs */
typedef struct {
    pid_t pid;
    uint64_t first_seen;    /* Timestamp when first seen */
    bool analyzed;          /* Whether we've analyzed this process */
    char exe_path[512];     /* Cached executable path */
} tracked_pid_t;

/* Monitor state */
static struct {
    bool initialized;
    bool running;
    pthread_t thread;
    pthread_mutex_t mutex;
    
    /* Configuration */
    deft_monitor_config_t config;
    
    /* PID tracking (hash table for O(1) lookup) */
    tracked_pid_t *tracked_pids;
    size_t tracked_count;
    
    /* Whitelist */
    char whitelist[MAX_WHITELIST_ENTRIES][DEFT_MAX_PATH];
    size_t whitelist_count;
    
    /* Statistics */
    deft_stats_t stats;
    
} g_monitor = {
    .initialized = false,
    .running = false,
    .tracked_count = 0,
    .whitelist_count = 0,
};

/* ============================================================================
 * Private Helper Functions
 * ============================================================================ */

/**
 * Get current timestamp in milliseconds.
 */
static uint64_t get_timestamp_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/**
 * Check if a PID directory entry is valid.
 */
static bool is_pid_directory(const char *name)
{
    if (!name || !name[0]) {
        return false;
    }
    
    /* Check if all characters are digits */
    for (const char *p = name; *p; p++) {
        if (!isdigit(*p)) {
            return false;
        }
    }
    
    return true;
}

/**
 * Read a file from /proc into a buffer.
 */
static int read_proc_file(pid_t pid, const char *filename, 
                          char *buffer, size_t size)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, filename);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    ssize_t n = read(fd, buffer, size - 1);
    close(fd);
    
    if (n < 0) {
        return -1;
    }
    
    buffer[n] = '\0';
    return (int)n;
}

/**
 * Find a tracked PID entry.
 */
static tracked_pid_t* find_tracked_pid(pid_t pid)
{
    for (size_t i = 0; i < g_monitor.tracked_count; i++) {
        if (g_monitor.tracked_pids[i].pid == pid) {
            return &g_monitor.tracked_pids[i];
        }
    }
    return NULL;
}

/**
 * Add a new PID to tracking.
 */
static tracked_pid_t* add_tracked_pid(pid_t pid)
{
    /* Check if we're at capacity */
    if (g_monitor.tracked_count >= MAX_TRACKED_PIDS) {
        /* Remove oldest entries (simple FIFO) */
        memmove(g_monitor.tracked_pids, 
                g_monitor.tracked_pids + 1000,
                (g_monitor.tracked_count - 1000) * sizeof(tracked_pid_t));
        g_monitor.tracked_count -= 1000;
    }
    
    /* Add new entry */
    tracked_pid_t *entry = &g_monitor.tracked_pids[g_monitor.tracked_count++];
    entry->pid = pid;
    entry->first_seen = get_timestamp_ms();
    entry->analyzed = false;
    entry->exe_path[0] = '\0';
    
    return entry;
}

/**
 * Remove a PID from tracking.
 */
static void remove_tracked_pid(pid_t pid)
{
    for (size_t i = 0; i < g_monitor.tracked_count; i++) {
        if (g_monitor.tracked_pids[i].pid == pid) {
            /* Shift remaining entries */
            memmove(&g_monitor.tracked_pids[i],
                    &g_monitor.tracked_pids[i + 1],
                    (g_monitor.tracked_count - i - 1) * sizeof(tracked_pid_t));
            g_monitor.tracked_count--;
            return;
        }
    }
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/**
 * Initialize the process monitoring subsystem.
 */
int deft_monitor_init(void)
{
    if (g_monitor.initialized) {
        return 0;
    }
    
    /* Allocate PID tracking array */
    g_monitor.tracked_pids = calloc(MAX_TRACKED_PIDS, sizeof(tracked_pid_t));
    if (!g_monitor.tracked_pids) {
        DEFT_LOG_ERROR("Failed to allocate PID tracking array");
        return -1;
    }
    
    /* Initialize mutex */
    if (pthread_mutex_init(&g_monitor.mutex, NULL) != 0) {
        free(g_monitor.tracked_pids);
        DEFT_LOG_ERROR("Failed to initialize mutex");
        return -1;
    }
    
    /* Initialize statistics */
    memset(&g_monitor.stats, 0, sizeof(g_monitor.stats));
    g_monitor.stats.start_time = get_timestamp_ms();
    
    g_monitor.initialized = true;
    DEFT_LOG_INFO("Process monitor initialized");
    
    return 0;
}

/**
 * Cleanup monitoring resources.
 */
void deft_monitor_cleanup(void)
{
    if (!g_monitor.initialized) {
        return;
    }
    
    /* Stop monitor if running */
    if (g_monitor.running) {
        deft_monitor_stop();
    }
    
    /* Free resources */
    if (g_monitor.tracked_pids) {
        free(g_monitor.tracked_pids);
        g_monitor.tracked_pids = NULL;
    }
    
    pthread_mutex_destroy(&g_monitor.mutex);
    
    g_monitor.initialized = false;
    DEFT_LOG_INFO("Process monitor cleaned up");
}

/**
 * Get executable path of a process.
 */
int deft_monitor_get_exe_path(pid_t pid, char *path, size_t path_len)
{
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    
    ssize_t len = readlink(link_path, path, path_len - 1);
    if (len < 0) {
        return -1;
    }
    
    path[len] = '\0';
    return 0;
}

/**
 * Get command line of a process.
 */
int deft_monitor_get_cmdline(pid_t pid, char *cmdline, size_t len)
{
    int result = read_proc_file(pid, "cmdline", cmdline, len);
    if (result < 0) {
        return -1;
    }
    
    /* Replace null separators with spaces */
    for (int i = 0; i < result - 1; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    
    return 0;
}

/**
 * Get information about a specific process.
 */
int deft_monitor_get_process(pid_t pid, deft_process_t *process)
{
    if (!process) {
        return -1;
    }
    
    memset(process, 0, sizeof(deft_process_t));
    process->pid = pid;
    
    /* Get executable path */
    if (deft_monitor_get_exe_path(pid, process->exe_path, sizeof(process->exe_path)) < 0) {
        return -1;  /* Process may have exited */
    }
    
    /* Get command line */
    deft_monitor_get_cmdline(pid, process->cmdline, sizeof(process->cmdline));
    
    /* Get process name from /proc/pid/comm */
    read_proc_file(pid, "comm", process->comm, sizeof(process->comm));
    
    /* Remove trailing newline from comm */
    size_t comm_len = strlen(process->comm);
    if (comm_len > 0 && process->comm[comm_len - 1] == '\n') {
        process->comm[comm_len - 1] = '\0';
    }
    
    /* Get process status for UID/GID */
    char status_buf[4096];
    if (read_proc_file(pid, "status", status_buf, sizeof(status_buf)) > 0) {
        /* Parse UID and GID */
        char *line = strstr(status_buf, "Uid:");
        if (line) {
            sscanf(line, "Uid:\t%d", &process->uid);
        }
        
        line = strstr(status_buf, "Gid:");
        if (line) {
            sscanf(line, "Gid:\t%d", &process->gid);
        }
        
        line = strstr(status_buf, "PPid:");
        if (line) {
            sscanf(line, "PPid:\t%d", &process->ppid);
        }
    }
    
    return 0;
}

/**
 * Check if a path is in a suspicious location.
 */
bool deft_is_suspicious_path(const char *path)
{
    if (!path) {
        return false;
    }
    
    /* Check against suspicious path prefixes */
    for (int i = 0; SUSPICIOUS_PATHS[i] != NULL; i++) {
        if (strncmp(path, SUSPICIOUS_PATHS[i], strlen(SUSPICIOUS_PATHS[i])) == 0) {
            return true;
        }
    }
    
    /* Check for hidden files/directories */
    if (strstr(path, "/.") != NULL && strstr(path, "/..") == NULL) {
        return true;
    }
    
    return false;
}

/**
 * Kill a process.
 */
int deft_monitor_kill_process(pid_t pid)
{
    if (kill(pid, SIGKILL) < 0) {
        DEFT_LOG_ERROR("Failed to kill process %d: %s", pid, strerror(errno));
        return -1;
    }
    
    DEFT_LOG_WARN("Killed process %d", pid);
    g_monitor.stats.processes_blocked++;
    
    return 0;
}

/**
 * Suspend a process.
 */
int deft_monitor_suspend_process(pid_t pid)
{
    if (kill(pid, SIGSTOP) < 0) {
        DEFT_LOG_ERROR("Failed to suspend process %d: %s", pid, strerror(errno));
        return -1;
    }
    
    DEFT_LOG_INFO("Suspended process %d", pid);
    return 0;
}

/**
 * Resume a suspended process.
 */
int deft_monitor_resume_process(pid_t pid)
{
    if (kill(pid, SIGCONT) < 0) {
        DEFT_LOG_ERROR("Failed to resume process %d: %s", pid, strerror(errno));
        return -1;
    }
    
    DEFT_LOG_INFO("Resumed process %d", pid);
    return 0;
}

/**
 * Add a path to the whitelist.
 */
int deft_monitor_whitelist_add(const char *path)
{
    if (!path || g_monitor.whitelist_count >= MAX_WHITELIST_ENTRIES) {
        return -1;
    }
    
    pthread_mutex_lock(&g_monitor.mutex);
    
    /* Check if already whitelisted */
    for (size_t i = 0; i < g_monitor.whitelist_count; i++) {
        if (strcmp(g_monitor.whitelist[i], path) == 0) {
            pthread_mutex_unlock(&g_monitor.mutex);
            return 0;  /* Already exists */
        }
    }
    
    /* Add to whitelist */
    strncpy(g_monitor.whitelist[g_monitor.whitelist_count], 
            path, DEFT_MAX_PATH - 1);
    g_monitor.whitelist_count++;
    
    pthread_mutex_unlock(&g_monitor.mutex);
    
    DEFT_LOG_INFO("Added to whitelist: %s", path);
    return 0;
}

/**
 * Remove a path from the whitelist.
 */
int deft_monitor_whitelist_remove(const char *path)
{
    if (!path) {
        return -1;
    }
    
    pthread_mutex_lock(&g_monitor.mutex);
    
    for (size_t i = 0; i < g_monitor.whitelist_count; i++) {
        if (strcmp(g_monitor.whitelist[i], path) == 0) {
            /* Shift remaining entries */
            memmove(&g_monitor.whitelist[i],
                    &g_monitor.whitelist[i + 1],
                    (g_monitor.whitelist_count - i - 1) * DEFT_MAX_PATH);
            g_monitor.whitelist_count--;
            
            pthread_mutex_unlock(&g_monitor.mutex);
            DEFT_LOG_INFO("Removed from whitelist: %s", path);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&g_monitor.mutex);
    return -1;  /* Not found */
}

/**
 * Check if a path is whitelisted.
 */
bool deft_monitor_is_whitelisted(const char *path)
{
    if (!path) {
        return false;
    }
    
    pthread_mutex_lock(&g_monitor.mutex);
    
    for (size_t i = 0; i < g_monitor.whitelist_count; i++) {
        if (strcmp(g_monitor.whitelist[i], path) == 0) {
            pthread_mutex_unlock(&g_monitor.mutex);
            return true;
        }
    }
    
    /* Also check critical system paths */
    for (int i = 0; CRITICAL_PATHS[i] != NULL; i++) {
        if (strncmp(path, CRITICAL_PATHS[i], strlen(CRITICAL_PATHS[i])) == 0) {
            pthread_mutex_unlock(&g_monitor.mutex);
            return true;
        }
    }
    
    pthread_mutex_unlock(&g_monitor.mutex);
    return false;
}

/**
 * Load whitelist from a file.
 */
int deft_monitor_whitelist_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        DEFT_LOG_WARN("Failed to open whitelist file: %s", path);
        return -1;
    }
    
    char line[DEFT_MAX_PATH];
    int count = 0;
    
    while (fgets(line, sizeof(line), f) != NULL) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        if (deft_monitor_whitelist_add(line) == 0) {
            count++;
        }
    }
    
    fclose(f);
    DEFT_LOG_INFO("Loaded %d entries from whitelist: %s", count, path);
    
    return count;
}

/**
 * Perform a single scan of all running processes.
 */
int deft_monitor_scan_all(deft_process_callback_t callback, void *user_data)
{
    if (!callback) {
        return -1;
    }
    
    DIR *proc_dir = opendir(PROC_PATH);
    if (!proc_dir) {
        DEFT_LOG_ERROR("Failed to open /proc: %s", strerror(errno));
        return -1;
    }
    
    int count = 0;
    struct dirent *entry;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        /* Skip non-PID directories */
        if (!is_pid_directory(entry->d_name)) {
            continue;
        }
        
        pid_t pid = atoi(entry->d_name);
        
        /* Skip our own process */
        if (pid == getpid()) {
            continue;
        }
        
        /* Get process information */
        deft_process_t process;
        if (deft_monitor_get_process(pid, &process) < 0) {
            continue;  /* Process may have exited */
        }
        
        /* Skip whitelisted processes */
        if (deft_monitor_is_whitelisted(process.exe_path)) {
            continue;
        }
        
        /* Call the callback */
        callback(&process, user_data);
        count++;
        
        g_monitor.stats.processes_scanned++;
    }
    
    closedir(proc_dir);
    g_monitor.stats.last_scan_time = get_timestamp_ms();
    
    return count;
}

/**
 * Monitor thread function.
 * 
 * This thread continuously scans /proc for new processes
 * and invokes callbacks when changes are detected.
 */
static void* monitor_thread_func(void *arg)
{
    (void)arg;
    
    DEFT_LOG_INFO("Monitor thread started");
    
    while (g_monitor.running) {
        /* Scan /proc for all processes */
        DIR *proc_dir = opendir(PROC_PATH);
        if (!proc_dir) {
            DEFT_LOG_ERROR("Failed to open /proc");
            usleep(g_monitor.config.scan_interval_ms * 1000);
            continue;
        }
        
        /* Track which PIDs we see in this scan */
        bool seen_pids[MAX_TRACKED_PIDS] = {false};
        
        struct dirent *entry;
        while ((entry = readdir(proc_dir)) != NULL && g_monitor.running) {
            if (!is_pid_directory(entry->d_name)) {
                continue;
            }
            
            pid_t pid = atoi(entry->d_name);
            
            /* Skip our own process */
            if (pid == getpid()) {
                continue;
            }
            
            pthread_mutex_lock(&g_monitor.mutex);
            
            /* Check if this is a new process */
            tracked_pid_t *tracked = find_tracked_pid(pid);
            
            if (!tracked) {
                /* New process detected! */
                tracked = add_tracked_pid(pid);
                
                /* Get executable path */
                deft_monitor_get_exe_path(pid, tracked->exe_path, 
                                          sizeof(tracked->exe_path));
                
                pthread_mutex_unlock(&g_monitor.mutex);
                
                /* Skip whitelisted */
                if (!deft_monitor_is_whitelisted(tracked->exe_path)) {
                    /* Get full process info */
                    deft_process_t process;
                    if (deft_monitor_get_process(pid, &process) == 0) {
                        g_monitor.stats.processes_scanned++;
                        
                        /* Call the callback if configured */
                        if (g_monitor.config.on_process) {
                            deft_action_t action = g_monitor.config.on_process(
                                &process, g_monitor.config.user_data);
                            
                            /* Handle action */
                            if (action == DEFT_ACTION_BLOCK) {
                                deft_monitor_kill_process(pid);
                            }
                        }
                    }
                }
                
                pthread_mutex_lock(&g_monitor.mutex);
                tracked = find_tracked_pid(pid);  /* Re-find after unlock */
            }
            
            /* Mark as seen */
            if (tracked) {
                for (size_t i = 0; i < g_monitor.tracked_count; i++) {
                    if (g_monitor.tracked_pids[i].pid == pid) {
                        seen_pids[i] = true;
                        break;
                    }
                }
            }
            
            pthread_mutex_unlock(&g_monitor.mutex);
        }
        
        closedir(proc_dir);
        
        /* Clean up exited processes */
        pthread_mutex_lock(&g_monitor.mutex);
        
        for (size_t i = g_monitor.tracked_count; i > 0; i--) {
            if (!seen_pids[i - 1]) {
                pid_t exited_pid = g_monitor.tracked_pids[i - 1].pid;
                remove_tracked_pid(exited_pid);
                
                /* Call exit callback if configured */
                if (g_monitor.config.on_exit) {
                    pthread_mutex_unlock(&g_monitor.mutex);
                    g_monitor.config.on_exit(exited_pid, g_monitor.config.user_data);
                    pthread_mutex_lock(&g_monitor.mutex);
                }
            }
        }
        
        pthread_mutex_unlock(&g_monitor.mutex);
        
        g_monitor.stats.last_scan_time = get_timestamp_ms();
        
        /* Sleep until next scan */
        usleep(g_monitor.config.scan_interval_ms * 1000);
    }
    
    DEFT_LOG_INFO("Monitor thread stopped");
    return NULL;
}

/**
 * Start the process monitor.
 */
int deft_monitor_start(const deft_monitor_config_t *config)
{
    if (!g_monitor.initialized) {
        DEFT_LOG_ERROR("Monitor not initialized");
        return -1;
    }
    
    if (g_monitor.running) {
        DEFT_LOG_WARN("Monitor already running");
        return 0;
    }
    
    /* Copy configuration */
    if (config) {
        memcpy(&g_monitor.config, config, sizeof(deft_monitor_config_t));
    } else {
        /* Use defaults */
        g_monitor.config.scan_interval_ms = DEFT_SCAN_INTERVAL_MS;
        g_monitor.config.monitor_children = true;
        g_monitor.config.follow_forks = true;
        g_monitor.config.scan_on_exec = true;
    }
    
    /* Start monitor thread */
    g_monitor.running = true;
    
    if (pthread_create(&g_monitor.thread, NULL, monitor_thread_func, NULL) != 0) {
        g_monitor.running = false;
        DEFT_LOG_ERROR("Failed to create monitor thread");
        return -1;
    }
    
    DEFT_LOG_INFO("Process monitor started (interval: %u ms)", 
                  g_monitor.config.scan_interval_ms);
    
    return 0;
}

/**
 * Stop the process monitor.
 */
int deft_monitor_stop(void)
{
    if (!g_monitor.running) {
        return 0;
    }
    
    g_monitor.running = false;
    
    /* Wait for thread to finish */
    pthread_join(g_monitor.thread, NULL);
    
    DEFT_LOG_INFO("Process monitor stopped");
    
    return 0;
}

/**
 * Check if monitor is running.
 */
bool deft_monitor_is_running(void)
{
    return g_monitor.running;
}

/**
 * Get monitor statistics.
 */
int deft_monitor_get_stats(deft_stats_t *stats)
{
    if (!stats) {
        return -1;
    }
    
    pthread_mutex_lock(&g_monitor.mutex);
    memcpy(stats, &g_monitor.stats, sizeof(deft_stats_t));
    pthread_mutex_unlock(&g_monitor.mutex);
    
    return 0;
}
