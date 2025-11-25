/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_log.c - Logging subsystem implementation
 * 
 * Provides unified logging for all DEFT components with support
 * for console output, file logging, and colored messages.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>

#include "deft_types.h"
#include "deft_log.h"

/* ============================================================================
 * Private Constants
 * ============================================================================ */

/* ANSI color codes */
#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_RED        "\033[31m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_BLUE       "\033[34m"
#define ANSI_MAGENTA    "\033[35m"
#define ANSI_CYAN       "\033[36m"
#define ANSI_WHITE      "\033[37m"

/* Log level configuration */
static const struct {
    const char *name;       /* Level name */
    const char *color;      /* ANSI color code */
    FILE **stream;          /* Output stream (stdout/stderr) */
} g_level_config[] = {
    [DEFT_LOG_TRACE] = {"TRACE", ANSI_WHITE,   NULL},
    [DEFT_LOG_DEBUG] = {"DEBUG", ANSI_CYAN,    NULL},
    [DEFT_LOG_INFO]  = {"INFO",  ANSI_GREEN,   NULL},
    [DEFT_LOG_WARN]  = {"WARN",  ANSI_YELLOW,  NULL},
    [DEFT_LOG_ERROR] = {"ERROR", ANSI_RED,     NULL},
    [DEFT_LOG_FATAL] = {"FATAL", ANSI_MAGENTA, NULL},
    [DEFT_LOG_ALERT] = {"ALERT", ANSI_RED,     NULL}
};

/* ============================================================================
 * Private State
 * ============================================================================ */

static struct {
    bool initialized;
    deft_log_config_t config;
    FILE *log_file;
    pthread_mutex_t mutex;
    size_t current_file_size;
} g_log = {
    .initialized = false,
    .log_file = NULL,
    .current_file_size = 0
};

/* ============================================================================
 * Private Helper Functions
 * ============================================================================ */

/**
 * Get current timestamp as formatted string.
 */
static void get_timestamp(char *buf, size_t size)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/**
 * Get short filename from full path.
 */
static const char* get_short_filename(const char *path)
{
    if (!path) return "unknown";
    
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/**
 * Rotate log files.
 */
static int rotate_log_files(void)
{
    if (!g_log.config.log_to_file || !g_log.log_file) {
        return 0;
    }
    
    /* Close current file */
    fclose(g_log.log_file);
    g_log.log_file = NULL;
    
    /* Rotate existing backup files */
    char old_path[DEFT_MAX_PATH + 16];
    char new_path[DEFT_MAX_PATH + 16];
    
    for (int i = g_log.config.max_backup_files - 1; i > 0; i--) {
        snprintf(old_path, sizeof(old_path), "%.4080s.%d", 
                 g_log.config.log_file_path, i - 1);
        snprintf(new_path, sizeof(new_path), "%.4080s.%d",
                 g_log.config.log_file_path, i);
        rename(old_path, new_path);
    }
    
    /* Move current log to .0 */
    snprintf(new_path, sizeof(new_path), "%.4080s.0", g_log.config.log_file_path);
    rename(g_log.config.log_file_path, new_path);
    
    /* Open new log file */
    g_log.log_file = fopen(g_log.config.log_file_path, "w");
    if (!g_log.log_file) {
        return -1;
    }
    
    g_log.current_file_size = 0;
    
    return 0;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/**
 * Initialize the logging subsystem.
 */
int deft_log_init(const deft_log_config_t *config)
{
    if (g_log.initialized) {
        return 0;
    }
    
    /* Initialize mutex */
    if (pthread_mutex_init(&g_log.mutex, NULL) != 0) {
        return -1;
    }
    
    /* Apply configuration or use defaults */
    if (config) {
        memcpy(&g_log.config, config, sizeof(deft_log_config_t));
    } else {
        /* Default configuration */
        g_log.config.min_level = DEFT_LOG_INFO;
        g_log.config.log_to_console = true;
        g_log.config.log_to_file = false;
        g_log.config.log_to_syslog = false;
        g_log.config.colorize = isatty(STDOUT_FILENO);
        g_log.config.include_timestamp = true;
        g_log.config.include_source = false;
        g_log.config.max_file_size = 10 * 1024 * 1024;  /* 10 MB */
        g_log.config.max_backup_files = 5;
    }
    
    /* Open log file if configured */
    if (g_log.config.log_to_file && g_log.config.log_file_path[0]) {
        g_log.log_file = fopen(g_log.config.log_file_path, "a");
        if (!g_log.log_file) {
            fprintf(stderr, "Warning: Failed to open log file: %s\n",
                    g_log.config.log_file_path);
            g_log.config.log_to_file = false;
        }
    }
    
    g_log.initialized = true;
    
    return 0;
}

/**
 * Cleanup logging resources.
 */
void deft_log_cleanup(void)
{
    if (!g_log.initialized) {
        return;
    }
    
    pthread_mutex_lock(&g_log.mutex);
    
    if (g_log.log_file) {
        fclose(g_log.log_file);
        g_log.log_file = NULL;
    }
    
    pthread_mutex_unlock(&g_log.mutex);
    pthread_mutex_destroy(&g_log.mutex);
    
    g_log.initialized = false;
}

/**
 * Log a message.
 */
void deft_log(deft_log_level_t level, const char *file, int line,
              const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    deft_log_v(level, file, line, fmt, args);
    va_end(args);
}

/**
 * Log a message (va_list version).
 */
void deft_log_v(deft_log_level_t level, const char *file, int line,
                const char *fmt, va_list args)
{
    /* Check if initialized - use stderr as fallback */
    if (!g_log.initialized) {
        if (level >= DEFT_LOG_WARN) {
            fprintf(stderr, "[%s] ", g_level_config[level].name);
            vfprintf(stderr, fmt, args);
            fprintf(stderr, "\n");
        }
        return;
    }
    
    /* Check minimum level */
    if (level < g_log.config.min_level) {
        return;
    }
    
    pthread_mutex_lock(&g_log.mutex);
    
    /* Format timestamp */
    char timestamp[32] = "";
    if (g_log.config.include_timestamp) {
        get_timestamp(timestamp, sizeof(timestamp));
    }
    
    /* Format source location */
    char source[128] = "";
    if (g_log.config.include_source && file) {
        snprintf(source, sizeof(source), " [%s:%d]", 
                 get_short_filename(file), line);
    }
    
    /* Format message */
    char message[4096];
    vsnprintf(message, sizeof(message), fmt, args);
    
    /* Output to console */
    if (g_log.config.log_to_console) {
        FILE *out = (level >= DEFT_LOG_WARN) ? stderr : stdout;
        
        if (g_log.config.colorize) {
            fprintf(out, "%s[%s]%s %s%s%s%s\n",
                    g_level_config[level].color,
                    g_level_config[level].name,
                    ANSI_RESET,
                    timestamp[0] ? timestamp : "",
                    timestamp[0] ? " " : "",
                    message,
                    source);
        } else {
            fprintf(out, "[%s] %s%s%s%s\n",
                    g_level_config[level].name,
                    timestamp[0] ? timestamp : "",
                    timestamp[0] ? " " : "",
                    message,
                    source);
        }
        fflush(out);
    }
    
    /* Output to file */
    if (g_log.config.log_to_file && g_log.log_file) {
        int written = fprintf(g_log.log_file, "[%s] %s%s%s%s\n",
                              g_level_config[level].name,
                              timestamp[0] ? timestamp : "",
                              timestamp[0] ? " " : "",
                              message,
                              source);
        fflush(g_log.log_file);
        
        if (written > 0) {
            g_log.current_file_size += written;
            
            /* Check for rotation */
            if (g_log.config.max_file_size > 0 &&
                g_log.current_file_size >= g_log.config.max_file_size) {
                rotate_log_files();
            }
        }
    }
    
    pthread_mutex_unlock(&g_log.mutex);
}

/**
 * Set minimum log level.
 */
void deft_log_set_level(deft_log_level_t level)
{
    g_log.config.min_level = level;
}

/**
 * Get current minimum log level.
 */
deft_log_level_t deft_log_get_level(void)
{
    return g_log.config.min_level;
}

/**
 * Enable or disable console output.
 */
void deft_log_set_console(bool enable)
{
    g_log.config.log_to_console = enable;
}

/**
 * Enable or disable file output.
 */
int deft_log_set_file(bool enable, const char *path)
{
    pthread_mutex_lock(&g_log.mutex);
    
    /* Close existing file */
    if (g_log.log_file) {
        fclose(g_log.log_file);
        g_log.log_file = NULL;
    }
    
    g_log.config.log_to_file = enable;
    
    if (enable) {
        if (path) {
            strncpy(g_log.config.log_file_path, path, 
                    sizeof(g_log.config.log_file_path) - 1);
        }
        
        if (g_log.config.log_file_path[0]) {
            g_log.log_file = fopen(g_log.config.log_file_path, "a");
            if (!g_log.log_file) {
                pthread_mutex_unlock(&g_log.mutex);
                return -1;
            }
        }
    }
    
    pthread_mutex_unlock(&g_log.mutex);
    return 0;
}

/**
 * Get log level name.
 */
const char* deft_log_level_name(deft_log_level_t level)
{
    if (level < 0 || level > DEFT_LOG_ALERT) {
        return "UNKNOWN";
    }
    return g_level_config[level].name;
}

/**
 * Manually rotate log files.
 */
int deft_log_rotate(void)
{
    pthread_mutex_lock(&g_log.mutex);
    int result = rotate_log_files();
    pthread_mutex_unlock(&g_log.mutex);
    return result;
}

/**
 * Flush log buffers.
 */
void deft_log_flush(void)
{
    pthread_mutex_lock(&g_log.mutex);
    
    if (g_log.log_file) {
        fflush(g_log.log_file);
    }
    fflush(stdout);
    fflush(stderr);
    
    pthread_mutex_unlock(&g_log.mutex);
}

/**
 * Log a security alert for malware detection.
 */
void deft_log_alert_detection(pid_t pid, const char *path,
                              float score, uint32_t flags,
                              int action)
{
    const char *action_str = "NONE";
    switch (action) {
        case DEFT_ACTION_LOG:        action_str = "LOG"; break;
        case DEFT_ACTION_ALERT:      action_str = "ALERT"; break;
        case DEFT_ACTION_BLOCK:      action_str = "BLOCKED"; break;
        case DEFT_ACTION_QUARANTINE: action_str = "QUARANTINED"; break;
    }
    
    /* Build flags string */
    char flags_str[256] = "";
    char *p = flags_str;
    
    if (flags & DEFT_FLAG_SUSPICIOUS_PATH) p += sprintf(p, "SUSPICIOUS_PATH ");
    if (flags & DEFT_FLAG_PACKED) p += sprintf(p, "PACKED ");
    if (flags & DEFT_FLAG_HIGH_ENTROPY) p += sprintf(p, "HIGH_ENTROPY ");
    if (flags & DEFT_FLAG_ROOTKIT_BEHAVIOR) p += sprintf(p, "ROOTKIT ");
    if (flags & DEFT_FLAG_RANSOMWARE) p += sprintf(p, "RANSOMWARE ");
    if (flags & DEFT_FLAG_CRYPTO_MINING) p += sprintf(p, "CRYPTOMINER ");
    if (flags & DEFT_FLAG_BACKDOOR) p += sprintf(p, "BACKDOOR ");
    
    DEFT_LOG_ALERT("MALWARE DETECTED: pid=%d path=%s score=%.2f action=%s flags=[%s]",
                   pid, path ? path : "unknown", score, action_str, flags_str);
}
