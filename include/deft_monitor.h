/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_monitor.h - Process monitoring interface
 * 
 * This module monitors running processes using the /proc filesystem,
 * which is available on all Linux kernels without requiring eBPF.
 */

#ifndef DEFT_MONITOR_H
#define DEFT_MONITOR_H

#include "deft_types.h"

/* ============================================================================
 * Callback Function Types
 * ============================================================================ */

/**
 * Callback function type for new process detection.
 * 
 * Called whenever a new process is detected. The callback should
 * perform analysis and return an action to take.
 * 
 * @param process   Information about the new process
 * @param user_data User-provided context pointer
 * @return Action to take for this process
 */
typedef deft_action_t (*deft_process_callback_t)(deft_process_t *process, 
                                                  void *user_data);

/**
 * Callback function type for process exit detection.
 * 
 * Called when a monitored process exits.
 * 
 * @param pid       PID of the exited process
 * @param user_data User-provided context pointer
 */
typedef void (*deft_exit_callback_t)(pid_t pid, void *user_data);

/* ============================================================================
 * Monitor Configuration
 * ============================================================================ */

typedef struct {
    uint32_t scan_interval_ms;           /* Interval between scans */
    bool monitor_children;               /* Monitor child processes */
    bool follow_forks;                   /* Follow forked processes */
    bool scan_on_exec;                   /* Scan on exec, not just fork */
    deft_process_callback_t on_process;  /* New process callback */
    deft_exit_callback_t on_exit;        /* Process exit callback */
    void *user_data;                     /* User context for callbacks */
} deft_monitor_config_t;

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

/**
 * Initialize the process monitoring subsystem.
 * 
 * Sets up internal data structures for process tracking.
 * Must be called before starting the monitor.
 * 
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_init(void);

/**
 * Cleanup and release monitoring resources.
 * 
 * Stops any running monitor and frees all resources.
 */
void deft_monitor_cleanup(void);

/**
 * Start the process monitor.
 * 
 * Begins monitoring for new processes. This function creates
 * a background thread that periodically scans /proc.
 * 
 * @param config    Monitor configuration
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_start(const deft_monitor_config_t *config);

/**
 * Stop the process monitor.
 * 
 * Signals the monitor thread to stop and waits for it to finish.
 * 
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_stop(void);

/**
 * Check if the monitor is currently running.
 * 
 * @return true if running, false otherwise
 */
bool deft_monitor_is_running(void);

/**
 * Perform a single scan of all processes.
 * 
 * Scans /proc for all running processes. This is useful for
 * initial system scan or manual triggering.
 * 
 * @param callback  Callback for each process found
 * @param user_data User context for callback
 * @return Number of processes scanned, or negative on error
 */
int deft_monitor_scan_all(deft_process_callback_t callback, void *user_data);

/**
 * Get information about a specific process.
 * 
 * Retrieves process information from /proc/<pid>/.
 * 
 * @param pid       Process ID to query
 * @param process   Structure to receive process information
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_get_process(pid_t pid, deft_process_t *process);

/**
 * Get the executable path of a process.
 * 
 * Reads the /proc/<pid>/exe symbolic link.
 * 
 * @param pid       Process ID
 * @param path      Buffer to receive the path
 * @param path_len  Size of path buffer
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_get_exe_path(pid_t pid, char *path, size_t path_len);

/**
 * Get the command line of a process.
 * 
 * Reads /proc/<pid>/cmdline.
 * 
 * @param pid       Process ID
 * @param cmdline   Buffer to receive command line
 * @param len       Size of buffer
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_get_cmdline(pid_t pid, char *cmdline, size_t len);

/**
 * Kill a process.
 * 
 * Sends SIGKILL to terminate the process.
 * 
 * @param pid       Process ID to kill
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_kill_process(pid_t pid);

/**
 * Suspend a process.
 * 
 * Sends SIGSTOP to suspend the process.
 * 
 * @param pid       Process ID to suspend
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_suspend_process(pid_t pid);

/**
 * Resume a suspended process.
 * 
 * Sends SIGCONT to resume the process.
 * 
 * @param pid       Process ID to resume
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_resume_process(pid_t pid);

/**
 * Check if a path is in a suspicious location.
 * 
 * Returns true for paths in /tmp, /dev/shm, hidden directories, etc.
 * 
 * @param path      Path to check
 * @return true if suspicious, false otherwise
 */
bool deft_is_suspicious_path(const char *path);

/**
 * Add a process to the whitelist.
 * 
 * Whitelisted processes are not scanned or blocked.
 * 
 * @param path      Executable path to whitelist
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_whitelist_add(const char *path);

/**
 * Remove a process from the whitelist.
 * 
 * @param path      Executable path to remove
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_whitelist_remove(const char *path);

/**
 * Check if a path is whitelisted.
 * 
 * @param path      Path to check
 * @return true if whitelisted, false otherwise
 */
bool deft_monitor_is_whitelisted(const char *path);

/**
 * Load whitelist from a file.
 * 
 * File should contain one path per line.
 * 
 * @param path      Path to whitelist file
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_whitelist_load(const char *path);

/**
 * Get monitor statistics.
 * 
 * @param stats     Structure to receive statistics
 * @return 0 on success, negative error code on failure
 */
int deft_monitor_get_stats(deft_stats_t *stats);

#endif /* DEFT_MONITOR_H */
