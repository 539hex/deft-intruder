/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_log.h - Logging subsystem interface
 * 
 * Provides unified logging for all DEFT components with support for
 * console output, file logging, and syslog integration.
 */

#ifndef DEFT_LOG_H
#define DEFT_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

/* ============================================================================
 * Log Levels
 * ============================================================================ */

typedef enum {
    DEFT_LOG_TRACE = 0,     /* Detailed tracing (very verbose) */
    DEFT_LOG_DEBUG,         /* Debug information */
    DEFT_LOG_INFO,          /* Informational messages */
    DEFT_LOG_WARN,          /* Warning messages */
    DEFT_LOG_ERROR,         /* Error messages */
    DEFT_LOG_FATAL,         /* Fatal errors (before crash) */
    DEFT_LOG_ALERT          /* Security alerts (malware detected) */
} deft_log_level_t;

/* ============================================================================
 * Log Configuration
 * ============================================================================ */

typedef struct {
    deft_log_level_t min_level;     /* Minimum level to log */
    bool log_to_console;            /* Output to stdout/stderr */
    bool log_to_file;               /* Output to file */
    bool log_to_syslog;             /* Output to syslog */
    bool colorize;                  /* Use ANSI colors in console */
    bool include_timestamp;         /* Include timestamp in messages */
    bool include_source;            /* Include source file/line */
    char log_file_path[4096];       /* Path to log file */
    size_t max_file_size;           /* Max log file size (0 = unlimited) */
    int max_backup_files;           /* Number of backup files to keep */
} deft_log_config_t;

/* ============================================================================
 * Convenience Macros
 * ============================================================================ */

#define DEFT_LOG_TRACE(...) deft_log(DEFT_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define DEFT_LOG_DEBUG(...) deft_log(DEFT_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define DEFT_LOG_INFO(...)  deft_log(DEFT_LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define DEFT_LOG_WARN(...)  deft_log(DEFT_LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define DEFT_LOG_ERROR(...) deft_log(DEFT_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define DEFT_LOG_FATAL(...) deft_log(DEFT_LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#define DEFT_LOG_ALERT(...) deft_log(DEFT_LOG_ALERT, __FILE__, __LINE__, __VA_ARGS__)

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

/**
 * Initialize the logging subsystem.
 * 
 * @param config    Logging configuration (NULL for defaults)
 * @return 0 on success, negative error code on failure
 */
int deft_log_init(const deft_log_config_t *config);

/**
 * Cleanup logging resources.
 */
void deft_log_cleanup(void);

/**
 * Log a message.
 * 
 * @param level     Log level
 * @param file      Source file name (__FILE__)
 * @param line      Source line number (__LINE__)
 * @param fmt       Format string (printf-style)
 * @param ...       Format arguments
 */
void deft_log(deft_log_level_t level, const char *file, int line,
              const char *fmt, ...) __attribute__((format(printf, 4, 5)));

/**
 * Log a message (va_list version).
 */
void deft_log_v(deft_log_level_t level, const char *file, int line,
                const char *fmt, va_list args);

/**
 * Set the minimum log level.
 * 
 * @param level     Minimum level to log
 */
void deft_log_set_level(deft_log_level_t level);

/**
 * Get the current minimum log level.
 * 
 * @return Current minimum level
 */
deft_log_level_t deft_log_get_level(void);

/**
 * Enable or disable console output.
 * 
 * @param enable    Whether to enable console logging
 */
void deft_log_set_console(bool enable);

/**
 * Enable or disable file output.
 * 
 * @param enable    Whether to enable file logging
 * @param path      Path to log file (NULL to keep current)
 * @return 0 on success, negative error code on failure
 */
int deft_log_set_file(bool enable, const char *path);

/**
 * Get log level name as string.
 * 
 * @param level     Log level
 * @return Level name string
 */
const char* deft_log_level_name(deft_log_level_t level);

/**
 * Rotate log files.
 * 
 * Manually trigger log file rotation.
 * 
 * @return 0 on success, negative error code on failure
 */
int deft_log_rotate(void);

/**
 * Flush log buffers.
 */
void deft_log_flush(void);

/**
 * Log a security alert (malware detection).
 * 
 * This is a specialized logging function for malware alerts
 * that includes additional context.
 * 
 * @param pid       Process ID
 * @param path      Executable path
 * @param score     Detection score
 * @param flags     Detection flags
 * @param action    Action taken
 */
void deft_log_alert_detection(pid_t pid, const char *path,
                              float score, uint32_t flags,
                              int action);

#endif /* DEFT_LOG_H */
