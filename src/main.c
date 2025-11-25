/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * main.c - Main daemon entry point
 * 
 * This is the main program that ties together all DEFT components:
 * - Process monitoring via /proc filesystem
 * - Feature extraction from executables
 * - ML-based classification
 * - Heuristic detection rules
 * - Action handling (log, alert, block)
 * 
 * The daemon runs in the background monitoring all new processes
 * and blocks malicious ones before they can cause harm.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>

#include "deft_types.h"
#include "deft_features.h"
#include "deft_model.h"
#include "deft_monitor.h"
#include "deft_heuristics.h"
#include "deft_log.h"

/* ============================================================================
 * Program Constants
 * ============================================================================ */

#define PROGRAM_NAME    "deft-intruder"
#define PID_FILE        "/var/run/deft-intruder.pid"
#define DEFAULT_LOG     "/var/log/deft-intruder.log"
#define DEFAULT_MODEL   "/etc/deft-intruder/model.bin"
#define QUARANTINE_DIR  "/var/quarantine/deft-intruder"

/* ============================================================================
 * Global State
 * ============================================================================ */

static volatile bool g_running = true;
static deft_model_t g_model;
static deft_config_t g_config;

/* ============================================================================
 * Signal Handlers
 * ============================================================================ */

/**
 * Handle termination signals gracefully.
 */
static void signal_handler(int sig)
{
    DEFT_LOG_INFO("Received signal %d, shutting down...", sig);
    g_running = false;
}

/**
 * Handle SIGHUP for configuration reload.
 */
static void sighup_handler(int sig)
{
    (void)sig;
    DEFT_LOG_INFO("Received SIGHUP, reloading configuration...");
    /* TODO: Implement config reload */
}

/* ============================================================================
 * Process Analysis Callback
 * ============================================================================ */

/**
 * Callback invoked for each new process detected.
 * 
 * This function performs the main analysis:
 * 1. Extract features from the executable
 * 2. Run ML model prediction
 * 3. Apply heuristic rules
 * 4. Combine scores and make decision
 * 5. Take appropriate action
 * 
 * @param process   Process information
 * @param user_data User context (unused)
 * @return Action to take
 */
static deft_action_t analyze_process(deft_process_t *process, void *user_data)
{
    (void)user_data;
    
    if (!process) {
        return DEFT_ACTION_NONE;
    }
    
    DEFT_LOG_DEBUG("Analyzing process: pid=%d exe=%s", 
                   process->pid, process->exe_path);
    
    /* Skip if executable path is empty or unreadable */
    if (process->exe_path[0] == '\0') {
        return DEFT_ACTION_NONE;
    }
    
    /* Check access to executable */
    if (access(process->exe_path, R_OK) != 0) {
        DEFT_LOG_DEBUG("Cannot access executable: %s", process->exe_path);
        return DEFT_ACTION_NONE;
    }
    
    /* ================================================================
     * Step 1: Extract features from executable
     * ================================================================ */
    
    if (deft_extract_file_features(process->exe_path, &process->features) != 0) {
        DEFT_LOG_DEBUG("Failed to extract features from: %s", process->exe_path);
        /* Continue with heuristics even if feature extraction fails */
    }
    
    /* ================================================================
     * Step 2: Run ML model prediction
     * ================================================================ */
    
    float ml_score = 0.0f;
    
    if (g_model.loaded && process->features.valid) {
        ml_score = deft_model_predict(&g_model, &process->features);
        process->ml_score = ml_score;
        
        DEFT_LOG_DEBUG("ML score for %s: %.3f", process->exe_path, ml_score);
    }
    
    /* ================================================================
     * Step 3: Run heuristic analysis
     * ================================================================ */
    
    deft_heuristic_result_t heuristic_result;
    deft_heuristics_analyze(process, &heuristic_result);
    
    process->heuristic_flags = heuristic_result.flags;
    
    DEFT_LOG_DEBUG("Heuristic score for %s: %.3f (flags: 0x%x)",
                   process->exe_path, heuristic_result.score, 
                   heuristic_result.flags);
    
    /* ================================================================
     * Step 4: Combine scores and make decision
     * ================================================================ */
    
    /* Weighted combination of ML and heuristic scores */
    float combined_score;
    
    if (g_model.loaded && process->features.valid) {
        /* Both ML and heuristics available */
        combined_score = (ml_score * 0.7f) + (heuristic_result.score * 0.3f);
    } else {
        /* Only heuristics available */
        combined_score = heuristic_result.score;
    }
    
    /* Boost score for certain dangerous flags */
    if (heuristic_result.flags & DEFT_FLAG_ROOTKIT_BEHAVIOR) {
        combined_score = fmaxf(combined_score, 0.8f);
    }
    if (heuristic_result.flags & DEFT_FLAG_RANSOMWARE) {
        combined_score = fmaxf(combined_score, 0.8f);
    }
    
    /* Determine result */
    if (combined_score >= g_config.threshold) {
        process->result = DEFT_RESULT_MALWARE;
    } else if (combined_score >= g_config.threshold * 0.6f) {
        process->result = DEFT_RESULT_SUSPICIOUS;
    } else {
        process->result = DEFT_RESULT_CLEAN;
    }
    
    /* ================================================================
     * Step 5: Take appropriate action
     * ================================================================ */
    
    deft_action_t action = DEFT_ACTION_NONE;
    
    if (process->result == DEFT_RESULT_MALWARE) {
        /* Malware detected! */
        action = g_config.default_action;
        
        deft_log_alert_detection(process->pid, process->exe_path,
                                 combined_score, heuristic_result.flags,
                                 action);
        
        /* Print alert to console */
        fprintf(stderr, "\n");
        fprintf(stderr, "╔══════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║                    ⚠️  MALWARE DETECTED ⚠️                     ║\n");
        fprintf(stderr, "╠══════════════════════════════════════════════════════════════╣\n");
        fprintf(stderr, "║ PID:   %-54d ║\n", process->pid);
        fprintf(stderr, "║ Path:  %-54.54s ║\n", process->exe_path);
        fprintf(stderr, "║ Score: %-54.2f ║\n", combined_score);
        fprintf(stderr, "║ Action: %-53s ║\n", 
                action == DEFT_ACTION_BLOCK ? "BLOCKED" : 
                action == DEFT_ACTION_QUARANTINE ? "QUARANTINED" : "LOGGED");
        fprintf(stderr, "╚══════════════════════════════════════════════════════════════╝\n\n");
        
    } else if (process->result == DEFT_RESULT_SUSPICIOUS) {
        /* Suspicious - log but don't block */
        DEFT_LOG_WARN("Suspicious process: pid=%d path=%s score=%.2f",
                      process->pid, process->exe_path, combined_score);
        action = DEFT_ACTION_LOG;
    }
    
    /* Apply dry-run mode */
    if (g_config.dry_run && action == DEFT_ACTION_BLOCK) {
        DEFT_LOG_INFO("Dry-run mode: would have blocked pid=%d", process->pid);
        action = DEFT_ACTION_LOG;
    }
    
    return action;
}

/* ============================================================================
 * Daemon Functions
 * ============================================================================ */

/**
 * Write PID file for daemon mode.
 */
static int write_pid_file(void)
{
    int fd = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        DEFT_LOG_ERROR("Failed to create PID file: %s", strerror(errno));
        return -1;
    }
    
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d\n", getpid());
    if (write(fd, buf, len) != len) {
        close(fd);
        return -1;
    }
    close(fd);
    
    return 0;
}

/**
 * Daemonize the process.
 */
static int daemonize(void)
{
    /* First fork */
    pid_t pid = fork();
    if (pid < 0) {
        DEFT_LOG_ERROR("First fork failed: %s", strerror(errno));
        return -1;
    }
    if (pid > 0) {
        /* Parent exits */
        exit(0);
    }
    
    /* Create new session */
    if (setsid() < 0) {
        DEFT_LOG_ERROR("setsid failed: %s", strerror(errno));
        return -1;
    }
    
    /* Second fork (prevent acquiring controlling terminal) */
    pid = fork();
    if (pid < 0) {
        DEFT_LOG_ERROR("Second fork failed: %s", strerror(errno));
        return -1;
    }
    if (pid > 0) {
        exit(0);
    }
    
    /* Set working directory */
    if (chdir("/") < 0) {
        /* Non-fatal, continue anyway */
    }
    
    /* Set file creation mask */
    umask(0);
    
    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    /* Redirect to /dev/null */
    open("/dev/null", O_RDONLY);  /* stdin */
    open("/dev/null", O_WRONLY);  /* stdout */
    open("/dev/null", O_WRONLY);  /* stderr */
    
    return 0;
}

/* ============================================================================
 * Usage and Help
 * ============================================================================ */

static void print_usage(const char *progname)
{
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\n");
    printf("DEFT-Intruder: Real-time Heuristic Malware Detection System\n");
    printf("\n");
    printf("Options:\n");
    printf("  -d, --daemon         Run as a background daemon\n");
    printf("  -f, --foreground     Run in foreground (default)\n");
    printf("  -v, --verbose        Enable verbose logging\n");
    printf("  -n, --dry-run        Don't block processes, just log\n");
    printf("  -t, --threshold N    Detection threshold 0.0-1.0 (default: 0.5)\n");
    printf("  -m, --model PATH     Path to ML model file\n");
    printf("  -l, --log PATH       Path to log file\n");
    printf("  -w, --whitelist PATH Path to whitelist file\n");
    printf("  -i, --interval MS    Scan interval in milliseconds (default: 100)\n");
    printf("  -a, --action ACTION  Default action: log, alert, block (default: block)\n");
    printf("  -s, --scan           Scan all running processes and exit\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -V, --version        Show version information\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -d                # Run as daemon with default settings\n", progname);
    printf("  %s -v -n             # Verbose dry-run mode\n", progname);
    printf("  %s -s                # Scan current processes\n", progname);
    printf("  %s -t 0.7 -a alert   # Higher threshold, alert only\n", progname);
    printf("\n");
}

static void print_version(void)
{
    printf("DEFT-Intruder v%s\n", DEFT_VERSION_STRING);
    printf("Real-time Heuristic Malware Detection System\n");
    printf("Copyright (C) 2025 - Open Source Project\n");
    printf("License: GPL-3.0\n");
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int main(int argc, char *argv[])
{
    int opt;
    bool scan_only = false;
    
    /* Initialize default configuration */
    memset(&g_config, 0, sizeof(g_config));
    g_config.daemon_mode = false;
    g_config.verbose = false;
    g_config.dry_run = false;
    g_config.threshold = DEFT_MALWARE_THRESHOLD;
    g_config.default_action = DEFT_ACTION_BLOCK;
    g_config.scan_interval_ms = DEFT_SCAN_INTERVAL_MS;
    strncpy(g_config.log_path, DEFAULT_LOG, sizeof(g_config.log_path) - 1);
    strncpy(g_config.model_path, DEFAULT_MODEL, sizeof(g_config.model_path) - 1);
    strncpy(g_config.quarantine_path, QUARANTINE_DIR, sizeof(g_config.quarantine_path) - 1);
    
    /* Parse command line options */
    static struct option long_options[] = {
        {"daemon",     no_argument,       0, 'd'},
        {"foreground", no_argument,       0, 'f'},
        {"verbose",    no_argument,       0, 'v'},
        {"dry-run",    no_argument,       0, 'n'},
        {"threshold",  required_argument, 0, 't'},
        {"model",      required_argument, 0, 'm'},
        {"log",        required_argument, 0, 'l'},
        {"whitelist",  required_argument, 0, 'w'},
        {"interval",   required_argument, 0, 'i'},
        {"action",     required_argument, 0, 'a'},
        {"scan",       no_argument,       0, 's'},
        {"help",       no_argument,       0, 'h'},
        {"version",    no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "dfvnt:m:l:w:i:a:shV", 
                               long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                g_config.daemon_mode = true;
                break;
            case 'f':
                g_config.daemon_mode = false;
                break;
            case 'v':
                g_config.verbose = true;
                break;
            case 'n':
                g_config.dry_run = true;
                break;
            case 't':
                g_config.threshold = atof(optarg);
                if (g_config.threshold < 0.0f || g_config.threshold > 1.0f) {
                    fprintf(stderr, "Error: threshold must be between 0.0 and 1.0\n");
                    return 1;
                }
                break;
            case 'm':
                strncpy(g_config.model_path, optarg, sizeof(g_config.model_path) - 1);
                break;
            case 'l':
                strncpy(g_config.log_path, optarg, sizeof(g_config.log_path) - 1);
                break;
            case 'w':
                strncpy(g_config.whitelist_path, optarg, sizeof(g_config.whitelist_path) - 1);
                break;
            case 'i':
                g_config.scan_interval_ms = atoi(optarg);
                if (g_config.scan_interval_ms < 10) {
                    fprintf(stderr, "Error: interval must be at least 10ms\n");
                    return 1;
                }
                break;
            case 'a':
                if (strcmp(optarg, "log") == 0) {
                    g_config.default_action = DEFT_ACTION_LOG;
                } else if (strcmp(optarg, "alert") == 0) {
                    g_config.default_action = DEFT_ACTION_ALERT;
                } else if (strcmp(optarg, "block") == 0) {
                    g_config.default_action = DEFT_ACTION_BLOCK;
                } else if (strcmp(optarg, "quarantine") == 0) {
                    g_config.default_action = DEFT_ACTION_QUARANTINE;
                } else {
                    fprintf(stderr, "Error: unknown action '%s'\n", optarg);
                    return 1;
                }
                break;
            case 's':
                scan_only = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'V':
                print_version();
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* Check for root privileges */
    if (geteuid() != 0) {
        fprintf(stderr, "Warning: Running without root privileges.\n");
        fprintf(stderr, "         Some features may not work correctly.\n");
        fprintf(stderr, "         Process blocking will be disabled.\n\n");
        g_config.default_action = DEFT_ACTION_LOG;
    }
    
    /* Initialize logging */
    deft_log_config_t log_config = {
        .min_level = g_config.verbose ? DEFT_LOG_DEBUG : DEFT_LOG_INFO,
        .log_to_console = !g_config.daemon_mode,
        .log_to_file = g_config.log_path[0] != '\0',
        .colorize = !g_config.daemon_mode && isatty(STDOUT_FILENO),
        .include_timestamp = true,
        .include_source = g_config.verbose,
        .max_file_size = 10 * 1024 * 1024,
        .max_backup_files = 5
    };
    memset(log_config.log_file_path, 0, sizeof(log_config.log_file_path));
    snprintf(log_config.log_file_path, sizeof(log_config.log_file_path), 
             "%s", g_config.log_path);
    
    if (deft_log_init(&log_config) != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }
    
    /* Print banner */
    DEFT_LOG_INFO("===========================================");
    DEFT_LOG_INFO("DEFT-Intruder v%s Starting", DEFT_VERSION_STRING);
    DEFT_LOG_INFO("Real-time Heuristic Malware Detection");
    DEFT_LOG_INFO("===========================================");
    
    if (g_config.dry_run) {
        DEFT_LOG_WARN("Running in DRY-RUN mode - no processes will be blocked");
    }
    
    /* Initialize subsystems */
    DEFT_LOG_INFO("Initializing subsystems...");
    
    if (deft_features_init() != 0) {
        DEFT_LOG_ERROR("Failed to initialize feature extraction");
        return 1;
    }
    
    if (deft_model_init() != 0) {
        DEFT_LOG_ERROR("Failed to initialize ML model");
        return 1;
    }
    
    if (deft_heuristics_init() != 0) {
        DEFT_LOG_ERROR("Failed to initialize heuristics");
        return 1;
    }
    
    if (deft_monitor_init() != 0) {
        DEFT_LOG_ERROR("Failed to initialize process monitor");
        return 1;
    }
    
    /* Load ML model */
    DEFT_LOG_INFO("Loading ML model...");
    
    if (access(g_config.model_path, R_OK) == 0) {
        if (deft_model_load(&g_model, g_config.model_path) == 0) {
            DEFT_LOG_INFO("Loaded model from: %s", g_config.model_path);
        } else {
            DEFT_LOG_WARN("Failed to load model from: %s", g_config.model_path);
        }
    }
    
    if (!g_model.loaded) {
        DEFT_LOG_INFO("Using embedded model");
        if (deft_model_load_embedded(&g_model) != 0) {
            DEFT_LOG_WARN("Failed to load embedded model");
            DEFT_LOG_WARN("Running with heuristics only");
        }
    }
    
    if (g_model.loaded) {
        deft_model_print_stats(&g_model, stdout);
    }
    
    /* Load whitelist if specified */
    if (g_config.whitelist_path[0]) {
        DEFT_LOG_INFO("Loading whitelist from: %s", g_config.whitelist_path);
        deft_monitor_whitelist_load(g_config.whitelist_path);
    }
    
    /* Handle scan-only mode */
    if (scan_only) {
        DEFT_LOG_INFO("Scanning all running processes...");
        int count = deft_monitor_scan_all(analyze_process, NULL);
        DEFT_LOG_INFO("Scanned %d processes", count);
        goto cleanup;
    }
    
    /* Daemonize if requested */
    if (g_config.daemon_mode) {
        DEFT_LOG_INFO("Daemonizing...");
        if (daemonize() != 0) {
            DEFT_LOG_ERROR("Failed to daemonize");
            goto cleanup;
        }
        
        /* Write PID file */
        write_pid_file();
        
        /* Disable console output */
        deft_log_set_console(false);
    }
    
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, sighup_handler);
    signal(SIGPIPE, SIG_IGN);
    
    /* Configure and start monitor */
    deft_monitor_config_t monitor_config = {
        .scan_interval_ms = g_config.scan_interval_ms,
        .monitor_children = true,
        .follow_forks = true,
        .scan_on_exec = true,
        .on_process = analyze_process,
        .on_exit = NULL,
        .user_data = NULL
    };
    
    DEFT_LOG_INFO("Starting process monitor (interval: %u ms)...", 
                  g_config.scan_interval_ms);
    
    if (deft_monitor_start(&monitor_config) != 0) {
        DEFT_LOG_ERROR("Failed to start process monitor");
        goto cleanup;
    }
    
    DEFT_LOG_INFO("DEFT-Intruder is now active and monitoring");
    
    /* Main loop */
    while (g_running) {
        sleep(1);
        
        /* Periodically log statistics */
        static int stat_counter = 0;
        if (++stat_counter >= 60) {  /* Every 60 seconds */
            deft_stats_t stats;
            deft_monitor_get_stats(&stats);
            
            DEFT_LOG_INFO("Stats: scanned=%lu detected=%lu blocked=%lu",
                          stats.processes_scanned,
                          stats.malware_detected,
                          stats.processes_blocked);
            
            stat_counter = 0;
        }
    }
    
    /* Stop monitor */
    DEFT_LOG_INFO("Stopping process monitor...");
    deft_monitor_stop();
    
cleanup:
    /* Cleanup */
    DEFT_LOG_INFO("Cleaning up...");
    deft_monitor_cleanup();
    deft_heuristics_cleanup();
    deft_model_cleanup();
    deft_features_cleanup();
    deft_log_cleanup();
    
    /* Remove PID file */
    if (g_config.daemon_mode) {
        unlink(PID_FILE);
    }
    
    return 0;
}
