/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_types.h - Common type definitions and constants
 */

#ifndef DEFT_TYPES_H
#define DEFT_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/* ============================================================================
 * Version Information
 * ============================================================================ */
#define DEFT_VERSION_MAJOR  1
#define DEFT_VERSION_MINOR  0
#define DEFT_VERSION_PATCH  0
#define DEFT_VERSION_STRING "1.0.0"

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/* Maximum path length for file paths */
#define DEFT_MAX_PATH       4096

/* Maximum length for process command line */
#define DEFT_MAX_CMDLINE    8192

/* Maximum number of monitored processes */
#define DEFT_MAX_PROCESSES  65536

/* Scan interval in milliseconds */
#define DEFT_SCAN_INTERVAL_MS   100

/* Number of features extracted from binaries (EMBER-compatible subset) */
#define DEFT_FEATURE_COUNT  256

/* Decision threshold for malware classification (0.0 - 1.0) */
#define DEFT_MALWARE_THRESHOLD  0.5f

/* Maximum number of decision trees in the ensemble */
#define DEFT_MAX_TREES      10

/* Maximum depth of each decision tree */
#define DEFT_MAX_TREE_DEPTH 15

/* Maximum number of nodes per tree */
#define DEFT_MAX_TREE_NODES 4096

/* ============================================================================
 * Feature Extraction Constants
 * ============================================================================ */

/* ELF Header Magic */
#define DEFT_ELF_MAGIC      0x464C457F  /* 0x7F 'E' 'L' 'F' */

/* PE Header Magic */
#define DEFT_PE_MAGIC       0x00004550  /* 'P' 'E' 0x00 0x00 */
#define DEFT_MZ_MAGIC       0x5A4D      /* 'M' 'Z' */

/* Maximum file size to analyze (100 MB) */
#define DEFT_MAX_FILE_SIZE  (100 * 1024 * 1024)

/* Minimum file size to analyze (64 bytes for headers) */
#define DEFT_MIN_FILE_SIZE  64

/* ============================================================================
 * Heuristic Detection Flags
 * ============================================================================ */

/* Process behavior flags */
#define DEFT_FLAG_NONE              0x00000000
#define DEFT_FLAG_SUSPICIOUS_PATH   0x00000001  /* Running from temp/unusual location */
#define DEFT_FLAG_HIDDEN_PROC       0x00000002  /* Process trying to hide itself */
#define DEFT_FLAG_PACKED            0x00000004  /* Binary appears packed/obfuscated */
#define DEFT_FLAG_HIGH_ENTROPY      0x00000008  /* High entropy sections (encryption) */
#define DEFT_FLAG_SELF_MODIFYING    0x00000010  /* Self-modifying code detected */
#define DEFT_FLAG_NETWORK_SUSPECT   0x00000020  /* Suspicious network activity */
#define DEFT_FLAG_PRIV_ESCALATION   0x00000040  /* Privilege escalation attempt */
#define DEFT_FLAG_ANTI_DEBUG        0x00000080  /* Anti-debugging techniques */
#define DEFT_FLAG_ROOTKIT_BEHAVIOR  0x00000100  /* Rootkit-like behavior */
#define DEFT_FLAG_CRYPTO_MINING     0x00000200  /* Crypto mining indicators */
#define DEFT_FLAG_RANSOMWARE        0x00000400  /* Ransomware indicators */
#define DEFT_FLAG_KEYLOGGER         0x00000800  /* Keylogger indicators */
#define DEFT_FLAG_BACKDOOR          0x00001000  /* Backdoor indicators */
#define DEFT_FLAG_DROPPER           0x00002000  /* Dropper/downloader behavior */
#define DEFT_FLAG_ANOMALY_IMPORTS   0x00004000  /* Unusual import patterns */
#define DEFT_FLAG_MEMORY_INJECT     0x00008000  /* Memory injection detected */

/* ============================================================================
 * Action Types
 * ============================================================================ */

typedef enum {
    DEFT_ACTION_NONE = 0,       /* No action taken */
    DEFT_ACTION_LOG,            /* Log the event only */
    DEFT_ACTION_ALERT,          /* Send alert notification */
    DEFT_ACTION_BLOCK,          /* Block/kill the process */
    DEFT_ACTION_QUARANTINE      /* Move binary to quarantine */
} deft_action_t;

/* ============================================================================
 * Detection Result
 * ============================================================================ */

typedef enum {
    DEFT_RESULT_CLEAN = 0,      /* No malware detected */
    DEFT_RESULT_SUSPICIOUS,     /* Suspicious, needs review */
    DEFT_RESULT_MALWARE,        /* Malware detected */
    DEFT_RESULT_ERROR           /* Error during analysis */
} deft_result_t;

/* ============================================================================
 * Binary Type
 * ============================================================================ */

typedef enum {
    DEFT_BIN_UNKNOWN = 0,       /* Unknown binary type */
    DEFT_BIN_ELF32,             /* 32-bit ELF binary */
    DEFT_BIN_ELF64,             /* 64-bit ELF binary */
    DEFT_BIN_PE32,              /* 32-bit PE binary (Wine) */
    DEFT_BIN_PE64,              /* 64-bit PE binary (Wine) */
    DEFT_BIN_SCRIPT,            /* Script file */
    DEFT_BIN_SHAREDLIB          /* Shared library */
} deft_bin_type_t;

/* ============================================================================
 * Feature Vector Structure
 * ============================================================================ */

typedef struct {
    float features[DEFT_FEATURE_COUNT];  /* Normalized feature values */
    uint32_t flags;                       /* Heuristic detection flags */
    deft_bin_type_t bin_type;            /* Type of binary */
    float entropy;                        /* Overall file entropy */
    uint32_t section_count;              /* Number of sections */
    uint64_t file_size;                  /* File size in bytes */
    bool valid;                          /* Whether extraction was successful */
} deft_features_t;

/* ============================================================================
 * Process Information Structure
 * ============================================================================ */

typedef struct {
    pid_t pid;                           /* Process ID */
    pid_t ppid;                          /* Parent process ID */
    uid_t uid;                           /* User ID */
    gid_t gid;                           /* Group ID */
    char exe_path[DEFT_MAX_PATH];        /* Path to executable */
    char cmdline[DEFT_MAX_CMDLINE];      /* Command line arguments */
    char comm[256];                      /* Process name */
    uint64_t start_time;                 /* Process start time */
    deft_features_t features;            /* Extracted features */
    deft_result_t result;                /* Detection result */
    float ml_score;                      /* ML model confidence score */
    uint32_t heuristic_flags;            /* Heuristic detection flags */
} deft_process_t;

/* ============================================================================
 * Decision Tree Node Structure
 * ============================================================================ */

typedef struct {
    int16_t feature_index;      /* Feature index to split on (-1 for leaf) */
    float threshold;            /* Threshold value for split */
    int16_t left_child;         /* Index of left child (-1 for none) */
    int16_t right_child;        /* Index of right child (-1 for none) */
    float value;                /* Leaf value (probability for leaf nodes) */
} deft_tree_node_t;

/* ============================================================================
 * Decision Tree Structure
 * ============================================================================ */

typedef struct {
    deft_tree_node_t nodes[DEFT_MAX_TREE_NODES];  /* Tree nodes */
    uint32_t node_count;                           /* Number of nodes in tree */
    uint32_t max_depth;                            /* Maximum depth of tree */
} deft_decision_tree_t;

/* ============================================================================
 * ML Model Structure (Random Forest)
 * ============================================================================ */

typedef struct {
    deft_decision_tree_t trees[DEFT_MAX_TREES];   /* Decision trees */
    uint32_t tree_count;                           /* Number of trees */
    float threshold;                               /* Classification threshold */
    bool loaded;                                   /* Whether model is loaded */
} deft_model_t;

/* ============================================================================
 * Configuration Structure
 * ============================================================================ */

typedef struct {
    bool daemon_mode;                    /* Run as daemon */
    bool verbose;                        /* Verbose logging */
    bool dry_run;                        /* Don't take actions, just log */
    char log_path[DEFT_MAX_PATH];        /* Path to log file */
    char quarantine_path[DEFT_MAX_PATH]; /* Path to quarantine directory */
    char model_path[DEFT_MAX_PATH];      /* Path to ML model file */
    deft_action_t default_action;        /* Default action for malware */
    float threshold;                     /* Detection threshold */
    uint32_t scan_interval_ms;           /* Process scan interval */
    char whitelist_path[DEFT_MAX_PATH];  /* Path to whitelist file */
} deft_config_t;

/* ============================================================================
 * Statistics Structure
 * ============================================================================ */

typedef struct {
    uint64_t processes_scanned;          /* Total processes scanned */
    uint64_t malware_detected;           /* Malware detections */
    uint64_t suspicious_detected;        /* Suspicious detections */
    uint64_t processes_blocked;          /* Processes blocked */
    uint64_t false_positives;            /* Reported false positives */
    uint64_t start_time;                 /* Daemon start time */
    uint64_t last_scan_time;             /* Last scan timestamp */
} deft_stats_t;

#endif /* DEFT_TYPES_H */
