/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_heuristics.c - Heuristic-based detection implementation
 * 
 * This module implements rule-based heuristics that complement the ML
 * model. Heuristics are useful for detecting behavior patterns that
 * may not be visible in static file analysis.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>

#include "deft_types.h"
#include "deft_heuristics.h"
#include "deft_features.h"
#include "deft_log.h"

/* ============================================================================
 * Heuristic Rules Definition
 * ============================================================================ */

/* Default heuristic rules */
static deft_heuristic_rule_t g_rules[] = {
    {
        .name = "high_entropy",
        .description = "File has unusually high entropy (possible encryption/packing)",
        .flag = DEFT_FLAG_HIGH_ENTROPY,
        .weight = 0.3f,
        .enabled = true
    },
    {
        .name = "suspicious_path",
        .description = "Process running from suspicious location (tmp, dev/shm)",
        .flag = DEFT_FLAG_SUSPICIOUS_PATH,
        .weight = 0.4f,
        .enabled = true
    },
    {
        .name = "packed_binary",
        .description = "Binary appears to be packed or obfuscated",
        .flag = DEFT_FLAG_PACKED,
        .weight = 0.35f,
        .enabled = true
    },
    {
        .name = "anti_debug",
        .description = "Binary contains anti-debugging techniques",
        .flag = DEFT_FLAG_ANTI_DEBUG,
        .weight = 0.3f,
        .enabled = true
    },
    {
        .name = "rootkit_behavior",
        .description = "Process exhibits rootkit-like behavior",
        .flag = DEFT_FLAG_ROOTKIT_BEHAVIOR,
        .weight = 0.5f,
        .enabled = true
    },
    {
        .name = "ransomware_indicators",
        .description = "Process shows ransomware behavior patterns",
        .flag = DEFT_FLAG_RANSOMWARE,
        .weight = 0.5f,
        .enabled = true
    },
    {
        .name = "crypto_mining",
        .description = "Process appears to be a cryptocurrency miner",
        .flag = DEFT_FLAG_CRYPTO_MINING,
        .weight = 0.4f,
        .enabled = true
    },
    {
        .name = "keylogger",
        .description = "Process shows keylogging behavior",
        .flag = DEFT_FLAG_KEYLOGGER,
        .weight = 0.45f,
        .enabled = true
    },
    {
        .name = "backdoor",
        .description = "Process exhibits backdoor characteristics",
        .flag = DEFT_FLAG_BACKDOOR,
        .weight = 0.45f,
        .enabled = true
    },
    {
        .name = "memory_injection",
        .description = "Process attempting memory injection",
        .flag = DEFT_FLAG_MEMORY_INJECT,
        .weight = 0.5f,
        .enabled = true
    },
    {
        .name = "privilege_escalation",
        .description = "Process attempting privilege escalation",
        .flag = DEFT_FLAG_PRIV_ESCALATION,
        .weight = 0.5f,
        .enabled = true
    },
    {
        .name = "anomaly_imports",
        .description = "Binary has unusual import patterns",
        .flag = DEFT_FLAG_ANOMALY_IMPORTS,
        .weight = 0.25f,
        .enabled = true
    }
};

static const int g_num_rules = sizeof(g_rules) / sizeof(g_rules[0]);

/* Suspicious parent processes */
static const char *SUSPICIOUS_PARENTS[] = {
    "bash",
    "sh",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "curl",
    "wget",
    "nc",
    "netcat",
    NULL
};

/* Ransomware file extensions that may be created */
static const char *RANSOMWARE_EXTENSIONS[] __attribute__((unused)) = {
    ".encrypted",
    ".locked",
    ".crypto",
    ".crypt",
    ".ransom",
    ".WNCRY",
    ".locky",
    NULL
};

/* Forward declaration from deft_monitor.h */
extern bool deft_is_suspicious_path(const char *path);

/* Crypto miner indicators */
static const char *MINER_STRINGS[] = {
    "stratum+tcp",
    "stratum+ssl",
    "xmrig",
    "cpuminer",
    "minerd",
    "cgminer",
    "bfgminer",
    "nicehash",
    NULL
};

/* ============================================================================
 * Private State
 * ============================================================================ */

static bool g_heuristics_initialized = false;

/* ============================================================================
 * Private Helper Functions
 * ============================================================================ */

/**
 * Check if a string contains any pattern from an array.
 */
static bool contains_any(const char *str, const char **patterns)
{
    if (!str || !patterns) {
        return false;
    }
    
    for (int i = 0; patterns[i] != NULL; i++) {
        if (strstr(str, patterns[i]) != NULL) {
            return true;
        }
    }
    
    return false;
}

/**
 * Get CPU usage for a process.
 */
static float get_cpu_usage(pid_t pid)
{
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    
    FILE *f = fopen(stat_path, "r");
    if (!f) {
        return 0.0f;
    }
    
    /* Read stat file - field 14 is utime, 15 is stime */
    char buf[512];
    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        return 0.0f;
    }
    fclose(f);
    
    /* Parse out the CPU times (simplified) */
    long utime = 0, stime = 0;
    char *p = strrchr(buf, ')');  /* Skip comm field which may have spaces */
    if (p) {
        sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %ld %ld",
               &utime, &stime);
    }
    
    /* This is a simplified calculation - actual CPU % needs sampling over time */
    return (float)(utime + stime) / sysconf(_SC_CLK_TCK);
}

/**
 * Check if process is hidden (not visible in normal ps output).
 */
static bool is_hidden_process(pid_t pid)
{
    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
    
    int fd = open(cmdline_path, O_RDONLY);
    if (fd < 0) {
        return true;  /* Can't read = possibly hidden */
    }
    
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    
    if (n <= 0) {
        return true;  /* Empty cmdline = possibly hidden */
    }
    
    /* Check for null-only cmdline (kernel threads are OK) */
    bool all_null = true;
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] != '\0') {
            all_null = false;
            break;
        }
    }
    
    return all_null;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/**
 * Initialize the heuristics engine.
 */
int deft_heuristics_init(void)
{
    if (g_heuristics_initialized) {
        return 0;
    }
    
    g_heuristics_initialized = true;
    DEFT_LOG_INFO("Heuristics engine initialized with %d rules", g_num_rules);
    
    return 0;
}

/**
 * Cleanup heuristics resources.
 */
void deft_heuristics_cleanup(void)
{
    g_heuristics_initialized = false;
    DEFT_LOG_INFO("Heuristics engine cleaned up");
}

/**
 * Check for packing/obfuscation.
 */
float deft_heuristics_check_packing(const deft_features_t *features)
{
    if (!features || !features->valid) {
        return 0.0f;
    }
    
    float score = 0.0f;
    
    /* High overall entropy indicates compression/encryption */
    if (features->entropy > 7.0f) {
        score += 0.3f;
    }
    if (features->entropy > 7.5f) {
        score += 0.2f;
    }
    
    /* High entropy variance between sections */
    if (features->features[FEAT_ENTROPY_VARIANCE] > 0.5f) {
        score += 0.2f;
    }
    
    /* Suspicious section names (from feature extractor) */
    if (features->features[FEAT_UNUSUAL_SECTION_NAMES] > 0) {
        score += 0.2f;
    }
    
    /* Very few imports (packed binaries often have minimal imports) */
    if (features->features[FEAT_IMPORT_COUNT] < 0.05f) {
        score += 0.1f;
    }
    
    return score > 1.0f ? 1.0f : score;
}

/**
 * Check for anti-debugging techniques.
 */
float deft_heuristics_check_antidebug(const deft_features_t *features)
{
    if (!features || !features->valid) {
        return 0.0f;
    }
    
    float score = 0.0f;
    
    /* Check for anti-debug feature from imports */
    if (features->features[FEAT_IMP_DEBUG] > 0.1f) {
        score += 0.3f;
    }
    
    /* Check for anti-debug heuristic feature */
    score += features->features[FEAT_ANTI_DEBUG_SCORE];
    
    return score > 1.0f ? 1.0f : score;
}

/**
 * Check for suspicious import patterns.
 */
float deft_heuristics_check_imports(const deft_features_t *features)
{
    if (!features || !features->valid) {
        return 0.0f;
    }
    
    float score = 0.0f;
    
    /* Process injection imports */
    if (features->features[FEAT_IMP_INJECTION] > 0.1f) {
        score += 0.4f;
    }
    
    /* Memory manipulation imports */
    if (features->features[FEAT_IMP_MEMORY] > 0.2f) {
        score += 0.2f;
    }
    
    /* Keylogging imports */
    if (features->features[FEAT_IMP_KEYLOG] > 0) {
        score += 0.3f;
    }
    
    /* Crypto imports (ransomware indicator) */
    if (features->features[FEAT_IMP_CRYPTO] > 0.1f) {
        score += 0.2f;
    }
    
    return score > 1.0f ? 1.0f : score;
}

/**
 * Check for rootkit-like behavior.
 */
float deft_heuristics_check_rootkit(const deft_process_t *process)
{
    if (!process) {
        return 0.0f;
    }
    
    float score = 0.0f;
    
    /* Check if process is hidden */
    if (is_hidden_process(process->pid)) {
        score += 0.4f;
    }
    
    /* Check for suspicious executable location */
    if (deft_is_suspicious_path(process->exe_path)) {
        score += 0.2f;
    }
    
    /* Check for deleted executable (process still running but file deleted) */
    if (strstr(process->exe_path, "(deleted)") != NULL) {
        score += 0.5f;
    }
    
    /* Running as root from unusual location */
    if (process->uid == 0 && deft_is_suspicious_path(process->exe_path)) {
        score += 0.3f;
    }
    
    return score > 1.0f ? 1.0f : score;
}

/**
 * Check for ransomware indicators.
 */
float deft_heuristics_check_ransomware(const deft_process_t *process,
                                        const deft_features_t *features)
{
    if (!process) {
        return 0.0f;
    }
    
    float score = 0.0f;
    
    /* Check cmdline for ransomware-related strings */
    if (process->cmdline[0]) {
        if (strstr(process->cmdline, "encrypt") != NULL ||
            strstr(process->cmdline, "ransom") != NULL ||
            strstr(process->cmdline, "bitcoin") != NULL ||
            strstr(process->cmdline, "wallet") != NULL) {
            score += 0.3f;
        }
    }
    
    /* Check for crypto imports in features */
    if (features && features->valid) {
        if (features->features[FEAT_IMP_CRYPTO] > 0.2f) {
            score += 0.3f;
        }
        score += features->features[FEAT_RANSOMWARE_SCORE];
    }
    
    /* High file system activity combined with crypto */
    if (features && features->features[FEAT_IMP_FILESYSTEM] > 0.3f &&
        features->features[FEAT_IMP_CRYPTO] > 0.1f) {
        score += 0.2f;
    }
    
    return score > 1.0f ? 1.0f : score;
}

/**
 * Check for crypto mining behavior.
 */
float deft_heuristics_check_cryptominer(const deft_process_t *process)
{
    if (!process) {
        return 0.0f;
    }
    
    float score = 0.0f;
    
    /* Check process name and cmdline for miner indicators */
    if (contains_any(process->comm, MINER_STRINGS)) {
        score += 0.5f;
    }
    
    if (contains_any(process->cmdline, MINER_STRINGS)) {
        score += 0.4f;
    }
    
    /* High CPU usage is a miner indicator */
    float cpu = get_cpu_usage(process->pid);
    if (cpu > 80.0f) {
        score += 0.2f;
    }
    if (cpu > 95.0f) {
        score += 0.2f;
    }
    
    /* Check for stratum protocol in cmdline */
    if (strstr(process->cmdline, "stratum") != NULL) {
        score += 0.5f;
    }
    
    return score > 1.0f ? 1.0f : score;
}

/**
 * Check for suspicious parent-child relationship.
 */
float deft_heuristics_check_parent_child(const deft_process_t *process)
{
    if (!process || process->ppid <= 1) {
        return 0.0f;
    }
    
    float score = 0.0f;
    
    /* Get parent process name */
    char parent_comm[256] = {0};
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", process->ppid);
    
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, parent_comm, sizeof(parent_comm) - 1);
        close(fd);
        if (n > 0) {
            parent_comm[n] = '\0';
            /* Remove trailing newline */
            char *nl = strchr(parent_comm, '\n');
            if (nl) *nl = '\0';
        }
    }
    
    /* Binary spawned by script interpreter */
    if (contains_any(parent_comm, SUSPICIOUS_PARENTS)) {
        /* Not necessarily bad, but worth noting */
        score += 0.1f;
        
        /* If running from tmp, more suspicious */
        if (deft_is_suspicious_path(process->exe_path)) {
            score += 0.3f;
        }
    }
    
    return score > 1.0f ? 1.0f : score;
}

/**
 * Check if process is running from a suspicious path.
 */
bool deft_is_suspicious_execution_path(const char *path)
{
    return deft_is_suspicious_path(path);
}

/**
 * Analyze a process using all heuristic rules.
 */
int deft_heuristics_analyze(const deft_process_t *process,
                            deft_heuristic_result_t *result)
{
    if (!process || !result) {
        return -1;
    }
    
    memset(result, 0, sizeof(deft_heuristic_result_t));
    
    float total_score = 0.0f;
    float total_weight = 0.0f;
    
    /* Check each heuristic */
    
    /* Suspicious path */
    if (g_rules[1].enabled && deft_is_suspicious_path(process->exe_path)) {
        result->flags |= DEFT_FLAG_SUSPICIOUS_PATH;
        result->triggered_rules[result->triggered_count++] = g_rules[1].name;
        total_score += g_rules[1].weight;
        total_weight += g_rules[1].weight;
    }
    
    /* Rootkit behavior */
    if (g_rules[4].enabled) {
        float rootkit_score = deft_heuristics_check_rootkit(process);
        if (rootkit_score > 0.3f) {
            result->flags |= DEFT_FLAG_ROOTKIT_BEHAVIOR;
            result->triggered_rules[result->triggered_count++] = g_rules[4].name;
            total_score += g_rules[4].weight * rootkit_score;
            total_weight += g_rules[4].weight;
        }
    }
    
    /* Ransomware indicators */
    if (g_rules[5].enabled) {
        float ransomware_score = deft_heuristics_check_ransomware(process, 
                                                                   &process->features);
        if (ransomware_score > 0.3f) {
            result->flags |= DEFT_FLAG_RANSOMWARE;
            result->triggered_rules[result->triggered_count++] = g_rules[5].name;
            total_score += g_rules[5].weight * ransomware_score;
            total_weight += g_rules[5].weight;
        }
    }
    
    /* Crypto mining */
    if (g_rules[6].enabled) {
        float miner_score = deft_heuristics_check_cryptominer(process);
        if (miner_score > 0.3f) {
            result->flags |= DEFT_FLAG_CRYPTO_MINING;
            result->triggered_rules[result->triggered_count++] = g_rules[6].name;
            total_score += g_rules[6].weight * miner_score;
            total_weight += g_rules[6].weight;
        }
    }
    
    /* Parent-child relationship */
    float parent_score = deft_heuristics_check_parent_child(process);
    if (parent_score > 0.3f) {
        total_score += 0.2f * parent_score;
        total_weight += 0.2f;
    }
    
    /* Check features if available */
    if (process->features.valid) {
        /* High entropy */
        if (g_rules[0].enabled && process->features.entropy > 7.0f) {
            result->flags |= DEFT_FLAG_HIGH_ENTROPY;
            result->triggered_rules[result->triggered_count++] = g_rules[0].name;
            total_score += g_rules[0].weight;
            total_weight += g_rules[0].weight;
        }
        
        /* Packing */
        if (g_rules[2].enabled) {
            float pack_score = deft_heuristics_check_packing(&process->features);
            if (pack_score > 0.3f) {
                result->flags |= DEFT_FLAG_PACKED;
                result->triggered_rules[result->triggered_count++] = g_rules[2].name;
                total_score += g_rules[2].weight * pack_score;
                total_weight += g_rules[2].weight;
            }
        }
        
        /* Anomaly imports */
        if (g_rules[11].enabled) {
            float import_score = deft_heuristics_check_imports(&process->features);
            if (import_score > 0.3f) {
                result->flags |= DEFT_FLAG_ANOMALY_IMPORTS;
                result->triggered_rules[result->triggered_count++] = g_rules[11].name;
                total_score += g_rules[11].weight * import_score;
                total_weight += g_rules[11].weight;
            }
        }
    }
    
    /* Calculate final score */
    if (total_weight > 0) {
        result->score = total_score / total_weight;
    } else {
        result->score = 0.0f;
    }
    
    return 0;
}

/**
 * Analyze a file using heuristic rules.
 */
int deft_heuristics_analyze_file(const char *path,
                                 const deft_features_t *features,
                                 deft_heuristic_result_t *result)
{
    if (!path || !result) {
        return -1;
    }
    
    memset(result, 0, sizeof(deft_heuristic_result_t));
    
    float total_score = 0.0f;
    
    /* Check suspicious path */
    if (deft_is_suspicious_path(path)) {
        result->flags |= DEFT_FLAG_SUSPICIOUS_PATH;
        result->triggered_rules[result->triggered_count++] = "suspicious_path";
        total_score += 0.3f;
    }
    
    /* Check features if provided */
    if (features && features->valid) {
        /* High entropy */
        if (features->entropy > 7.0f) {
            result->flags |= DEFT_FLAG_HIGH_ENTROPY;
            result->triggered_rules[result->triggered_count++] = "high_entropy";
            total_score += 0.25f;
        }
        
        /* Packing */
        float pack_score = deft_heuristics_check_packing(features);
        if (pack_score > 0.3f) {
            result->flags |= DEFT_FLAG_PACKED;
            result->triggered_rules[result->triggered_count++] = "packed_binary";
            total_score += 0.25f * pack_score;
        }
        
        /* Import anomalies */
        float import_score = deft_heuristics_check_imports(features);
        if (import_score > 0.3f) {
            result->flags |= DEFT_FLAG_ANOMALY_IMPORTS;
            result->triggered_rules[result->triggered_count++] = "anomaly_imports";
            total_score += 0.2f * import_score;
        }
    }
    
    result->score = total_score > 1.0f ? 1.0f : total_score;
    
    return 0;
}

/**
 * Enable or disable a specific rule.
 */
int deft_heuristics_set_rule(const char *rule_name, bool enabled)
{
    if (!rule_name) {
        return -1;
    }
    
    for (int i = 0; i < g_num_rules; i++) {
        if (strcmp(g_rules[i].name, rule_name) == 0) {
            g_rules[i].enabled = enabled;
            DEFT_LOG_INFO("Rule '%s' %s", rule_name, 
                          enabled ? "enabled" : "disabled");
            return 0;
        }
    }
    
    return -1;  /* Rule not found */
}

/**
 * Get list of all rules.
 */
int deft_heuristics_get_rules(deft_heuristic_rule_t *rules, int max_rules)
{
    if (!rules || max_rules <= 0) {
        return -1;
    }
    
    int count = max_rules < g_num_rules ? max_rules : g_num_rules;
    memcpy(rules, g_rules, count * sizeof(deft_heuristic_rule_t));
    
    return count;
}

/**
 * Load custom rules from configuration file.
 * 
 * File format (one rule per line):
 * enable <rule_name>
 * disable <rule_name>
 * weight <rule_name> <value>
 */
int deft_heuristics_load_rules(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        DEFT_LOG_WARN("Failed to open rules file: %s", path);
        return -1;
    }
    
    char line[256];
    int changes = 0;
    
    while (fgets(line, sizeof(line), f) != NULL) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        char name[64];
        float value;
        
        if (sscanf(line, "enable %63s", name) == 1) {
            if (deft_heuristics_set_rule(name, true) == 0) {
                changes++;
            }
        } else if (sscanf(line, "disable %63s", name) == 1) {
            if (deft_heuristics_set_rule(name, false) == 0) {
                changes++;
            }
        } else if (sscanf(line, "weight %63s %f", name, &value) == 2) {
            for (int i = 0; i < g_num_rules; i++) {
                if (strcmp(g_rules[i].name, name) == 0) {
                    g_rules[i].weight = value;
                    DEFT_LOG_INFO("Rule '%s' weight set to %.2f", name, value);
                    changes++;
                    break;
                }
            }
        }
    }
    
    fclose(f);
    DEFT_LOG_INFO("Loaded %d rule changes from: %s", changes, path);
    
    return changes;
}
