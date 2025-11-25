/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_heuristics.h - Heuristic-based detection rules
 * 
 * This module implements rule-based heuristic detection that complements
 * the ML-based classification. Heuristics catch behaviors that may not
 * be apparent from static features alone.
 */

#ifndef DEFT_HEURISTICS_H
#define DEFT_HEURISTICS_H

#include "deft_types.h"

/* ============================================================================
 * Heuristic Rule Structure
 * ============================================================================ */

typedef struct {
    const char *name;           /* Rule name */
    const char *description;    /* Rule description */
    uint32_t flag;              /* Detection flag (DEFT_FLAG_*) */
    float weight;               /* Weight in final score (0.0 - 1.0) */
    bool enabled;               /* Whether rule is active */
} deft_heuristic_rule_t;

/* ============================================================================
 * Heuristic Analysis Result
 * ============================================================================ */

typedef struct {
    uint32_t flags;             /* Combined detection flags */
    float score;                /* Overall heuristic score (0.0 - 1.0) */
    uint32_t triggered_count;   /* Number of rules triggered */
    const char *triggered_rules[32]; /* Names of triggered rules */
} deft_heuristic_result_t;

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

/**
 * Initialize the heuristics engine.
 * 
 * Loads default rules and prepares the engine for analysis.
 * 
 * @return 0 on success, negative error code on failure
 */
int deft_heuristics_init(void);

/**
 * Cleanup heuristics resources.
 */
void deft_heuristics_cleanup(void);

/**
 * Analyze a process using heuristic rules.
 * 
 * Applies all enabled heuristic rules to the process and
 * returns a combined result.
 * 
 * @param process   Process information
 * @param result    Structure to receive analysis result
 * @return 0 on success, negative error code on failure
 */
int deft_heuristics_analyze(const deft_process_t *process,
                            deft_heuristic_result_t *result);

/**
 * Analyze a file using heuristic rules.
 * 
 * @param path      Path to file
 * @param features  Extracted features
 * @param result    Structure to receive result
 * @return 0 on success, negative error code on failure
 */
int deft_heuristics_analyze_file(const char *path,
                                 const deft_features_t *features,
                                 deft_heuristic_result_t *result);

/**
 * Check if file appears to be packed or obfuscated.
 * 
 * Uses entropy analysis and section characteristics to detect
 * packing or obfuscation.
 * 
 * @param features  Extracted features
 * @return Packing probability (0.0 - 1.0)
 */
float deft_heuristics_check_packing(const deft_features_t *features);

/**
 * Check for anti-debugging techniques.
 * 
 * Looks for imports and behaviors associated with anti-debugging.
 * 
 * @param features  Extracted features
 * @return Anti-debug score (0.0 - 1.0)
 */
float deft_heuristics_check_antidebug(const deft_features_t *features);

/**
 * Check for suspicious import patterns.
 * 
 * Analyzes import table for malicious patterns.
 * 
 * @param features  Extracted features
 * @return Suspicion score (0.0 - 1.0)
 */
float deft_heuristics_check_imports(const deft_features_t *features);

/**
 * Check for rootkit-like behavior.
 * 
 * Looks for hidden processes, hooked syscalls, etc.
 * 
 * @param process   Process information
 * @return Rootkit score (0.0 - 1.0)
 */
float deft_heuristics_check_rootkit(const deft_process_t *process);

/**
 * Check for ransomware indicators.
 * 
 * Looks for encryption patterns, ransom note creation, etc.
 * 
 * @param process   Process information
 * @param features  Extracted features
 * @return Ransomware score (0.0 - 1.0)
 */
float deft_heuristics_check_ransomware(const deft_process_t *process,
                                        const deft_features_t *features);

/**
 * Check for crypto mining behavior.
 * 
 * Detects CPU-intensive processes with mining patterns.
 * 
 * @param process   Process information
 * @return Mining score (0.0 - 1.0)
 */
float deft_heuristics_check_cryptominer(const deft_process_t *process);

/**
 * Enable or disable a specific heuristic rule.
 * 
 * @param rule_name Name of the rule to modify
 * @param enabled   Whether to enable or disable
 * @return 0 on success, -1 if rule not found
 */
int deft_heuristics_set_rule(const char *rule_name, bool enabled);

/**
 * Get list of all available rules.
 * 
 * @param rules     Array to receive rule information
 * @param max_rules Maximum number of rules to return
 * @return Number of rules returned
 */
int deft_heuristics_get_rules(deft_heuristic_rule_t *rules, int max_rules);

/**
 * Load custom rules from a configuration file.
 * 
 * @param path      Path to rules configuration file
 * @return 0 on success, negative error code on failure
 */
int deft_heuristics_load_rules(const char *path);

/**
 * Check if process is running from a suspicious path.
 * 
 * @param path      Executable path
 * @return true if suspicious, false otherwise
 */
bool deft_is_suspicious_execution_path(const char *path);

/**
 * Check for suspicious parent-child relationship.
 * 
 * Some malware launches from unexpected parent processes.
 * 
 * @param process   Process information with parent info
 * @return Suspicion score (0.0 - 1.0)
 */
float deft_heuristics_check_parent_child(const deft_process_t *process);

#endif /* DEFT_HEURISTICS_H */
