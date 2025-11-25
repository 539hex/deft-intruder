/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_features.h - Feature extraction interface for binary analysis
 * 
 * This module extracts features from executables for ML-based classification.
 * Features are designed to be compatible with the EMBER dataset format.
 */

#ifndef DEFT_FEATURES_H
#define DEFT_FEATURES_H

#include "deft_types.h"
#include <stdio.h>

/* ============================================================================
 * Feature Index Constants (EMBER-compatible subset)
 * 
 * These indices map to specific features in the feature vector.
 * The features are organized into groups for clarity.
 * ============================================================================ */

/* General file properties (0-9) */
#define FEAT_FILE_SIZE              0   /* Normalized file size */
#define FEAT_VIRTUAL_SIZE           1   /* Virtual size of image */
#define FEAT_SECTION_COUNT          2   /* Number of sections */
#define FEAT_SYMBOL_COUNT           3   /* Number of symbols */
#define FEAT_IMPORT_COUNT           4   /* Number of imports */
#define FEAT_EXPORT_COUNT           5   /* Number of exports */
#define FEAT_RESOURCE_COUNT         6   /* Number of resources */
#define FEAT_RELOC_COUNT            7   /* Number of relocations */
#define FEAT_DEBUG_SIZE             8   /* Debug information size */
#define FEAT_HAS_TLS                9   /* Has TLS callbacks */

/* Header properties (10-29) */
#define FEAT_HEADER_CHECKSUM        10  /* Header checksum validity */
#define FEAT_TIMESTAMP              11  /* Compile timestamp normalized */
#define FEAT_MACHINE_TYPE           12  /* Target machine type */
#define FEAT_CHARACTERISTICS        13  /* File characteristics flags */
#define FEAT_SUBSYSTEM              14  /* Subsystem type */
#define FEAT_DLL_CHARACTERISTICS    15  /* DLL characteristics */
#define FEAT_STACK_RESERVE          16  /* Stack reserve size */
#define FEAT_HEAP_RESERVE           17  /* Heap reserve size */
#define FEAT_ENTRY_POINT            18  /* Entry point RVA normalized */
#define FEAT_BASE_OF_CODE           19  /* Base of code section */

/* Entropy features (30-49) */
#define FEAT_ENTROPY_OVERALL        30  /* Overall file entropy */
#define FEAT_ENTROPY_HEADER         31  /* Header entropy */
#define FEAT_ENTROPY_CODE           32  /* Code section entropy */
#define FEAT_ENTROPY_DATA           33  /* Data section entropy */
#define FEAT_ENTROPY_RSRC           34  /* Resource section entropy */
#define FEAT_ENTROPY_MIN            35  /* Minimum section entropy */
#define FEAT_ENTROPY_MAX            36  /* Maximum section entropy */
#define FEAT_ENTROPY_MEAN           37  /* Mean section entropy */
#define FEAT_ENTROPY_VARIANCE       38  /* Entropy variance */
#define FEAT_HIGH_ENTROPY_SECTIONS  39  /* Count of high entropy sections */

/* Section features (50-79) */
#define FEAT_SECTION_BASE           50  /* Base index for section features */
#define FEAT_EXECUTABLE_SECTIONS    50  /* Number of executable sections */
#define FEAT_WRITABLE_SECTIONS      51  /* Number of writable sections */
#define FEAT_READABLE_SECTIONS      52  /* Number of readable sections */
#define FEAT_RWX_SECTIONS           53  /* Sections with RWX permissions */
#define FEAT_UNUSUAL_SECTION_NAMES  54  /* Count of unusual section names */
#define FEAT_CODE_SECTION_SIZE      55  /* Normalized code section size */
#define FEAT_DATA_SECTION_SIZE      56  /* Normalized data section size */
#define FEAT_BSS_SECTION_SIZE       57  /* Normalized BSS section size */
#define FEAT_ZERO_SIZE_SECTIONS     58  /* Sections with zero raw size */

/* String features (80-109) */
#define FEAT_STRING_BASE            80  /* Base index for string features */
#define FEAT_STRING_COUNT           80  /* Total string count */
#define FEAT_AVG_STRING_LENGTH      81  /* Average string length */
#define FEAT_URL_COUNT              82  /* URL patterns in strings */
#define FEAT_IP_COUNT               83  /* IP address patterns */
#define FEAT_FILEPATH_COUNT         84  /* File path patterns */
#define FEAT_REGISTRY_COUNT         85  /* Registry key patterns */
#define FEAT_SUSPICIOUS_STRINGS     86  /* Known malicious strings */
#define FEAT_CRYPTO_STRINGS         87  /* Cryptographic strings */
#define FEAT_PACKER_STRINGS         88  /* Packer/protector strings */
#define FEAT_NETWORK_STRINGS        89  /* Network-related strings */

/* Import features (110-159) - Histogram of import categories */
#define FEAT_IMPORT_BASE            110 /* Base index for import features */
#define FEAT_IMP_FILESYSTEM         110 /* File system operations */
#define FEAT_IMP_REGISTRY           111 /* Registry operations */
#define FEAT_IMP_NETWORK            112 /* Network operations */
#define FEAT_IMP_PROCESS            113 /* Process operations */
#define FEAT_IMP_THREAD             114 /* Thread operations */
#define FEAT_IMP_MEMORY             115 /* Memory operations */
#define FEAT_IMP_CRYPTO             116 /* Cryptographic operations */
#define FEAT_IMP_SYSTEM             117 /* System calls */
#define FEAT_IMP_USER               118 /* User/security operations */
#define FEAT_IMP_DEBUG              119 /* Debugging operations */
#define FEAT_IMP_SERVICE            120 /* Service operations */
#define FEAT_IMP_DEVICE             121 /* Device operations */
#define FEAT_IMP_SHELL              122 /* Shell operations */
#define FEAT_IMP_INJECTION          123 /* Code injection patterns */
#define FEAT_IMP_KEYLOG             124 /* Keylogging patterns */

/* Byte histogram features (160-191) - 32-bin byte histogram */
#define FEAT_BYTE_HIST_BASE         160 /* Base for byte histogram */

/* Byte entropy histogram (192-223) - 32-bin entropy histogram */
#define FEAT_BYTE_ENTROPY_BASE      192 /* Base for byte entropy histogram */

/* Additional heuristic features (224-255) */
#define FEAT_HEURISTIC_BASE         224 /* Base for heuristic features */
#define FEAT_PACKED_INDICATOR       224 /* Packing detection score */
#define FEAT_OBFUSCATION_SCORE      225 /* Obfuscation score */
#define FEAT_ANTI_DEBUG_SCORE       226 /* Anti-debugging score */
#define FEAT_ANTI_VM_SCORE          227 /* Anti-VM score */
#define FEAT_ROOTKIT_SCORE          228 /* Rootkit behavior score */
#define FEAT_RANSOMWARE_SCORE       229 /* Ransomware behavior score */
#define FEAT_BACKDOOR_SCORE         230 /* Backdoor behavior score */
#define FEAT_DROPPER_SCORE          231 /* Dropper behavior score */

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

/**
 * Initialize the feature extraction subsystem.
 * 
 * This function must be called before using any other feature extraction
 * functions. It loads necessary resources and initializes internal state.
 * 
 * @return 0 on success, negative error code on failure
 */
int deft_features_init(void);

/**
 * Cleanup and release resources used by the feature extraction subsystem.
 * 
 * Call this function when shutting down to properly release all resources.
 */
void deft_features_cleanup(void);

/**
 * Extract features from a file on disk.
 * 
 * Analyzes the specified file and extracts a feature vector suitable for
 * ML-based classification. Works with ELF binaries, PE files (via Wine),
 * and script files.
 * 
 * @param path      Path to the file to analyze
 * @param features  Pointer to structure to receive extracted features
 * @return 0 on success, negative error code on failure
 */
int deft_extract_file_features(const char *path, deft_features_t *features);

/**
 * Extract features from a memory buffer.
 * 
 * Analyzes binary data in memory and extracts features. Useful for analyzing
 * files without disk access or for analyzing memory-mapped content.
 * 
 * @param data      Pointer to binary data
 * @param size      Size of the data in bytes
 * @param features  Pointer to structure to receive extracted features
 * @return 0 on success, negative error code on failure
 */
int deft_extract_buffer_features(const uint8_t *data, size_t size, 
                                  deft_features_t *features);

/**
 * Calculate Shannon entropy of a data buffer.
 * 
 * Computes the Shannon entropy of the given data, which measures the
 * randomness/information density. Values range from 0 (very uniform)
 * to 8 (maximum randomness for byte data).
 * 
 * @param data  Pointer to data buffer
 * @param size  Size of data in bytes
 * @return Entropy value between 0.0 and 8.0
 */
float deft_calculate_entropy(const uint8_t *data, size_t size);

/**
 * Detect the type of binary from its header.
 * 
 * Examines the file header to determine if it's an ELF binary, PE file,
 * script, or unknown format.
 * 
 * @param data  Pointer to file data (at least 64 bytes)
 * @param size  Size of available data
 * @return Binary type enumeration value
 */
deft_bin_type_t deft_detect_binary_type(const uint8_t *data, size_t size);

/**
 * Print feature vector to a file stream (for debugging).
 * 
 * @param features  Pointer to feature structure to print
 * @param stream    Output stream (e.g., stdout, stderr, or log file)
 */
void deft_print_features(const deft_features_t *features, FILE *stream);

/**
 * Normalize a feature value to the range [0, 1].
 * 
 * Uses min-max normalization based on training data statistics.
 * 
 * @param feature_index  Index of the feature
 * @param raw_value      Raw feature value
 * @return Normalized value between 0.0 and 1.0
 */
float deft_normalize_feature(int feature_index, float raw_value);

/**
 * Check if a section name is suspicious.
 * 
 * Compares against known packer/protector section names.
 * 
 * @param name  Section name to check
 * @return true if suspicious, false otherwise
 */
bool deft_is_suspicious_section_name(const char *name);

/**
 * Check if a string matches known malicious patterns.
 * 
 * @param str  String to check
 * @return Maliciousness score (0.0 to 1.0)
 */
float deft_check_suspicious_string(const char *str);

#endif /* DEFT_FEATURES_H */
