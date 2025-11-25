/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_model.h - Machine Learning model interface
 * 
 * This module provides ML-based classification using a lightweight
 * decision tree ensemble (Random Forest) trained on the EMBER dataset.
 */

#ifndef DEFT_MODEL_H
#define DEFT_MODEL_H

#include "deft_types.h"

/* ============================================================================
 * Model File Format Constants
 * ============================================================================ */

/* Magic number for model files: "DEFT" in little-endian */
#define DEFT_MODEL_MAGIC    0x54464544

/* Current model file format version */
#define DEFT_MODEL_VERSION  1

/* ============================================================================
 * Model File Header Structure (for loading/saving models)
 * ============================================================================ */

typedef struct __attribute__((packed)) {
    uint32_t magic;              /* Magic number for validation */
    uint32_t version;            /* File format version */
    uint32_t tree_count;         /* Number of trees in ensemble */
    uint32_t feature_count;      /* Number of features used */
    float threshold;             /* Classification threshold */
    uint32_t checksum;           /* CRC32 checksum of tree data */
    uint8_t reserved[40];        /* Reserved for future use */
} deft_model_header_t;

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

/**
 * Initialize the ML model subsystem.
 * 
 * Prepares internal structures for model loading and inference.
 * Must be called before any other model functions.
 * 
 * @return 0 on success, negative error code on failure
 */
int deft_model_init(void);

/**
 * Cleanup and release model resources.
 * 
 * Frees all memory associated with loaded models.
 */
void deft_model_cleanup(void);

/**
 * Load a trained model from a file.
 * 
 * Reads a pre-trained model from the specified file path.
 * The model file should be in DEFT binary format.
 * 
 * @param model     Pointer to model structure to populate
 * @param path      Path to the model file
 * @return 0 on success, negative error code on failure
 */
int deft_model_load(deft_model_t *model, const char *path);

/**
 * Load the embedded default model.
 * 
 * Uses the compiled-in model trained on EMBER dataset.
 * This is the default model used when no external model is specified.
 * 
 * @param model     Pointer to model structure to populate
 * @return 0 on success, negative error code on failure
 */
int deft_model_load_embedded(deft_model_t *model);

/**
 * Save a trained model to a file.
 * 
 * Writes the model to disk in DEFT binary format.
 * Useful for saving models trained with the Python script.
 * 
 * @param model     Pointer to model to save
 * @param path      Path to output file
 * @return 0 on success, negative error code on failure
 */
int deft_model_save(const deft_model_t *model, const char *path);

/**
 * Predict malware probability for a feature vector.
 * 
 * Runs inference using the loaded model ensemble and returns
 * the probability that the sample is malware.
 * 
 * @param model     Pointer to loaded model
 * @param features  Pointer to extracted features
 * @return Malware probability (0.0 to 1.0), or -1.0 on error
 */
float deft_model_predict(const deft_model_t *model, 
                         const deft_features_t *features);

/**
 * Predict malware probability for a raw feature array.
 * 
 * Lower-level prediction function that works directly with
 * feature arrays instead of the feature structure.
 * 
 * @param model         Pointer to loaded model
 * @param feature_vec   Array of DEFT_FEATURE_COUNT float values
 * @return Malware probability (0.0 to 1.0), or -1.0 on error
 */
float deft_model_predict_raw(const deft_model_t *model, 
                             const float *feature_vec);

/**
 * Classify a sample as malware, suspicious, or clean.
 * 
 * Uses the model's threshold settings to classify the sample.
 * 
 * @param model     Pointer to loaded model
 * @param features  Pointer to extracted features
 * @return Classification result (DEFT_RESULT_*)
 */
deft_result_t deft_model_classify(const deft_model_t *model,
                                  const deft_features_t *features);

/**
 * Get feature importance scores from the model.
 * 
 * Returns an array indicating the relative importance of each
 * feature in the classification decision.
 * 
 * @param model         Pointer to loaded model
 * @param importance    Array to receive importance scores (DEFT_FEATURE_COUNT elements)
 * @return 0 on success, negative error code on failure
 */
int deft_model_get_importance(const deft_model_t *model, float *importance);

/**
 * Validate model integrity.
 * 
 * Checks if the model is properly loaded and internally consistent.
 * 
 * @param model     Pointer to model to validate
 * @return true if valid, false otherwise
 */
bool deft_model_validate(const deft_model_t *model);

/**
 * Print model statistics (for debugging).
 * 
 * @param model     Pointer to model
 * @param stream    Output stream
 */
void deft_model_print_stats(const deft_model_t *model, FILE *stream);

/**
 * Traverse a single decision tree for prediction.
 * 
 * Internal function exposed for testing purposes.
 * 
 * @param tree          Pointer to decision tree
 * @param feature_vec   Feature vector array
 * @return Leaf node value (probability)
 */
float deft_tree_predict(const deft_decision_tree_t *tree, 
                        const float *feature_vec);

#endif /* DEFT_MODEL_H */
