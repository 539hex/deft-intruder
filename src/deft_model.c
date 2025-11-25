/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_model.c - Machine Learning inference engine
 * 
 * This module implements a lightweight Random Forest classifier for
 * malware detection. The model can be loaded from an external file
 * or use an embedded model trained on the EMBER dataset.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "deft_types.h"
#include "deft_model.h"
#include "deft_features.h"
#include "deft_log.h"

/* Include embedded model data if available */
#ifdef DEFT_EMBEDDED_MODEL
#include "deft_model_data.h"
#endif

/* ============================================================================
 * Private Constants
 * ============================================================================ */

/* Model file magic number for validation */
#define MODEL_FILE_MAGIC    0x54464544  /* "DEFT" */
#define MODEL_FILE_VERSION  1

/* Threshold levels for classification */
#define THRESHOLD_SUSPICIOUS    0.3f    /* Below this = clean */
#define THRESHOLD_MALWARE       0.5f    /* Above this = malware */

/* ============================================================================
 * Private State
 * ============================================================================ */

static bool g_model_initialized = false;

/* ============================================================================
 * Decision Tree Traversal
 * ============================================================================ */

/**
 * Traverse a single decision tree to get prediction.
 * 
 * This function walks through the tree from root to a leaf node,
 * making split decisions based on feature values at each node.
 * 
 * @param tree          Pointer to decision tree
 * @param feature_vec   Feature vector (DEFT_FEATURE_COUNT floats)
 * @return Leaf value (malware probability)
 */
float deft_tree_predict(const deft_decision_tree_t *tree, 
                        const float *feature_vec)
{
    if (!tree || !feature_vec || tree->node_count == 0) {
        return 0.5f;  /* Return neutral on error */
    }
    
    /* Start at root node (index 0) */
    int node_idx = 0;
    
    /* Traverse tree until we reach a leaf */
    while (node_idx >= 0 && node_idx < (int)tree->node_count) {
        const deft_tree_node_t *node = &tree->nodes[node_idx];
        
        /* Check if this is a leaf node */
        if (node->feature_index < 0) {
            /* Leaf node - return the stored probability */
            return node->value;
        }
        
        /* Internal node - make split decision */
        if (node->feature_index >= DEFT_FEATURE_COUNT) {
            /* Invalid feature index - return neutral */
            DEFT_LOG_WARN("Invalid feature index %d in tree", node->feature_index);
            return 0.5f;
        }
        
        /* Compare feature value to threshold */
        float feature_value = feature_vec[node->feature_index];
        
        if (feature_value <= node->threshold) {
            /* Go left */
            node_idx = node->left_child;
        } else {
            /* Go right */
            node_idx = node->right_child;
        }
    }
    
    /* Should not reach here - invalid tree structure */
    DEFT_LOG_WARN("Tree traversal ended without reaching leaf");
    return 0.5f;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/**
 * Initialize the ML model subsystem.
 */
int deft_model_init(void)
{
    if (g_model_initialized) {
        return 0;  /* Already initialized */
    }
    
    DEFT_LOG_INFO("ML model subsystem initialized");
    g_model_initialized = true;
    
    return 0;
}

/**
 * Cleanup model resources.
 */
void deft_model_cleanup(void)
{
    g_model_initialized = false;
    DEFT_LOG_INFO("ML model subsystem cleaned up");
}

/**
 * Load a model from binary file.
 * 
 * File format:
 * - 64-byte header (magic, version, tree_count, etc.)
 * - Tree data (node_count + nodes for each tree)
 */
int deft_model_load(deft_model_t *model, const char *path)
{
    if (!model || !path) {
        return -1;
    }
    
    /* Initialize model to empty state */
    memset(model, 0, sizeof(deft_model_t));
    
    /* Open model file */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        DEFT_LOG_ERROR("Failed to open model file: %s", path);
        return -1;
    }
    
    /* Read header */
    deft_model_header_t header;
    if (read(fd, &header, sizeof(header)) != sizeof(header)) {
        DEFT_LOG_ERROR("Failed to read model header");
        close(fd);
        return -1;
    }
    
    /* Validate header */
    if (header.magic != MODEL_FILE_MAGIC) {
        DEFT_LOG_ERROR("Invalid model file magic: 0x%08X", header.magic);
        close(fd);
        return -1;
    }
    
    if (header.version != MODEL_FILE_VERSION) {
        DEFT_LOG_ERROR("Unsupported model version: %u", header.version);
        close(fd);
        return -1;
    }
    
    if (header.tree_count > DEFT_MAX_TREES) {
        DEFT_LOG_ERROR("Too many trees in model: %u", header.tree_count);
        close(fd);
        return -1;
    }
    
    /* Store model metadata */
    model->tree_count = header.tree_count;
    model->threshold = header.threshold;
    
    /* Read tree data */
    for (uint32_t t = 0; t < header.tree_count; t++) {
        /* Read node count for this tree */
        uint32_t node_count;
        if (read(fd, &node_count, sizeof(node_count)) != sizeof(node_count)) {
            DEFT_LOG_ERROR("Failed to read node count for tree %u", t);
            close(fd);
            return -1;
        }
        
        if (node_count > DEFT_MAX_TREE_NODES) {
            DEFT_LOG_ERROR("Too many nodes in tree %u: %u", t, node_count);
            close(fd);
            return -1;
        }
        
        model->trees[t].node_count = node_count;
        
        /* Read nodes */
        size_t nodes_size = node_count * sizeof(deft_tree_node_t);
        if (read(fd, model->trees[t].nodes, nodes_size) != (ssize_t)nodes_size) {
            DEFT_LOG_ERROR("Failed to read nodes for tree %u", t);
            close(fd);
            return -1;
        }
    }
    
    close(fd);
    
    model->loaded = true;
    DEFT_LOG_INFO("Loaded model from %s (%u trees)", path, model->tree_count);
    
    return 0;
}

/**
 * Load the embedded model.
 * 
 * This uses the model data compiled into the binary from
 * the deft_model_data.h header file.
 */
int deft_model_load_embedded(deft_model_t *model)
{
    if (!model) {
        return -1;
    }
    
#ifdef DEFT_EMBEDDED_MODEL
    /* Use the embedded model data */
    int result = deft_load_embedded_model(model);
    if (result == 0) {
        DEFT_LOG_INFO("Loaded embedded model (%u trees)", model->tree_count);
    }
    return result;
#else
    /* No embedded model available */
    DEFT_LOG_WARN("No embedded model available - build with DEFT_EMBEDDED_MODEL");
    
    /* Create a minimal placeholder model */
    memset(model, 0, sizeof(deft_model_t));
    model->tree_count = 1;
    model->threshold = 0.5f;
    
    /* Single tree with just a root leaf node */
    model->trees[0].node_count = 1;
    model->trees[0].nodes[0].feature_index = -1;  /* Leaf */
    model->trees[0].nodes[0].value = 0.5f;        /* Neutral */
    
    model->loaded = true;
    
    return 0;
#endif
}

/**
 * Save model to binary file.
 */
int deft_model_save(const deft_model_t *model, const char *path)
{
    if (!model || !path || !model->loaded) {
        return -1;
    }
    
    /* Open output file */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        DEFT_LOG_ERROR("Failed to create model file: %s", path);
        return -1;
    }
    
    /* Prepare header */
    deft_model_header_t header = {
        .magic = MODEL_FILE_MAGIC,
        .version = MODEL_FILE_VERSION,
        .tree_count = model->tree_count,
        .feature_count = DEFT_FEATURE_COUNT,
        .threshold = model->threshold,
        .checksum = 0  /* TODO: Calculate checksum */
    };
    memset(header.reserved, 0, sizeof(header.reserved));
    
    /* Write header */
    if (write(fd, &header, sizeof(header)) != sizeof(header)) {
        DEFT_LOG_ERROR("Failed to write model header");
        close(fd);
        return -1;
    }
    
    /* Write tree data */
    for (uint32_t t = 0; t < model->tree_count; t++) {
        /* Write node count */
        if (write(fd, &model->trees[t].node_count, sizeof(uint32_t)) != sizeof(uint32_t)) {
            close(fd);
            return -1;
        }
        
        /* Write nodes */
        size_t nodes_size = model->trees[t].node_count * sizeof(deft_tree_node_t);
        if (write(fd, model->trees[t].nodes, nodes_size) != (ssize_t)nodes_size) {
            close(fd);
            return -1;
        }
    }
    
    close(fd);
    DEFT_LOG_INFO("Saved model to %s", path);
    
    return 0;
}

/**
 * Predict malware probability for a feature vector.
 * 
 * This runs inference using the Random Forest ensemble by
 * averaging predictions from all trees.
 */
float deft_model_predict(const deft_model_t *model, 
                         const deft_features_t *features)
{
    if (!model || !features || !model->loaded) {
        return -1.0f;
    }
    
    if (!features->valid) {
        /* Features were not successfully extracted */
        return -1.0f;
    }
    
    return deft_model_predict_raw(model, features->features);
}

/**
 * Predict malware probability for a raw feature array.
 */
float deft_model_predict_raw(const deft_model_t *model, 
                             const float *feature_vec)
{
    if (!model || !feature_vec || !model->loaded) {
        return -1.0f;
    }
    
    if (model->tree_count == 0) {
        return -1.0f;
    }
    
    /* Aggregate predictions from all trees */
    float sum = 0.0f;
    
    for (uint32_t t = 0; t < model->tree_count; t++) {
        float tree_pred = deft_tree_predict(&model->trees[t], feature_vec);
        sum += tree_pred;
    }
    
    /* Average across all trees */
    float prediction = sum / (float)model->tree_count;
    
    return prediction;
}

/**
 * Classify a sample as clean, suspicious, or malware.
 */
deft_result_t deft_model_classify(const deft_model_t *model,
                                  const deft_features_t *features)
{
    float score = deft_model_predict(model, features);
    
    if (score < 0) {
        return DEFT_RESULT_ERROR;
    }
    
    /* Apply threshold to classify */
    if (score >= model->threshold) {
        return DEFT_RESULT_MALWARE;
    } else if (score >= THRESHOLD_SUSPICIOUS) {
        return DEFT_RESULT_SUSPICIOUS;
    } else {
        return DEFT_RESULT_CLEAN;
    }
}

/**
 * Get feature importance from the model.
 * 
 * This estimates feature importance by counting how many times
 * each feature is used as a split criterion across all trees.
 */
int deft_model_get_importance(const deft_model_t *model, float *importance)
{
    if (!model || !importance || !model->loaded) {
        return -1;
    }
    
    /* Initialize importance array */
    memset(importance, 0, DEFT_FEATURE_COUNT * sizeof(float));
    
    uint32_t total_splits = 0;
    
    /* Count feature usage across all trees */
    for (uint32_t t = 0; t < model->tree_count; t++) {
        const deft_decision_tree_t *tree = &model->trees[t];
        
        for (uint32_t n = 0; n < tree->node_count; n++) {
            int16_t feat_idx = tree->nodes[n].feature_index;
            
            /* Skip leaf nodes (feature_index == -1) */
            if (feat_idx >= 0 && feat_idx < DEFT_FEATURE_COUNT) {
                importance[feat_idx] += 1.0f;
                total_splits++;
            }
        }
    }
    
    /* Normalize to sum to 1.0 */
    if (total_splits > 0) {
        for (int i = 0; i < DEFT_FEATURE_COUNT; i++) {
            importance[i] /= (float)total_splits;
        }
    }
    
    return 0;
}

/**
 * Validate model integrity.
 */
bool deft_model_validate(const deft_model_t *model)
{
    if (!model || !model->loaded) {
        return false;
    }
    
    if (model->tree_count == 0 || model->tree_count > DEFT_MAX_TREES) {
        return false;
    }
    
    /* Validate each tree */
    for (uint32_t t = 0; t < model->tree_count; t++) {
        const deft_decision_tree_t *tree = &model->trees[t];
        
        if (tree->node_count == 0 || tree->node_count > DEFT_MAX_TREE_NODES) {
            return false;
        }
        
        /* Check for at least one leaf node */
        bool has_leaf = false;
        for (uint32_t n = 0; n < tree->node_count; n++) {
            if (tree->nodes[n].feature_index < 0) {
                has_leaf = true;
                break;
            }
        }
        
        if (!has_leaf) {
            return false;
        }
    }
    
    return true;
}

/**
 * Print model statistics.
 */
void deft_model_print_stats(const deft_model_t *model, FILE *stream)
{
    if (!model || !stream) {
        return;
    }
    
    fprintf(stream, "=== ML Model Statistics ===\n");
    fprintf(stream, "Loaded: %s\n", model->loaded ? "Yes" : "No");
    fprintf(stream, "Tree Count: %u\n", model->tree_count);
    fprintf(stream, "Threshold: %.3f\n", model->threshold);
    
    uint32_t total_nodes = 0;
    uint32_t total_leaves = 0;
    
    for (uint32_t t = 0; t < model->tree_count; t++) {
        const deft_decision_tree_t *tree = &model->trees[t];
        total_nodes += tree->node_count;
        
        for (uint32_t n = 0; n < tree->node_count; n++) {
            if (tree->nodes[n].feature_index < 0) {
                total_leaves++;
            }
        }
        
        fprintf(stream, "  Tree %u: %u nodes\n", t, tree->node_count);
    }
    
    fprintf(stream, "Total Nodes: %u\n", total_nodes);
    fprintf(stream, "Total Leaves: %u\n", total_leaves);
    fprintf(stream, "Approx Size: %u bytes\n", 
            (unsigned int)(total_nodes * sizeof(deft_tree_node_t)));
}
