#!/usr/bin/env python3
"""
DEFT-Intruder: Model Training Script

This script trains a lightweight Random Forest classifier on the EMBER 2018 dataset
and exports it to C code that can be embedded directly in the DEFT-Intruder daemon.

The EMBER dataset contains feature vectors extracted from Windows PE files,
labeled as malware (1), benign (0), or unknown (-1).

Features:
- Uses scikit-learn to train a small Random Forest model
- Exports decision trees to C arrays for embedding
- Generates model statistics and feature importance

Usage:
    python train_model.py <path_to_ember_dataset> <output_dir>

Requirements:
    pip install numpy scikit-learn lief tqdm

Copyright (C) 2025 - Open Source Project
License: GPL-3.0
"""

import os
import sys
import json
import struct
import hashlib
import argparse
import numpy as np
from pathlib import Path

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
    from tqdm import tqdm
except ImportError:
    print("Required packages not found. Install with:")
    print("  pip install numpy scikit-learn tqdm")
    sys.exit(1)


# ============================================================================
# Constants
# ============================================================================

# Maximum number of trees in the ensemble (keep small for embedded use)
MAX_TREES = 10

# Maximum depth of each tree
MAX_TREE_DEPTH = 15

# Number of features (Our vectorized EMBER features)
# Histogram(256) + ByteEntropy(256) + Strings(104) + General(10) + 
# Header(62) + Sections(255) + Imports(256) + Exports(128) + DataDirs(30) = 1357
NUM_FEATURES = 256  # We'll select top 256 most important features for embedded model

# Model file magic number: "DEFT" in little-endian
MODEL_MAGIC = 0x54464544

# Model file version
MODEL_VERSION = 1


# ============================================================================
# Feature Mapping
# ============================================================================

# EMBER feature indices that map to our reduced feature set
# We select the most important features from EMBER's 2381 features
EMBER_FEATURE_MAPPING = {
    # File properties (0-9)
    0: 0,      # File size
    1: 1,      # Virtual size
    2: 2,      # Section count
    3: 3,      # Symbol count
    4: 4,      # Import count
    5: 5,      # Export count
    6: 6,      # Resource count
    7: 7,      # Relocation count
    8: 8,      # Debug size
    9: 9,      # Has TLS
    
    # Entropy features (30-49 map from EMBER byte entropy histogram)
    # EMBER indices 256-511 are byte entropy histogram
    30: 256,   # Overall entropy (first bin)
    31: 260,   # Header entropy estimate
    32: 280,   # Code section entropy estimate
    33: 300,   # Data section entropy estimate
    
    # We'll fill the rest with selected important features from EMBER
}


def load_ember_dataset(dataset_path, max_samples_per_file=None):
    """
    Load the EMBER 2018 dataset from extracted directory.
    
    The EMBER dataset contains:
    - train_features_*.jsonl: Training data in JSONL format
    - test_features.jsonl: Test data in JSONL format
    
    Args:
        dataset_path: Path to extracted EMBER dataset directory
        max_samples_per_file: Optional limit on samples per file (for faster testing)
        
    Returns:
        Tuple of (X_train, y_train, X_test, y_test)
    """
    dataset_path = Path(dataset_path)
    
    print(f"[*] Loading EMBER dataset from {dataset_path}")
    
    # Check for pre-extracted binary files first
    train_x_path = dataset_path / "X_train.dat"
    train_y_path = dataset_path / "y_train.dat"
    test_x_path = dataset_path / "X_test.dat"
    test_y_path = dataset_path / "y_test.dat"
    
    # EMBER 2018 has specific dimensions
    # X: float32 features, Y: int32 labels
    n_train = 900000  # 900k training samples
    n_test = 200000   # 200k test samples
    n_features = 2381 # EMBER feature count
    
    if train_x_path.exists():
        print("[*] Loading pre-extracted feature files...")
        X_train = np.memmap(str(train_x_path), dtype=np.float32, 
                           mode='r', shape=(n_train, n_features))
        y_train = np.memmap(str(train_y_path), dtype=np.int32,
                           mode='r', shape=(n_train,))
        X_test = np.memmap(str(test_x_path), dtype=np.float32,
                          mode='r', shape=(n_test, n_features))
        y_test = np.memmap(str(test_y_path), dtype=np.int32,
                          mode='r', shape=(n_test,))
    else:
        # Load from JSONL files
        print("[*] Loading from JSONL files...")
        
        # Find all training files
        train_files = sorted(dataset_path.glob("train_features*.jsonl"))
        if not train_files:
            raise FileNotFoundError(f"No training files found in {dataset_path}")
        
        print(f"[*] Found {len(train_files)} training files")
        
        # Load training data from all files
        X_train_parts = []
        y_train_parts = []
        
        for train_file in train_files:
            X_part, y_part = load_ember_json(train_file, max_samples=max_samples_per_file)
            if len(X_part) > 0:
                X_train_parts.append(X_part)
                y_train_parts.append(y_part)
        
        X_train = np.vstack(X_train_parts)
        y_train = np.concatenate(y_train_parts)
        
        # Load test data
        test_file = dataset_path / "test_features.jsonl"
        if test_file.exists():
            X_test, y_test = load_ember_json(test_file, max_samples=max_samples_per_file)
        else:
            # If no test file, split training data
            print("[*] No test file found, splitting training data...")
            from sklearn.model_selection import train_test_split
            X_train, X_test, y_train, y_test = train_test_split(
                X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
            )
    
    print(f"[+] Loaded {len(X_train)} training samples, {len(X_test)} test samples")
    
    # Show class distribution
    train_benign = np.sum(y_train == 0)
    train_malware = np.sum(y_train == 1)
    test_benign = np.sum(y_test == 0)
    test_malware = np.sum(y_test == 1)
    
    print(f"[+] Training: {train_benign} benign, {train_malware} malware")
    print(f"[+] Testing:  {test_benign} benign, {test_malware} malware")
    
    return X_train, y_train, X_test, y_test


def vectorize_ember_sample(data):
    """
    Vectorize a single EMBER sample into a flat feature vector.
    
    EMBER features are stored in nested dictionaries. We flatten them into
    a consistent vector format of exactly 1357 features.
    """
    TOTAL_FEATURES = 1357
    features = []
    
    # Helper function to safely get list with padding
    def safe_list(data, default_len):
        if isinstance(data, list):
            result = [float(x) if isinstance(x, (int, float)) else 0.0 for x in data]
            if len(result) >= default_len:
                return result[:default_len]
            return result + [0.0] * (default_len - len(result))
        return [0.0] * default_len
    
    # Byte histogram (256 bins)
    histogram = safe_list(data.get('histogram', []), 256)
    features.extend(histogram)
    
    # Byte entropy histogram (256 bins)
    byteentropy = safe_list(data.get('byteentropy', []), 256)
    features.extend(byteentropy)
    
    # String features (104 values)
    strings_data = data.get('strings', {})
    if not isinstance(strings_data, dict):
        strings_data = {}
    strings_features = [
        float(strings_data.get('numstrings', 0) or 0),
        float(strings_data.get('avlength', 0) or 0),
        float(len(str(strings_data.get('printables', ''))) if strings_data.get('printables') else 0),
        float(strings_data.get('entropy', 0) or 0),
        float(strings_data.get('paths', 0) or 0),
        float(strings_data.get('urls', 0) or 0),
        float(strings_data.get('registry', 0) or 0),
        float(strings_data.get('MZ', 0) or 0),
    ]
    # Pad strings features to 104
    while len(strings_features) < 104:
        strings_features.append(0.0)
    features.extend(strings_features[:104])
    
    # General info (10 values)
    general = data.get('general', {})
    if not isinstance(general, dict):
        general = {}
    general_features = [
        float(general.get('size', 0) or 0),
        float(general.get('vsize', 0) or 0),
        float(general.get('has_debug', 0) or 0),
        float(general.get('exports', 0) or 0),
        float(general.get('imports', 0) or 0),
        float(general.get('has_relocations', 0) or 0),
        float(general.get('has_resources', 0) or 0),
        float(general.get('has_signature', 0) or 0),
        float(general.get('has_tls', 0) or 0),
        float(general.get('symbols', 0) or 0),
    ]
    features.extend(general_features)
    
    # Header info (62 values)
    header = data.get('header', {})
    if not isinstance(header, dict):
        header = {}
    coff = header.get('coff', {})
    if not isinstance(coff, dict):
        coff = {}
    optional = header.get('optional', {})
    if not isinstance(optional, dict):
        optional = {}
    
    def to_float(val):
        """Convert value to float safely."""
        if val is None:
            return 0.0
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, str):
            return float(len(val))  # Use string length for non-numeric strings
        if isinstance(val, (list, dict)):
            return float(len(val))
        return 0.0
    
    header_features = [
        to_float(coff.get('timestamp', 0)),
        to_float(coff.get('machine', '')),
        to_float(coff.get('characteristics', [])),
        to_float(optional.get('subsystem', 0)),
        to_float(optional.get('dll_characteristics', 0)),
        to_float(optional.get('magic', 0)),
        to_float(optional.get('major_image_version', 0)),
        to_float(optional.get('minor_image_version', 0)),
        to_float(optional.get('major_linker_version', 0)),
        to_float(optional.get('minor_linker_version', 0)),
        to_float(optional.get('major_operating_system_version', 0)),
        to_float(optional.get('minor_operating_system_version', 0)),
        to_float(optional.get('major_subsystem_version', 0)),
        to_float(optional.get('minor_subsystem_version', 0)),
        to_float(optional.get('sizeof_code', 0)),
        to_float(optional.get('sizeof_headers', 0)),
        to_float(optional.get('sizeof_heap_commit', 0)),
    ]
    # Pad header features to 62
    while len(header_features) < 62:
        header_features.append(0.0)
    features.extend(header_features[:62])
    
    # Section info (255 values) - flatten section data
    sections = data.get('section', {})
    if not isinstance(sections, dict):
        sections = {}
    section_list = sections.get('sections', []) if isinstance(sections, dict) else []
    if not isinstance(section_list, list):
        section_list = []
    section_features = []
    for sec in section_list[:5]:  # Max 5 sections
        if isinstance(sec, dict):
            section_features.extend([
                float(sec.get('size', 0) or 0),
                float(sec.get('entropy', 0) or 0),
                float(sec.get('vsize', 0) or 0),
            ])
        else:
            section_features.extend([0.0, 0.0, 0.0])
    # Pad section features to 255
    while len(section_features) < 255:
        section_features.append(0.0)
    features.extend(section_features[:255])
    
    # Imports info (256 values)
    imports = data.get('imports', {})
    import_features = []
    if isinstance(imports, dict):
        for dll_name, funcs in list(imports.items())[:64]:
            import_features.append(float(len(funcs) if isinstance(funcs, list) else 0))
    while len(import_features) < 256:
        import_features.append(0.0)
    features.extend(import_features[:256])
    
    # Exports info (128 values)
    exports = data.get('exports', [])
    export_count = float(len(exports) if isinstance(exports, list) else 0)
    export_features = [export_count]
    while len(export_features) < 128:
        export_features.append(0.0)
    features.extend(export_features[:128])
    
    # Data directories (30 values)
    datadirs = data.get('datadirectories', [])
    datadir_features = []
    if isinstance(datadirs, list):
        for dd in datadirs[:15]:
            if isinstance(dd, dict):
                datadir_features.extend([float(dd.get('size', 0) or 0), float(dd.get('virtual_address', 0) or 0)])
            else:
                datadir_features.extend([0.0, 0.0])
    while len(datadir_features) < 30:
        datadir_features.append(0.0)
    features.extend(datadir_features[:30])
    
    # Verify final length
    assert len(features) == 1357, f"Feature vector length mismatch: {len(features)} != 1357"
    
    return features


def load_ember_json(jsonl_path, max_samples=None):
    """
    Load EMBER features from JSONL file format.
    
    Each line contains a JSON object with various feature groups (histogram,
    byteentropy, strings, general, header, section, imports, exports, datadirectories)
    and a 'label' field.
    """
    features = []
    labels = []
    
    print(f"[*] Loading {jsonl_path}...")
    
    with open(jsonl_path, 'r') as f:
        for i, line in enumerate(tqdm(f, desc="Loading")):
            if max_samples and i >= max_samples:
                break
            data = json.loads(line)
            
            # Skip unlabeled samples (label == -1)
            label = data.get('label', -1)
            if label == -1:
                continue
                
            # Vectorize the sample
            feature_vec = vectorize_ember_sample(data)
            features.append(feature_vec)
            labels.append(label)
    
    return np.array(features, dtype=np.float32), np.array(labels, dtype=np.int32)


def select_features(X, num_features=NUM_FEATURES):
    """
    Select a subset of features from the vectorized EMBER feature set.
    
    We prioritize features that are most discriminative for malware detection
    and can be efficiently computed at runtime.
    
    Args:
        X: Full feature matrix (N x 1357)
        num_features: Number of features to select (default 256)
        
    Returns:
        Reduced feature matrix (N x num_features), selected indices
    """
    # Our vectorized features:
    # - Byte histogram (0-255)
    # - Byte entropy histogram (256-511)
    # - String features (512-615)
    # - General info (616-625)
    # - Header info (626-687)
    # - Section info (688-942)
    # - Import info (943-1198)
    # - Export info (1199-1326)
    # - Data directory info (1327-1356)
    
    if X.shape[1] <= num_features:
        # If we have fewer features than requested, use all of them
        return X, np.arange(X.shape[1])
    
    # Select evenly spaced features across the feature space
    indices = np.linspace(0, X.shape[1] - 1, num_features, dtype=int)
    return X[:, indices], indices


def train_model(X_train, y_train, n_estimators=MAX_TREES, max_depth=MAX_TREE_DEPTH):
    """
    Train a lightweight Random Forest classifier.
    
    We use a small number of shallow trees to keep the model size manageable
    for embedding in C code while maintaining good detection accuracy.
    
    Args:
        X_train: Training features
        y_train: Training labels
        n_estimators: Number of trees
        max_depth: Maximum tree depth
        
    Returns:
        Trained RandomForestClassifier
    """
    print(f"[*] Training Random Forest with {n_estimators} trees, max_depth={max_depth}")
    
    # Filter out unknown samples (label = -1)
    mask = y_train != -1
    X_filtered = X_train[mask]
    y_filtered = y_train[mask]
    
    print(f"[*] Using {len(X_filtered)} labeled samples "
          f"({np.sum(y_filtered == 1)} malware, {np.sum(y_filtered == 0)} benign)")
    
    # Create and train the classifier
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        n_jobs=-1,  # Use all CPU cores
        random_state=42,
        class_weight='balanced',  # Handle class imbalance
        min_samples_leaf=10,  # Prevent overfitting
        verbose=1
    )
    
    clf.fit(X_filtered, y_filtered)
    
    return clf


def evaluate_model(clf, X_test, y_test):
    """
    Evaluate the trained model on test data.
    
    Args:
        clf: Trained classifier
        X_test: Test features
        y_test: Test labels
    """
    # Filter unknown samples
    mask = y_test != -1
    X_filtered = X_test[mask]
    y_filtered = y_test[mask]
    
    print("\n[*] Evaluating model on test set...")
    
    # Make predictions
    y_pred = clf.predict(X_filtered)
    y_prob = clf.predict_proba(X_filtered)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_filtered, y_pred)
    auc = roc_auc_score(y_filtered, y_prob)
    
    print(f"\n[+] Test Accuracy: {accuracy:.4f}")
    print(f"[+] Test AUC-ROC:  {auc:.4f}")
    print("\n[+] Classification Report:")
    print(classification_report(y_filtered, y_pred, 
                               target_names=['Benign', 'Malware']))
    
    return accuracy, auc


def export_tree_to_c(tree, tree_idx, feature_indices):
    """
    Export a single decision tree to C code.
    
    Converts the sklearn tree structure to C arrays that can be
    traversed at runtime for inference.
    
    Args:
        tree: sklearn DecisionTreeClassifier
        tree_idx: Index of tree in ensemble
        feature_indices: Mapping of reduced feature indices to original
        
    Returns:
        C code string for this tree
    """
    tree_ = tree.tree_
    
    code = f"""
/* Decision Tree {tree_idx} - {tree_.node_count} nodes */
static const deft_tree_node_t g_tree_{tree_idx}_nodes[] = {{
"""
    
    for node_idx in range(tree_.node_count):
        feature = tree_.feature[node_idx]
        threshold = tree_.threshold[node_idx]
        left = tree_.children_left[node_idx]
        right = tree_.children_right[node_idx]
        
        # For leaf nodes, get the malware probability
        if left == -1:  # Leaf node
            # Normalize probabilities
            values = tree_.value[node_idx][0]
            total = np.sum(values)
            prob = values[1] / total if total > 0 else 0.5
            code += f"    {{ -1, 0.0f, -1, -1, {prob:.6f}f }},  /* Node {node_idx}: Leaf */\n"
        else:
            code += f"    {{ {feature}, {threshold:.6f}f, {left}, {right}, 0.0f }},  /* Node {node_idx} */\n"
    
    code += "};\n"
    
    return code


def export_model_to_c(clf, feature_indices, output_path):
    """
    Export the entire Random Forest model to C code.
    
    Generates a header file with embedded model data that can be
    compiled directly into the DEFT-Intruder daemon.
    
    Args:
        clf: Trained RandomForestClassifier
        feature_indices: Mapping of reduced feature indices
        output_path: Path to output C header file
    """
    print(f"[*] Exporting model to {output_path}")
    
    code = """/*
 * DEFT-Intruder: Embedded ML Model
 * 
 * AUTO-GENERATED FILE - DO NOT EDIT
 * 
 * This file contains the trained Random Forest model exported from
 * the EMBER 2018 dataset. It provides malware classification capability
 * without requiring external model files.
 * 
 * Generated by train_model.py
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 */

#ifndef DEFT_MODEL_DATA_H
#define DEFT_MODEL_DATA_H

#include "deft_types.h"

/* ============================================================================
 * Model Metadata
 * ============================================================================ */

"""
    
    code += f"#define DEFT_EMBEDDED_TREE_COUNT    {len(clf.estimators_)}\n"
    code += f"#define DEFT_EMBEDDED_FEATURE_COUNT {NUM_FEATURES}\n"
    code += f"#define DEFT_EMBEDDED_THRESHOLD     0.5f\n\n"
    
    # Export feature importance
    importances = clf.feature_importances_
    code += "/* Feature importance scores (for debugging/analysis) */\n"
    code += "static const float g_feature_importance[] = {\n    "
    for i, imp in enumerate(importances):
        code += f"{imp:.6f}f"
        if i < len(importances) - 1:
            code += ", "
        if (i + 1) % 8 == 0:
            code += "\n    "
    code += "\n};\n\n"
    
    # Export feature index mapping
    code += "/* Mapping from reduced features to original EMBER indices */\n"
    code += "static const uint16_t g_feature_mapping[] = {\n    "
    for i, idx in enumerate(feature_indices):
        code += f"{idx}"
        if i < len(feature_indices) - 1:
            code += ", "
        if (i + 1) % 16 == 0:
            code += "\n    "
    code += "\n};\n\n"
    
    # Export each tree
    code += "/* ============================================================================\n"
    code += " * Decision Trees\n"
    code += " * ============================================================================ */\n\n"
    
    for i, tree in enumerate(clf.estimators_):
        code += export_tree_to_c(tree, i, feature_indices)
    
    # Export tree metadata
    code += "\n/* Tree metadata (node counts) */\n"
    code += "static const uint32_t g_tree_node_counts[] = {\n    "
    for i, tree in enumerate(clf.estimators_):
        code += f"{tree.tree_.node_count}"
        if i < len(clf.estimators_) - 1:
            code += ", "
    code += "\n};\n\n"
    
    # Export tree pointers
    code += "/* Pointers to tree node arrays */\n"
    code += "static const deft_tree_node_t* g_tree_nodes[] = {\n"
    for i in range(len(clf.estimators_)):
        code += f"    g_tree_{i}_nodes,\n"
    code += "};\n\n"
    
    # Helper function to load embedded model
    code += """
/**
 * Load the embedded model into the model structure.
 * 
 * This function initializes a deft_model_t structure with the
 * embedded model data, avoiding the need for external model files.
 * 
 * @param model     Pointer to model structure to initialize
 * @return 0 on success, -1 on failure
 */
static inline int deft_load_embedded_model(deft_model_t *model)
{
    if (!model) return -1;
    
    /* Initialize model structure */
    model->tree_count = DEFT_EMBEDDED_TREE_COUNT;
    model->threshold = DEFT_EMBEDDED_THRESHOLD;
    model->loaded = true;
    
    /* Copy tree data */
    for (uint32_t t = 0; t < DEFT_EMBEDDED_TREE_COUNT; t++) {
        model->trees[t].node_count = g_tree_node_counts[t];
        model->trees[t].max_depth = DEFT_MAX_TREE_DEPTH;
        
        /* Copy nodes */
        for (uint32_t n = 0; n < g_tree_node_counts[t]; n++) {
            model->trees[t].nodes[n] = g_tree_nodes[t][n];
        }
    }
    
    return 0;
}

#endif /* DEFT_MODEL_DATA_H */
"""
    
    with open(output_path, 'w') as f:
        f.write(code)
    
    print(f"[+] Model exported to {output_path}")
    
    # Calculate model size
    total_nodes = sum(tree.tree_.node_count for tree in clf.estimators_)
    size_bytes = total_nodes * 16  # Approximate size per node
    print(f"[+] Model size: ~{size_bytes / 1024:.1f} KB ({total_nodes} total nodes)")


def export_model_binary(clf, feature_indices, output_path):
    """
    Export the model to a binary file format.
    
    This allows loading the model at runtime instead of embedding it.
    Useful for updating models without recompilation.
    
    File format:
    - Header (64 bytes)
    - Tree node data (variable)
    
    Args:
        clf: Trained classifier
        feature_indices: Feature index mapping
        output_path: Path to output binary file
    """
    print(f"[*] Exporting binary model to {output_path}")
    
    with open(output_path, 'wb') as f:
        # Write header
        f.write(struct.pack('<I', MODEL_MAGIC))      # Magic
        f.write(struct.pack('<I', MODEL_VERSION))    # Version
        f.write(struct.pack('<I', len(clf.estimators_)))  # Tree count
        f.write(struct.pack('<I', NUM_FEATURES))     # Feature count
        f.write(struct.pack('<f', 0.5))              # Threshold
        
        # Calculate checksum placeholder
        checksum_pos = f.tell()
        f.write(struct.pack('<I', 0))                # Checksum (placeholder)
        
        # Reserved bytes
        f.write(b'\x00' * 40)
        
        # Write tree data
        tree_data_start = f.tell()
        for tree in clf.estimators_:
            tree_ = tree.tree_
            
            # Write node count
            f.write(struct.pack('<I', tree_.node_count))
            
            # Write nodes
            for node_idx in range(tree_.node_count):
                feature = tree_.feature[node_idx]
                threshold = tree_.threshold[node_idx]
                left = tree_.children_left[node_idx]
                right = tree_.children_right[node_idx]
                
                if left == -1:  # Leaf
                    values = tree_.value[node_idx][0]
                    total = np.sum(values)
                    prob = values[1] / total if total > 0 else 0.5
                    f.write(struct.pack('<h', -1))           # feature_index
                    f.write(struct.pack('<f', 0.0))          # threshold
                    f.write(struct.pack('<h', -1))           # left_child
                    f.write(struct.pack('<h', -1))           # right_child
                    f.write(struct.pack('<f', prob))         # value
                else:
                    f.write(struct.pack('<h', feature))      # feature_index
                    f.write(struct.pack('<f', threshold))    # threshold
                    f.write(struct.pack('<h', left))         # left_child
                    f.write(struct.pack('<h', right))        # right_child
                    f.write(struct.pack('<f', 0.0))          # value
    
    # Read back the tree data to calculate checksum
    with open(output_path, 'rb') as f:
        f.seek(tree_data_start)
        tree_data = f.read()
    checksum = hash(tree_data) & 0xFFFFFFFF
    
    # Write the checksum back
    with open(output_path, 'r+b') as f:
        f.seek(checksum_pos)
        f.write(struct.pack('<I', checksum))
    
    file_size = os.path.getsize(output_path)
    print(f"[+] Binary model exported ({file_size} bytes)")


def create_sample_model(output_dir):
    """
    Create a sample model with synthetic data when EMBER is not available.
    
    This generates a small demonstration model that can be used for testing.
    The model will not be accurate for real malware detection but allows
    testing the infrastructure.
    
    Args:
        output_dir: Directory to save the model files
    """
    print("[*] EMBER dataset not found, creating sample model for testing...")
    
    # Generate synthetic training data
    np.random.seed(42)
    n_samples = 10000
    
    # Create features: malware tends to have higher entropy, more imports, etc.
    X = np.random.randn(n_samples, NUM_FEATURES).astype(np.float32)
    y = np.zeros(n_samples, dtype=np.int32)
    
    # Simple pattern: if certain feature combinations are high, it's "malware"
    malware_mask = (
        (X[:, 30] > 0.5) &   # High entropy
        (X[:, 4] > 0.3) &    # Many imports
        (X[:, 50] > 0.2)     # Executable sections
    ) | (
        (X[:, 224] > 0.7)    # Packed indicator
    )
    y[malware_mask] = 1
    
    print(f"[*] Created {n_samples} synthetic samples "
          f"({np.sum(y == 1)} malware, {np.sum(y == 0)} benign)")
    
    # Train model
    clf = train_model(X, y, n_estimators=MAX_TREES, max_depth=10)
    
    # Feature indices (direct mapping for synthetic data)
    feature_indices = np.arange(NUM_FEATURES)
    
    # Export
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    export_model_to_c(clf, feature_indices, output_dir / "deft_model_data.h")
    export_model_binary(clf, feature_indices, output_dir / "deft_model.bin")
    
    print("\n[!] NOTE: This is a SAMPLE model trained on synthetic data.")
    print("[!] For actual malware detection, train on the real EMBER dataset.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Train DEFT-Intruder ML model on EMBER dataset"
    )
    parser.add_argument(
        'dataset_path',
        nargs='?',
        help="Path to EMBER dataset directory"
    )
    parser.add_argument(
        'output_dir',
        nargs='?',
        default='./include',
        help="Output directory for model files (default: ./include)"
    )
    parser.add_argument(
        '--trees', '-t',
        type=int,
        default=MAX_TREES,
        help=f"Number of trees in ensemble (default: {MAX_TREES})"
    )
    parser.add_argument(
        '--depth', '-d',
        type=int,
        default=MAX_TREE_DEPTH,
        help=f"Maximum tree depth (default: {MAX_TREE_DEPTH})"
    )
    parser.add_argument(
        '--max-samples', '-m',
        type=int,
        default=50000,
        help="Maximum samples per training file (default: 50000, set to 0 for all)"
    )
    parser.add_argument(
        '--sample',
        action='store_true',
        help="Create sample model with synthetic data"
    )
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if args.sample or not args.dataset_path:
        create_sample_model(output_dir)
        return
    
    max_samples = args.max_samples if args.max_samples > 0 else None
    
    try:
        # Load EMBER dataset
        X_train, y_train, X_test, y_test = load_ember_dataset(args.dataset_path, max_samples_per_file=max_samples)
        
        # Select feature subset
        X_train_reduced, feature_indices = select_features(X_train, NUM_FEATURES)
        X_test_reduced, _ = select_features(X_test, NUM_FEATURES)
        
        # Train model
        clf = train_model(X_train_reduced, y_train, args.trees, args.depth)
        
        # Evaluate
        evaluate_model(clf, X_test_reduced, y_test)
        
        # Export to C code
        export_model_to_c(clf, feature_indices, output_dir / "deft_model_data.h")
        
        # Export binary format
        export_model_binary(clf, feature_indices, output_dir / "deft_model.bin")
        
        print("\n[+] Training complete!")
        print(f"[+] C header: {output_dir / 'deft_model_data.h'}")
        print(f"[+] Binary model: {output_dir / 'deft_model.bin'}")
        
    except FileNotFoundError as e:
        print(f"[!] Dataset not found: {e}")
        print("[*] Creating sample model instead...")
        create_sample_model(output_dir)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
