# DEFT-Intruder

**Real-time Heuristic Malware Detection System for Linux**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/Language-C-orange.svg)](https://en.wikipedia.org/wiki/C_(programming_language))

DEFT-Intruder is a lightweight, real-time malware detection daemon for Linux systems. It monitors all running processes and uses a combination of machine learning and heuristic rules to detect and block malicious software before it can cause harm.

## Features

- **Real-time Process Monitoring**: Continuously monitors `/proc` filesystem for new process creation
- **ML-Based Detection**: Uses a Random Forest classifier trained on the EMBER 2018 malware dataset
- **Heuristic Analysis**: Rule-based detection for common malware behaviors
- **Universal Compatibility**: Works on all Linux distributions without requiring eBPF or kernel modules
- **Low Overhead**: Minimal CPU and memory footprint
- **Configurable Actions**: Log, alert, block, or quarantine detected threats
- **Whitelist Support**: Exclude trusted applications from scanning
- **Detailed Logging**: Comprehensive logging with rotation support

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        DEFT-Intruder                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   Process   │    │   Feature   │    │   ML Classifier     │  │
│  │   Monitor   │───▶│  Extractor  │───▶│  (Random Forest)    │  │
│  │  (/proc)    │    │  (ELF/PE)   │    │                     │  │
│  └─────────────┘    └─────────────┘    └──────────┬──────────┘  │
│         │                                          │             │
│         │           ┌─────────────┐               │             │
│         └──────────▶│  Heuristic  │───────────────┤             │
│                     │   Engine    │               │             │
│                     └─────────────┘               ▼             │
│                                          ┌─────────────────┐    │
│                                          │  Decision       │    │
│                                          │  Engine         │    │
│                                          └────────┬────────┘    │
│                                                   │              │
│                     ┌─────────────────────────────┼──────────┐  │
│                     │                             ▼          │  │
│                     │  LOG  │  ALERT  │  BLOCK  │ QUARANTINE │  │
│                     └─────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Requirements

### Build Requirements

- GCC 7+ or Clang 6+
- GNU Make
- POSIX-compliant system (Linux)
- pthread library

### Runtime Requirements

- Linux kernel 2.6+ (any distribution)
- Root privileges (for process blocking)
- ~10MB disk space
- ~20MB RAM

### Optional (for ML model training)

- Python 3.6+
- NumPy
- scikit-learn
- tqdm

## Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Deftdotcx/deft-intruder.git
cd deft-intruder

# Build the project
make

# (Optional) Train the ML model with EMBER dataset
make model

# Install to system
sudo make install

# Run the daemon
sudo deft-intruder -d
```

### Building from Source

```bash
# Standard build
make

# Build with debug symbols
make debug

# Build with embedded ML model
make embedded

# Clean build artifacts
make clean
```

### Training the ML Model

The ML model can be trained on the EMBER 2018 dataset for accurate malware detection:

```bash
# Download EMBER dataset (if not already present)
# Place ember_dataset_2018_2.tar.bz2 in the project directory

# Train the model
make model

# Or use the Python script directly
python3 train_model.py ember_dataset ./include

# For testing without EMBER, generate a sample model
make sample-model
```

The training script will:
1. Load the EMBER 2018 dataset
2. Select a subset of 256 discriminative features
3. Train a Random Forest with 10 shallow trees
4. Export the model to C code for embedding
5. Generate a binary model file for runtime loading

## Usage

### Command Line Options

```
Usage: deft-intruder [OPTIONS]

Options:
  -d, --daemon         Run as a background daemon
  -f, --foreground     Run in foreground (default)
  -v, --verbose        Enable verbose logging
  -n, --dry-run        Don't block processes, just log
  -t, --threshold N    Detection threshold 0.0-1.0 (default: 0.5)
  -m, --model PATH     Path to ML model file
  -l, --log PATH       Path to log file
  -w, --whitelist PATH Path to whitelist file
  -i, --interval MS    Scan interval in milliseconds (default: 100)
  -a, --action ACTION  Default action: log, alert, block (default: block)
  -s, --scan           Scan all running processes and exit
  -h, --help           Show this help message
  -V, --version        Show version information
```

### Examples

```bash
# Run as daemon with default settings
sudo deft-intruder -d

# Run in foreground with verbose output
sudo deft-intruder -v

# Dry-run mode (don't block, just log)
sudo deft-intruder -n -v

# Use higher detection threshold
sudo deft-intruder -t 0.7

# Scan current processes only
sudo deft-intruder -s

# Alert only, don't block
sudo deft-intruder -a alert

# Use custom model and whitelist
sudo deft-intruder -m /path/to/model.bin -w /path/to/whitelist.txt
```

### Whitelist Configuration

Create a whitelist file with one path per line:

```
# /etc/deft-intruder/whitelist.txt
# System binaries (already whitelisted by default)
/usr/bin/firefox
/usr/bin/chromium
/opt/myapp/bin/myapp
# VS Code Server (for remote development)
/home/*/.vscode-server/*
# Comments start with #
```

## Detection Capabilities

### ML-Based Detection

The Random Forest model is trained on features including:

| Feature Category | Description |
|-----------------|-------------|
| File Properties | Size, sections, imports, exports |
| Entropy Analysis | Overall and per-section entropy |
| Section Analysis | Permissions, suspicious names, RWX sections |
| Import Analysis | API categories (crypto, injection, keylogging) |
| Byte Histogram | Distribution of byte values |
| Packing Indicators | UPX, ASPack, Themida signatures |

### Heuristic Rules

| Rule | Description | Weight |
|------|-------------|--------|
| high_entropy | Unusually high entropy (encryption/packing) | 0.30 |
| suspicious_path | Running from /tmp, /dev/shm, etc. | 0.40 |
| packed_binary | Binary appears packed/obfuscated | 0.35 |
| anti_debug | Anti-debugging techniques detected | 0.30 |
| rootkit_behavior | Hidden process, deleted executable | 0.50 |
| ransomware | Crypto APIs + filesystem access | 0.50 |
| crypto_mining | Stratum protocol, high CPU usage | 0.40 |
| memory_injection | Code injection patterns | 0.50 |

## System Integration

### Systemd Service

Install the systemd service for automatic startup:

```bash
sudo make install-service
sudo systemctl enable deft-intruder
sudo systemctl start deft-intruder
```

Service file location: `/etc/systemd/system/deft-intruder.service`

### Log Files

Default log location: `/var/log/deft-intruder.log`

Log format:
```
[INFO] 2025-01-15 10:30:45 DEFT-Intruder v1.0.0 Starting
[INFO] 2025-01-15 10:30:45 Loaded model from: /etc/deft-intruder/model.bin
[ALERT] 2025-01-15 10:31:22 MALWARE DETECTED: pid=12345 path=/tmp/evil score=0.89 action=BLOCKED
```

## How It Works

### 1. Process Monitoring

DEFT-Intruder periodically scans `/proc` to detect new processes. Unlike eBPF-based solutions, this approach works on all Linux kernels:

```c
// Scan /proc for PIDs
DIR *proc = opendir("/proc");
while ((entry = readdir(proc))) {
    if (is_pid(entry->d_name)) {
        analyze_process(atoi(entry->d_name));
    }
}
```

### 2. Feature Extraction

For each new process, features are extracted from its executable:

```c
// Extract features from binary
deft_features_t features;
deft_extract_file_features(exe_path, &features);

// Features include:
// - File entropy
// - Section characteristics
// - Import patterns
// - Byte histogram
```

### 3. ML Classification

The Random Forest model predicts malware probability:

```c
// Run inference
float score = deft_model_predict(&model, &features);

// Classification
if (score >= threshold) {
    // MALWARE
} else if (score >= threshold * 0.6) {
    // SUSPICIOUS
} else {
    // CLEAN
}
```

### 4. Heuristic Analysis

Additional behavioral checks are performed:

```c
// Check heuristics
deft_heuristic_result_t result;
deft_heuristics_analyze(&process, &result);

// Combine with ML score
combined_score = (ml_score * 0.7) + (heuristic_score * 0.3);
```

### 5. Action Execution

Based on the combined score, appropriate action is taken:

- **LOG**: Record the detection in the log file
- **ALERT**: Log + display alert notification
- **BLOCK**: Kill the process with SIGKILL
- **QUARANTINE**: Move executable to quarantine directory

## Performance

### Benchmarks

| Metric | Value |
|--------|-------|
| Scan latency | <1ms per process |
| Memory usage | ~20MB RSS |
| CPU usage | <1% (idle), <5% (active scan) |
| Model size | ~50KB embedded |
| Detection rate | 95%+ on EMBER test set |
| False positive rate | <1% on common Linux binaries |

### Optimization Tips

1. **Increase scan interval** for low-priority systems:
   ```bash
   deft-intruder -i 500  # 500ms interval
   ```

2. **Use whitelist** for trusted applications:
   ```bash
   deft-intruder -w /etc/deft-intruder/whitelist.txt
   ```

3. **Adjust threshold** based on your security requirements:
   ```bash
   deft-intruder -t 0.7  # Higher threshold = fewer false positives
   ```

## API Reference

### Core Functions

```c
// Feature extraction
int deft_extract_file_features(const char *path, deft_features_t *features);
float deft_calculate_entropy(const uint8_t *data, size_t size);

// ML model
int deft_model_load(deft_model_t *model, const char *path);
float deft_model_predict(const deft_model_t *model, const deft_features_t *features);

// Process monitoring
int deft_monitor_start(const deft_monitor_config_t *config);
int deft_monitor_scan_all(deft_process_callback_t callback, void *user_data);

// Heuristics
int deft_heuristics_analyze(const deft_process_t *process, deft_heuristic_result_t *result);
```

See header files in `include/` for complete API documentation.

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Build with debug symbols
make debug

# Run static analysis
make cppcheck

# Run with memory sanitizers
make valgrind

# Run tests
make test
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [EMBER Dataset](https://github.com/elastic/ember) - Endgame Malware BEnchmark for Research
- [scikit-learn](https://scikit-learn.org/) - Machine learning library for model training
- The open-source security community

## Disclaimer

DEFT-Intruder is provided for educational and security research purposes. While it aims to detect malware, no security tool can guarantee 100% protection. Always use multiple layers of security and keep your systems updated.

## Roadmap

- [ ] YARA rule integration
- [ ] Network traffic analysis
- [ ] Real-time file system monitoring (inotify)
- [ ] Web-based dashboard
- [ ] Distributed deployment support
- [ ] Integration with threat intelligence feeds

## Support

- **Issues**: [GitHub Issues](https://github.com/Deftdotcx/deft-intruder/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Deftdotcx/deft-intruder/discussions)

---

Made with ❤️ for the Linux security community
