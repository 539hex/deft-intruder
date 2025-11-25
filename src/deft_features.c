/*
 * DEFT-Intruder: Real-time Heuristic Malware Detection System
 * 
 * Copyright (C) 2025 - Open Source Project
 * License: GPL-3.0
 * 
 * deft_features.c - Feature extraction implementation
 * 
 * This module extracts features from executable files for ML-based
 * malware classification. It supports ELF binaries (native Linux)
 * and PE files (Windows executables running under Wine).
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
#include <ctype.h>
#include <elf.h>

#include "deft_types.h"
#include "deft_features.h"
#include "deft_log.h"

/* ============================================================================
 * Private Constants and Structures
 * ============================================================================ */

/* Suspicious section names commonly used by packers and malware */
static const char *SUSPICIOUS_SECTIONS[] = {
    "UPX0", "UPX1", "UPX2", ".upx",      /* UPX packer */
    ".aspack", ".adata", ".ASPack",      /* ASPack */
    ".petite", ".pec1", ".pec2",         /* Petite */
    ".themida", ".enigma",               /* Themida/Enigma */
    ".nsp0", ".nsp1", ".nsp2",           /* NsPack */
    ".packed", ".crypted",               /* Generic */
    ".vmware", ".vbox",                  /* VM detection evasion */
    "CODE", "DATA", "BSS",               /* Old-style section names */
    ".rlpack", ".yP",                    /* RLPack, Yoda */
    ".perplex", ".pelock",               /* PELock */
    ".mpress",                           /* MPress */
    NULL
};

/* Suspicious API names that indicate malicious behavior */
static const char *SUSPICIOUS_APIS[] = {
    /* Process injection */
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtMapViewOfSection", "RtlCreateUserThread", "QueueUserAPC",
    
    /* Keylogging */
    "GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx",
    "GetKeyboardState", "keybd_event",
    
    /* Anti-debugging */
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
    
    /* Persistence */
    "RegSetValueEx", "CreateService", "StartService",
    "SetFileTime", "NtSetInformationFile",
    
    /* Network */
    "URLDownloadToFile", "InternetOpen", "WinHttpOpen",
    "socket", "connect", "send", "recv",
    
    /* Crypto (ransomware) */
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
    "BCryptEncrypt", "BCryptDecrypt",
    
    /* System manipulation */
    "ShellExecute", "WinExec", "CreateProcess",
    "system", "popen", "execve",
    
    NULL
};

/* Feature normalization parameters (min, max, scale) */
typedef struct {
    float min_val;
    float max_val;
} norm_params_t;

/* Default normalization parameters (approximate from EMBER statistics) */
static const norm_params_t g_norm_params[DEFT_FEATURE_COUNT] = {
    [FEAT_FILE_SIZE] = {0, 100000000},           /* File size up to 100MB */
    [FEAT_VIRTUAL_SIZE] = {0, 500000000},        /* Virtual size */
    [FEAT_SECTION_COUNT] = {0, 100},             /* Section count */
    [FEAT_SYMBOL_COUNT] = {0, 10000},            /* Symbol count */
    [FEAT_IMPORT_COUNT] = {0, 5000},             /* Import count */
    [FEAT_EXPORT_COUNT] = {0, 5000},             /* Export count */
    [FEAT_ENTROPY_OVERALL] = {0, 8},             /* Entropy 0-8 */
    [FEAT_ENTROPY_MAX] = {0, 8},
    [FEAT_ENTROPY_MIN] = {0, 8},
    [FEAT_ENTROPY_MEAN] = {0, 8},
    /* Default: 0-1 range for most features */
};

/* ============================================================================
 * Private Helper Functions
 * ============================================================================ */

/**
 * Calculate Shannon entropy of a data buffer.
 * 
 * Entropy measures the randomness/information density of data.
 * High entropy (>7) often indicates encryption or compression.
 * 
 * @param data  Data buffer
 * @param size  Size of data
 * @return Entropy value between 0.0 and 8.0
 */
float deft_calculate_entropy(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0.0f;
    }
    
    /* Count byte frequencies */
    uint32_t counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[data[i]]++;
    }
    
    /* Calculate entropy using Shannon's formula */
    float entropy = 0.0f;
    float size_f = (float)size;
    
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            float p = (float)counts[i] / size_f;
            entropy -= p * log2f(p);
        }
    }
    
    return entropy;
}

/**
 * Calculate byte histogram for a data buffer.
 * 
 * Creates a normalized histogram of byte frequencies.
 * 
 * @param data      Data buffer
 * @param size      Size of data
 * @param histogram Output histogram (32 bins)
 */
static void calculate_byte_histogram(const uint8_t *data, size_t size, 
                                     float *histogram)
{
    if (!data || size == 0 || !histogram) {
        return;
    }
    
    /* Initialize histogram bins */
    uint32_t bins[32] = {0};
    
    /* Count bytes into 32 bins (8 bytes per bin) */
    for (size_t i = 0; i < size; i++) {
        bins[data[i] / 8]++;
    }
    
    /* Normalize */
    float size_f = (float)size;
    for (int i = 0; i < 32; i++) {
        histogram[i] = (float)bins[i] / size_f;
    }
}

/**
 * Check if a section name is suspicious.
 * 
 * @param name  Section name (null-terminated or 8 chars max)
 * @return true if suspicious
 */
bool deft_is_suspicious_section_name(const char *name)
{
    if (!name || !name[0]) {
        return false;
    }
    
    for (int i = 0; SUSPICIOUS_SECTIONS[i] != NULL; i++) {
        if (strncasecmp(name, SUSPICIOUS_SECTIONS[i], 8) == 0) {
            return true;
        }
    }
    
    return false;
}

/**
 * Check if a string matches suspicious patterns.
 * 
 * @param str   String to check
 * @return Suspiciousness score 0.0 - 1.0
 */
float deft_check_suspicious_string(const char *str)
{
    if (!str || !str[0]) {
        return 0.0f;
    }
    
    float score = 0.0f;
    
    /* Check for suspicious API names */
    for (int i = 0; SUSPICIOUS_APIS[i] != NULL; i++) {
        if (strstr(str, SUSPICIOUS_APIS[i]) != NULL) {
            score += 0.1f;
        }
    }
    
    /* Check for URL patterns */
    if (strstr(str, "http://") || strstr(str, "https://")) {
        score += 0.05f;
    }
    
    /* Check for IP address pattern (simple regex-like) */
    int dots = 0;
    int digits = 0;
    for (const char *p = str; *p; p++) {
        if (*p == '.') dots++;
        else if (isdigit(*p)) digits++;
    }
    if (dots == 3 && digits >= 4 && digits <= 12) {
        score += 0.1f;
    }
    
    /* Check for registry key patterns (Windows) */
    if (strstr(str, "HKEY_") || strstr(str, "Software\\")) {
        score += 0.05f;
    }
    
    /* Check for file system paths */
    if (strstr(str, "/tmp/") || strstr(str, "\\Temp\\")) {
        score += 0.05f;
    }
    
    return score > 1.0f ? 1.0f : score;
}

/**
 * Normalize a feature value to [0, 1] range.
 */
float deft_normalize_feature(int feature_index, float raw_value)
{
    if (feature_index < 0 || feature_index >= DEFT_FEATURE_COUNT) {
        return 0.0f;
    }
    
    float min_val = g_norm_params[feature_index].min_val;
    float max_val = g_norm_params[feature_index].max_val;
    
    /* Default range if not specified */
    if (min_val == 0 && max_val == 0) {
        return raw_value;  /* Assume already normalized */
    }
    
    /* Normalize to [0, 1] */
    float normalized = (raw_value - min_val) / (max_val - min_val);
    
    /* Clamp to valid range */
    if (normalized < 0.0f) normalized = 0.0f;
    if (normalized > 1.0f) normalized = 1.0f;
    
    return normalized;
}

/* ============================================================================
 * ELF Binary Analysis
 * ============================================================================ */

/**
 * Extract features from ELF binary.
 * 
 * @param data      File data
 * @param size      File size
 * @param features  Output features structure
 * @return 0 on success, negative on error
 */
static int extract_elf_features(const uint8_t *data, size_t size, 
                                 deft_features_t *features)
{
    if (size < sizeof(Elf64_Ehdr)) {
        return -1;
    }
    
    /* Check ELF magic */
    if (memcmp(data, ELFMAG, SELFMAG) != 0) {
        return -1;
    }
    
    /* Determine if 32-bit or 64-bit */
    uint8_t elf_class = data[EI_CLASS];
    bool is_64bit = (elf_class == ELFCLASS64);
    
    features->bin_type = is_64bit ? DEFT_BIN_ELF64 : DEFT_BIN_ELF32;
    
    if (is_64bit) {
        const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
        
        /* Basic header features */
        features->features[FEAT_ENTRY_POINT] = 
            deft_normalize_feature(FEAT_ENTRY_POINT, (float)ehdr->e_entry);
        features->features[FEAT_MACHINE_TYPE] = 
            (float)ehdr->e_machine / 256.0f;  /* Normalize machine type */
        
        /* Count sections */
        features->section_count = ehdr->e_shnum;
        features->features[FEAT_SECTION_COUNT] = 
            deft_normalize_feature(FEAT_SECTION_COUNT, (float)ehdr->e_shnum);
        
        /* Analyze section headers */
        if (ehdr->e_shoff > 0 && ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) <= size) {
            const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(data + ehdr->e_shoff);
            
            uint32_t exec_sections = 0;
            uint32_t write_sections = 0;
            uint32_t rwx_sections = 0;
            uint32_t suspicious_names = 0;
            float entropy_sum = 0.0f;
            float entropy_max = 0.0f;
            float entropy_min = 8.0f;
            
            /* String table for section names */
            const char *strtab = NULL;
            if (ehdr->e_shstrndx < ehdr->e_shnum) {
                const Elf64_Shdr *str_shdr = &shdrs[ehdr->e_shstrndx];
                if (str_shdr->sh_offset + str_shdr->sh_size <= size) {
                    strtab = (const char *)(data + str_shdr->sh_offset);
                }
            }
            
            for (int i = 0; i < ehdr->e_shnum; i++) {
                const Elf64_Shdr *shdr = &shdrs[i];
                
                /* Count permission-based sections */
                if (shdr->sh_flags & SHF_EXECINSTR) exec_sections++;
                if (shdr->sh_flags & SHF_WRITE) write_sections++;
                if ((shdr->sh_flags & (SHF_EXECINSTR | SHF_WRITE)) == 
                    (SHF_EXECINSTR | SHF_WRITE)) {
                    rwx_sections++;  /* Writable and executable = suspicious */
                }
                
                /* Check section name if available */
                if (strtab && shdr->sh_name > 0) {
                    const char *name = strtab + shdr->sh_name;
                    if (deft_is_suspicious_section_name(name)) {
                        suspicious_names++;
                    }
                }
                
                /* Calculate section entropy */
                if (shdr->sh_size > 0 && shdr->sh_offset + shdr->sh_size <= size) {
                    float ent = deft_calculate_entropy(data + shdr->sh_offset, 
                                                       shdr->sh_size);
                    entropy_sum += ent;
                    if (ent > entropy_max) entropy_max = ent;
                    if (ent < entropy_min && ent > 0) entropy_min = ent;
                }
            }
            
            /* Store section features */
            features->features[FEAT_EXECUTABLE_SECTIONS] = 
                (float)exec_sections / 20.0f;
            features->features[FEAT_WRITABLE_SECTIONS] = 
                (float)write_sections / 20.0f;
            features->features[FEAT_RWX_SECTIONS] = 
                (float)rwx_sections / 10.0f;
            features->features[FEAT_UNUSUAL_SECTION_NAMES] = 
                (float)suspicious_names / 10.0f;
            
            /* Entropy features */
            if (ehdr->e_shnum > 0) {
                features->features[FEAT_ENTROPY_MEAN] = 
                    entropy_sum / (float)ehdr->e_shnum / 8.0f;
                features->features[FEAT_ENTROPY_MAX] = entropy_max / 8.0f;
                features->features[FEAT_ENTROPY_MIN] = entropy_min / 8.0f;
                features->features[FEAT_ENTROPY_VARIANCE] = 
                    (entropy_max - entropy_min) / 8.0f;
            }
            
            /* Flag high entropy sections (potential encryption/packing) */
            if (entropy_max > 7.5f) {
                features->flags |= DEFT_FLAG_HIGH_ENTROPY;
                features->features[FEAT_HIGH_ENTROPY_SECTIONS] = 1.0f;
            }
            
            /* Flag RWX sections (suspicious) */
            if (rwx_sections > 0) {
                features->flags |= DEFT_FLAG_PACKED;
            }
        }
        
        /* Analyze program headers for dynamic linking info */
        if (ehdr->e_phoff > 0 && ehdr->e_phnum > 0) {
            const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data + ehdr->e_phoff);
            
            /* Check for PT_DYNAMIC to find imports */
            for (int i = 0; i < ehdr->e_phnum; i++) {
                if (phdrs[i].p_type == PT_DYNAMIC) {
                    /* Found dynamic section - could parse for imports */
                    /* For now, just note that it's dynamically linked */
                    features->features[FEAT_IMPORT_COUNT] = 0.5f;  /* Placeholder */
                    break;
                }
            }
        }
        
    } else {
        /* 32-bit ELF - similar analysis */
        const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data;
        
        features->features[FEAT_ENTRY_POINT] = 
            deft_normalize_feature(FEAT_ENTRY_POINT, (float)ehdr->e_entry);
        features->features[FEAT_MACHINE_TYPE] = 
            (float)ehdr->e_machine / 256.0f;
        features->section_count = ehdr->e_shnum;
        features->features[FEAT_SECTION_COUNT] = 
            deft_normalize_feature(FEAT_SECTION_COUNT, (float)ehdr->e_shnum);
        
        /* Similar section analysis as 64-bit... */
    }
    
    return 0;
}

/* ============================================================================
 * PE Binary Analysis (for Wine/Windows binaries)
 * ============================================================================ */

/* PE header structures */
#pragma pack(push, 1)
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;
#pragma pack(pop)

/* PE section characteristics */
#define IMAGE_SCN_MEM_EXECUTE   0x20000000
#define IMAGE_SCN_MEM_READ      0x40000000
#define IMAGE_SCN_MEM_WRITE     0x80000000

/**
 * Extract features from PE binary.
 * 
 * @param data      File data
 * @param size      File size
 * @param features  Output features structure
 * @return 0 on success, negative on error
 */
static int extract_pe_features(const uint8_t *data, size_t size, 
                                deft_features_t *features)
{
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        return -1;
    }
    
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)data;
    
    /* Check MZ magic */
    if (dos->e_magic != DEFT_MZ_MAGIC) {
        return -1;
    }
    
    /* Check PE header offset */
    if (dos->e_lfanew + 24 > size) {
        return -1;
    }
    
    /* Check PE signature */
    const uint8_t *pe_ptr = data + dos->e_lfanew;
    if (*(uint32_t *)pe_ptr != DEFT_PE_MAGIC) {
        return -1;
    }
    
    const IMAGE_FILE_HEADER *file_hdr = (const IMAGE_FILE_HEADER *)(pe_ptr + 4);
    
    /* Determine PE type */
    features->bin_type = (file_hdr->Machine == 0x8664) ? DEFT_BIN_PE64 : DEFT_BIN_PE32;
    
    /* Extract header features */
    features->features[FEAT_MACHINE_TYPE] = (float)file_hdr->Machine / 65535.0f;
    features->features[FEAT_TIMESTAMP] = (float)(file_hdr->TimeDateStamp % 86400) / 86400.0f;
    features->features[FEAT_CHARACTERISTICS] = (float)file_hdr->Characteristics / 65535.0f;
    features->features[FEAT_SYMBOL_COUNT] = 
        deft_normalize_feature(FEAT_SYMBOL_COUNT, (float)file_hdr->NumberOfSymbols);
    
    /* Section analysis */
    features->section_count = file_hdr->NumberOfSections;
    features->features[FEAT_SECTION_COUNT] = 
        deft_normalize_feature(FEAT_SECTION_COUNT, (float)file_hdr->NumberOfSections);
    
    /* Find section headers */
    size_t sections_offset = dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 
                            file_hdr->SizeOfOptionalHeader;
    
    if (sections_offset + file_hdr->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > size) {
        return -1;
    }
    
    const IMAGE_SECTION_HEADER *sections = (const IMAGE_SECTION_HEADER *)(data + sections_offset);
    
    uint32_t exec_sections = 0;
    uint32_t write_sections = 0;
    uint32_t rwx_sections = 0;
    uint32_t suspicious_names = 0;
    uint32_t zero_size_sections = 0;
    float entropy_sum = 0.0f;
    float entropy_max = 0.0f;
    float entropy_min = 8.0f;
    
    for (int i = 0; i < file_hdr->NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER *section = &sections[i];
        
        /* Permission analysis */
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) exec_sections++;
        if (section->Characteristics & IMAGE_SCN_MEM_WRITE) write_sections++;
        if ((section->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) ==
            (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) {
            rwx_sections++;
        }
        
        /* Check for suspicious section names */
        if (deft_is_suspicious_section_name(section->Name)) {
            suspicious_names++;
        }
        
        /* Check for zero-size sections */
        if (section->SizeOfRawData == 0 && section->VirtualSize > 0) {
            zero_size_sections++;
        }
        
        /* Calculate section entropy */
        if (section->SizeOfRawData > 0 && 
            section->PointerToRawData + section->SizeOfRawData <= size) {
            float ent = deft_calculate_entropy(data + section->PointerToRawData,
                                               section->SizeOfRawData);
            entropy_sum += ent;
            if (ent > entropy_max) entropy_max = ent;
            if (ent < entropy_min && ent > 0) entropy_min = ent;
        }
    }
    
    /* Store section features */
    features->features[FEAT_EXECUTABLE_SECTIONS] = (float)exec_sections / 20.0f;
    features->features[FEAT_WRITABLE_SECTIONS] = (float)write_sections / 20.0f;
    features->features[FEAT_RWX_SECTIONS] = (float)rwx_sections / 10.0f;
    features->features[FEAT_UNUSUAL_SECTION_NAMES] = (float)suspicious_names / 10.0f;
    features->features[FEAT_ZERO_SIZE_SECTIONS] = (float)zero_size_sections / 10.0f;
    
    /* Entropy features */
    if (file_hdr->NumberOfSections > 0) {
        features->features[FEAT_ENTROPY_MEAN] = entropy_sum / (float)file_hdr->NumberOfSections / 8.0f;
        features->features[FEAT_ENTROPY_MAX] = entropy_max / 8.0f;
        features->features[FEAT_ENTROPY_MIN] = entropy_min / 8.0f;
        features->features[FEAT_ENTROPY_VARIANCE] = (entropy_max - entropy_min) / 8.0f;
    }
    
    /* Set flags based on analysis */
    if (entropy_max > 7.5f) {
        features->flags |= DEFT_FLAG_HIGH_ENTROPY;
        features->features[FEAT_HIGH_ENTROPY_SECTIONS] = 1.0f;
    }
    
    if (rwx_sections > 0) {
        features->flags |= DEFT_FLAG_PACKED;
    }
    
    if (suspicious_names > 0) {
        features->flags |= DEFT_FLAG_PACKED;
        features->features[FEAT_PACKED_INDICATOR] = 
            (float)suspicious_names / (float)file_hdr->NumberOfSections;
    }
    
    return 0;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/**
 * Initialize the feature extraction subsystem.
 */
int deft_features_init(void)
{
    DEFT_LOG_INFO("Feature extraction subsystem initialized");
    return 0;
}

/**
 * Cleanup feature extraction resources.
 */
void deft_features_cleanup(void)
{
    DEFT_LOG_INFO("Feature extraction subsystem cleaned up");
}

/**
 * Detect binary type from header.
 */
deft_bin_type_t deft_detect_binary_type(const uint8_t *data, size_t size)
{
    if (!data || size < 4) {
        return DEFT_BIN_UNKNOWN;
    }
    
    /* Check ELF magic */
    if (size >= SELFMAG && memcmp(data, ELFMAG, SELFMAG) == 0) {
        if (size >= EI_CLASS + 1) {
            return (data[EI_CLASS] == ELFCLASS64) ? DEFT_BIN_ELF64 : DEFT_BIN_ELF32;
        }
        return DEFT_BIN_ELF32;  /* Default to 32-bit if can't determine */
    }
    
    /* Check PE/MZ magic */
    if (size >= 2 && *(uint16_t *)data == DEFT_MZ_MAGIC) {
        /* Could be PE - need to check further for PE header */
        if (size >= 64) {
            const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)data;
            if (dos->e_lfanew + 4 <= size) {
                if (*(uint32_t *)(data + dos->e_lfanew) == DEFT_PE_MAGIC) {
                    /* Check machine type for 32/64 bit */
                    if (dos->e_lfanew + 24 <= size) {
                        const IMAGE_FILE_HEADER *fh = 
                            (const IMAGE_FILE_HEADER *)(data + dos->e_lfanew + 4);
                        return (fh->Machine == 0x8664) ? DEFT_BIN_PE64 : DEFT_BIN_PE32;
                    }
                    return DEFT_BIN_PE32;
                }
            }
        }
    }
    
    /* Check for script (shebang) */
    if (size >= 2 && data[0] == '#' && data[1] == '!') {
        return DEFT_BIN_SCRIPT;
    }
    
    return DEFT_BIN_UNKNOWN;
}

/**
 * Extract features from a file.
 */
int deft_extract_file_features(const char *path, deft_features_t *features)
{
    if (!path || !features) {
        return -1;
    }
    
    /* Initialize features structure */
    memset(features, 0, sizeof(deft_features_t));
    features->valid = false;
    
    /* Open file */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        DEFT_LOG_ERROR("Failed to open file: %s", path);
        return -1;
    }
    
    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    
    features->file_size = st.st_size;
    features->features[FEAT_FILE_SIZE] = 
        deft_normalize_feature(FEAT_FILE_SIZE, (float)st.st_size);
    
    /* Check file size limits */
    if (st.st_size < DEFT_MIN_FILE_SIZE || st.st_size > DEFT_MAX_FILE_SIZE) {
        close(fd);
        return -1;
    }
    
    /* Memory-map the file for efficient access */
    uint8_t *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (data == MAP_FAILED) {
        DEFT_LOG_ERROR("Failed to mmap file: %s", path);
        return -1;
    }
    
    /* Extract features from buffer */
    int result = deft_extract_buffer_features(data, st.st_size, features);
    
    munmap(data, st.st_size);
    
    return result;
}

/**
 * Extract features from a memory buffer.
 */
int deft_extract_buffer_features(const uint8_t *data, size_t size, 
                                  deft_features_t *features)
{
    if (!data || size < DEFT_MIN_FILE_SIZE || !features) {
        return -1;
    }
    
    /* Detect binary type */
    features->bin_type = deft_detect_binary_type(data, size);
    
    /* Calculate overall entropy */
    features->entropy = deft_calculate_entropy(data, size);
    features->features[FEAT_ENTROPY_OVERALL] = features->entropy / 8.0f;
    
    /* Calculate byte histogram */
    calculate_byte_histogram(data, size, &features->features[FEAT_BYTE_HIST_BASE]);
    
    /* Extract format-specific features */
    int result = 0;
    
    switch (features->bin_type) {
        case DEFT_BIN_ELF32:
        case DEFT_BIN_ELF64:
            result = extract_elf_features(data, size, features);
            break;
            
        case DEFT_BIN_PE32:
        case DEFT_BIN_PE64:
            result = extract_pe_features(data, size, features);
            break;
            
        case DEFT_BIN_SCRIPT:
            /* Scripts: just use entropy and byte histogram */
            features->features[FEAT_SECTION_COUNT] = 0;
            break;
            
        default:
            /* Unknown format: use basic features only */
            break;
    }
    
    /* Set packed indicator based on entropy */
    if (features->entropy > 7.0f) {
        features->features[FEAT_PACKED_INDICATOR] = 
            (features->entropy - 7.0f) / 1.0f;
        if (features->features[FEAT_PACKED_INDICATOR] > 1.0f) {
            features->features[FEAT_PACKED_INDICATOR] = 1.0f;
        }
    }
    
    features->valid = (result >= 0);
    
    return result;
}

/**
 * Print features for debugging.
 */
void deft_print_features(const deft_features_t *features, FILE *stream)
{
    if (!features || !stream) {
        return;
    }
    
    fprintf(stream, "=== Feature Extraction Results ===\n");
    fprintf(stream, "Binary Type: ");
    
    switch (features->bin_type) {
        case DEFT_BIN_ELF32:  fprintf(stream, "ELF32\n"); break;
        case DEFT_BIN_ELF64:  fprintf(stream, "ELF64\n"); break;
        case DEFT_BIN_PE32:   fprintf(stream, "PE32\n"); break;
        case DEFT_BIN_PE64:   fprintf(stream, "PE64\n"); break;
        case DEFT_BIN_SCRIPT: fprintf(stream, "Script\n"); break;
        default:              fprintf(stream, "Unknown\n"); break;
    }
    
    fprintf(stream, "File Size: %lu bytes\n", features->file_size);
    fprintf(stream, "Sections: %u\n", features->section_count);
    fprintf(stream, "Overall Entropy: %.3f\n", features->entropy);
    fprintf(stream, "Valid: %s\n", features->valid ? "Yes" : "No");
    fprintf(stream, "Flags: 0x%08X\n", features->flags);
    
    if (features->flags) {
        fprintf(stream, "  Active flags:");
        if (features->flags & DEFT_FLAG_SUSPICIOUS_PATH) fprintf(stream, " SUSPICIOUS_PATH");
        if (features->flags & DEFT_FLAG_PACKED) fprintf(stream, " PACKED");
        if (features->flags & DEFT_FLAG_HIGH_ENTROPY) fprintf(stream, " HIGH_ENTROPY");
        if (features->flags & DEFT_FLAG_ANTI_DEBUG) fprintf(stream, " ANTI_DEBUG");
        fprintf(stream, "\n");
    }
    
    /* Print key features */
    fprintf(stream, "\nKey Features:\n");
    fprintf(stream, "  File Size (norm): %.4f\n", features->features[FEAT_FILE_SIZE]);
    fprintf(stream, "  Section Count (norm): %.4f\n", features->features[FEAT_SECTION_COUNT]);
    fprintf(stream, "  Entropy Overall (norm): %.4f\n", features->features[FEAT_ENTROPY_OVERALL]);
    fprintf(stream, "  Entropy Max (norm): %.4f\n", features->features[FEAT_ENTROPY_MAX]);
    fprintf(stream, "  RWX Sections: %.4f\n", features->features[FEAT_RWX_SECTIONS]);
    fprintf(stream, "  Packed Indicator: %.4f\n", features->features[FEAT_PACKED_INDICATOR]);
}
