# File Format - Complete Specification with Signatures

## Overview

This document provides the complete specification for the Quantum-Safe File System (QSFS) format used by the Crypto Analyzer, including the Public Algorithm Manifest (PAM) structure, signature schemes, and binary layout. The QSFS format is designed to make cryptographic technologies "loud" and immediately visible while maintaining security and integrity.

## QSFS File Structure

### Overall File Layout

```
QSFS File Structure:
┌─────────────────────────────────────────────────────────────┐
│ File Header (64 bytes)                                      │
├─────────────────────────────────────────────────────────────┤
│ Public Algorithm Manifest (PAM) (variable length)          │
├─────────────────────────────────────────────────────────────┤
│ Signature Block (variable length)                          │
├─────────────────────────────────────────────────────────────┤
│ Encrypted Payload (variable length)                        │
├─────────────────────────────────────────────────────────────┤
│ Footer (32 bytes)                                          │
└─────────────────────────────────────────────────────────────┘
```

### File Header Specification

The QSFS file header provides essential metadata and format identification:

```c
struct QSFSHeader {
    uint8_t  magic[8];           // "QSv2\x00\x00\x00\x00"
    uint16_t version;            // Format version (big-endian)
    uint16_t flags;              // Feature flags
    uint32_t pam_offset;         // Offset to PAM section
    uint32_t pam_length;         // Length of PAM section
    uint32_t signature_offset;   // Offset to signature block
    uint32_t signature_length;   // Length of signature block
    uint32_t payload_offset;     // Offset to encrypted payload
    uint32_t payload_length;     // Length of encrypted payload
    uint32_t footer_offset;      // Offset to footer
    uint8_t  reserved[20];       // Reserved for future use
    uint32_t header_checksum;    // CRC32 of header (excluding this field)
};
```

**Field Descriptions:**

- **Magic**: 8-byte identifier "QSv2\x00\x00\x00\x00" for QSFS version 2
- **Version**: Format version number (current: 0x0002)
- **Flags**: Bitfield for format features and options
- **Offsets/Lengths**: Byte positions and sizes of major sections
- **Header Checksum**: CRC32 integrity check for header data

### Feature Flags

```c
#define QSFS_FLAG_PAM_PRESENT       0x0001  // PAM section included
#define QSFS_FLAG_SIGNATURES        0x0002  // Digital signatures present
#define QSFS_FLAG_COMPRESSION       0x0004  // Payload is compressed
#define QSFS_FLAG_ENCRYPTION        0x0008  // Payload is encrypted
#define QSFS_FLAG_ASCII_BANNER      0x0010  // ASCII banner in PAM
#define QSFS_FLAG_HYBRID_CRYPTO     0x0020  // Hybrid classical+PQ crypto
#define QSFS_FLAG_MULTI_SIGNATURE   0x0040  // Multiple signatures
#define QSFS_FLAG_CERTIFICATE_CHAIN 0x0080  // Certificate chain included
#define QSFS_FLAG_REVOCATION_INFO   0x0100  // Revocation information
#define QSFS_FLAG_TIMESTAMP         0x0200  // Trusted timestamp
```

## Public Algorithm Manifest (PAM)

### PAM Structure

The PAM section makes cryptographic technologies immediately visible:

```
PAM Section Layout:
┌─────────────────────────────────────────────────────────────┐
│ PAM Header (16 bytes)                                       │
├─────────────────────────────────────────────────────────────┤
│ ASCII Banner (optional, variable length)                   │
├─────────────────────────────────────────────────────────────┤
│ CBOR Manifest (variable length)                            │
├─────────────────────────────────────────────────────────────┤
│ Extension Data (optional, variable length)                 │
└─────────────────────────────────────────────────────────────┘
```

### PAM Header

```c
struct PAMHeader {
    uint8_t  pam_magic[4];       // "PAM\x01"
    uint16_t pam_version;        // PAM format version
    uint16_t pam_flags;          // PAM-specific flags
    uint32_t banner_length;      // Length of ASCII banner (0 if none)
    uint32_t manifest_length;    // Length of CBOR manifest
};
```

### ASCII Banner Format

The ASCII banner provides human-readable cryptographic information:

```
Example ASCII Banner:
================================================================================
QUANTUM-SAFE CRYPTOGRAPHIC STACK
================================================================================
Key Encapsulation:    ML-KEM-768 (NIST Level 3, Quantum-Safe)
Authenticated Encryption: AES-256-GCM (256-bit key, 96-bit nonce)
Digital Signature:    ML-DSA-65 (NIST Level 3, Quantum-Safe)
Hash Function:        BLAKE3 (256-bit output, parallelizable)
Key Derivation:       Argon2id (memory-hard, side-channel resistant)
================================================================================
Security Level:       High (NIST Level 3+)
Quantum Resistance:   Full post-quantum protection
Standards Compliance: NIST FIPS 203/204/205, RFC 8439
Build Information:    CryptoAnalyzer v2.1.0, 2025-09-14T12:00:00Z
================================================================================
```

### CBOR Manifest Structure

The CBOR manifest contains structured cryptographic metadata:

```cbor
{
  "version": "2.0",
  "suite_id": "QS-Hybrid-Premium-1",
  "security_level": 3,
  "quantum_safe": true,
  "algorithms": {
    "aead": {
      "algorithm": "AES-256-GCM",
      "key_size": 256,
      "nonce_size": 96,
      "tag_size": 128,
      "mode": "GCM",
      "implementation": "AES-NI optimized",
      "standards": ["NIST SP 800-38D", "RFC 5116"]
    },
    "kem": {
      "algorithm": "ML-KEM-768",
      "security_level": 3,
      "public_key_size": 1184,
      "private_key_size": 2400,
      "ciphertext_size": 1088,
      "quantum_safe": true,
      "parameters": {
        "n": 256,
        "q": 3329,
        "k": 3,
        "eta1": 2,
        "eta2": 2,
        "du": 10,
        "dv": 4
      },
      "standards": ["NIST FIPS 203"]
    },
    "signature": {
      "algorithm": "ML-DSA-65",
      "security_level": 3,
      "public_key_size": 1952,
      "private_key_size": 4032,
      "signature_size": 3309,
      "quantum_safe": true,
      "parameters": {
        "n": 256,
        "q": 8380417,
        "k": 6,
        "l": 5,
        "eta": 4,
        "tau": 49,
        "beta": 196,
        "gamma1": 524288,
        "gamma2": 261888
      },
      "standards": ["NIST FIPS 204"]
    },
    "hash": {
      "algorithm": "BLAKE3",
      "output_size": 256,
      "block_size": 64,
      "parallelizable": true,
      "tree_mode": true,
      "performance": "high",
      "standards": ["RFC 9562"]
    },
    "kdf": {
      "algorithm": "Argon2id",
      "variant": "Argon2id",
      "memory_cost": 65536,
      "time_cost": 3,
      "parallelism": 4,
      "salt_size": 16,
      "output_size": 32,
      "side_channel_resistant": true,
      "standards": ["RFC 9106"]
    }
  },
  "hybrid_schemes": {
    "kem_hybrid": {
      "classical": "X25519",
      "post_quantum": "ML-KEM-768",
      "combiner": "HKDF-SHA256"
    },
    "signature_hybrid": {
      "classical": "Ed25519",
      "post_quantum": "ML-DSA-65",
      "combiner": "concatenation"
    }
  },
  "build_info": {
    "version": "2.1.0",
    "timestamp": "2025-09-14T12:00:00Z",
    "builder": "crypto-analyzer",
    "build_hash": "abc123def456",
    "compiler": "gcc-11.2.0",
    "optimization": "-O3 -march=native"
  },
  "compliance": {
    "standards": [
      "NIST Post-Quantum Cryptography",
      "FIPS 140-2 Level 1",
      "Common Criteria EAL4+",
      "CNSA Suite 2.0"
    ],
    "certifications": [
      "NIST CAVP",
      "FIPS 140-2",
      "Common Criteria"
    ]
  },
  "metadata": {
    "description": "High-security quantum-resistant cryptographic suite",
    "use_cases": ["government", "financial", "healthcare"],
    "performance_profile": "balanced",
    "memory_requirements": "moderate",
    "implementation_notes": "Constant-time implementations with side-channel protections"
  }
}
```

## Signature Block

### Signature Block Structure

```
Signature Block Layout:
┌─────────────────────────────────────────────────────────────┐
│ Signature Block Header (16 bytes)                          │
├─────────────────────────────────────────────────────────────┤
│ Certificate Chain (optional, variable length)              │
├─────────────────────────────────────────────────────────────┤
│ Signature 1 (variable length)                              │
├─────────────────────────────────────────────────────────────┤
│ Signature 2 (optional, variable length)                    │
├─────────────────────────────────────────────────────────────┤
│ ... (additional signatures)                                │
├─────────────────────────────────────────────────────────────┤
│ Timestamp Token (optional, variable length)                │
└─────────────────────────────────────────────────────────────┘
```

### Signature Block Header

```c
struct SignatureBlockHeader {
    uint8_t  sig_magic[4];       // "SIG\x01"
    uint16_t sig_version;        // Signature format version
    uint16_t sig_count;          // Number of signatures
    uint32_t cert_chain_length;  // Length of certificate chain
    uint32_t timestamp_length;   // Length of timestamp token
};
```

### Individual Signature Format

```c
struct SignatureEntry {
    uint32_t signature_length;   // Length of this signature
    uint16_t algorithm_id;       // Signature algorithm identifier
    uint16_t hash_algorithm_id;  // Hash algorithm identifier
    uint8_t  signer_id[32];      // SHA-256 hash of signer certificate
    uint64_t timestamp;          // Unix timestamp (seconds since epoch)
    uint8_t  signature_data[];   // Variable-length signature data
};
```

### Algorithm Identifiers

```c
// Signature Algorithm IDs
#define SIG_ALG_RSA_PSS_SHA256      0x0001
#define SIG_ALG_ECDSA_P256_SHA256   0x0002
#define SIG_ALG_ED25519             0x0003
#define SIG_ALG_ML_DSA_44           0x0101
#define SIG_ALG_ML_DSA_65           0x0102
#define SIG_ALG_ML_DSA_87           0x0103
#define SIG_ALG_FALCON_512          0x0201
#define SIG_ALG_FALCON_1024         0x0202
#define SIG_ALG_SPHINCS_SHA256_128F 0x0301
#define SIG_ALG_SPHINCS_SHA256_192F 0x0302
#define SIG_ALG_SPHINCS_SHA256_256F 0x0303

// Hash Algorithm IDs
#define HASH_ALG_SHA256             0x0001
#define HASH_ALG_SHA384             0x0002
#define HASH_ALG_SHA512             0x0003
#define HASH_ALG_SHA3_256           0x0011
#define HASH_ALG_SHA3_384           0x0012
#define HASH_ALG_SHA3_512           0x0013
#define HASH_ALG_BLAKE2B            0x0021
#define HASH_ALG_BLAKE2S            0x0022
#define HASH_ALG_BLAKE3             0x0023
```

## Encrypted Payload

### Payload Structure

```
Encrypted Payload Layout:
┌─────────────────────────────────────────────────────────────┐
│ Payload Header (32 bytes)                                   │
├─────────────────────────────────────────────────────────────┤
│ Key Encapsulation Data (variable length)                   │
├─────────────────────────────────────────────────────────────┤
│ Encrypted Content (variable length)                        │
├─────────────────────────────────────────────────────────────┤
│ Authentication Tag (16 bytes)                              │
└─────────────────────────────────────────────────────────────┘
```

### Payload Header

```c
struct PayloadHeader {
    uint8_t  payload_magic[4];   // "ENC\x01"
    uint16_t encryption_alg;     // AEAD algorithm identifier
    uint16_t kem_alg;            // KEM algorithm identifier
    uint32_t kem_data_length;    // Length of encapsulated key data
    uint32_t content_length;     // Length of encrypted content
    uint8_t  nonce[12];          // AEAD nonce/IV
    uint32_t reserved;           // Reserved for future use
};
```

### Key Encapsulation Data

```c
struct KEMData {
    uint32_t recipient_count;    // Number of recipients
    struct {
        uint8_t  recipient_id[32];   // SHA-256 of recipient public key
        uint32_t ciphertext_length;  // Length of KEM ciphertext
        uint8_t  ciphertext[];       // KEM ciphertext (variable length)
    } recipients[];
};
```

## File Footer

### Footer Structure

```c
struct QSFSFooter {
    uint32_t file_length;        // Total file length
    uint32_t sections_checksum;  // CRC32 of all sections
    uint8_t  file_hash[32];      // SHA-256 hash of entire file
    uint8_t  footer_magic[8];    // "QSFSEND\x00"
};
```

## Binary Encoding Examples

### Example 1: Simple QSFS File

```hex
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII
------  -----------------------------------------------  ----------------
000000  51 53 76 32 00 00 00 00 00 02 00 81 00 00 00 40  QSv2...........@
000010  00 00 08 00 00 00 00 A0 00 00 10 00 00 00 00 B0  ................
000020  00 00 20 00 00 00 00 D0 00 00 00 00 00 00 00 00  .. .............
000030  00 00 00 00 00 00 00 00 00 00 00 00 AB CD EF 12  ................
000040  50 41 4D 01 00 01 00 10 00 00 01 00 00 00 07 C0  PAM.............
000050  3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D  ================
...     [ASCII Banner continues]
0007C0  A5 67 76 65 72 73 69 6F 6E 63 32 2E 30 68 73 75  .gversion.2.0hsu
0007D0  69 74 65 5F 69 64 71 51 53 2D 48 79 62 72 69 64  ite_idqQS-Hybrid
...     [CBOR Manifest continues]
```

### Example 2: Multi-Signature QSFS File

```hex
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII
------  -----------------------------------------------  ----------------
000000  51 53 76 32 00 00 00 00 00 02 00 C2 00 00 00 40  QSv2...........@
000010  00 00 08 00 00 00 00 A0 00 00 20 00 00 00 00 C0  .......... .....
000020  00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00  ..@.............
000030  00 00 00 00 00 00 00 00 00 00 00 00 AB CD EF 12  ................
...     [PAM Section]
0000C0  53 49 47 01 00 01 00 02 00 00 10 00 00 00 00 20  SIG............ 
0000D0  [Certificate Chain Data]
...     [Signature 1: ML-DSA-65]
...     [Signature 2: Ed25519]
```

## Validation and Integrity

### File Validation Process

1. **Header Validation**
   - Verify magic number and version
   - Check header checksum
   - Validate section offsets and lengths

2. **PAM Validation**
   - Verify PAM magic and structure
   - Parse and validate CBOR manifest
   - Check algorithm compatibility

3. **Signature Validation**
   - Verify signature block structure
   - Validate certificate chains
   - Check signature algorithms and parameters
   - Verify cryptographic signatures

4. **Payload Validation**
   - Verify payload header
   - Check encryption parameters
   - Validate KEM data structure

5. **Footer Validation**
   - Verify footer magic
   - Check file length consistency
   - Validate checksums and hashes

### Checksum Calculations

```c
// CRC32 calculation for header checksum
uint32_t calculate_header_checksum(const QSFSHeader* header) {
    return crc32(0, (const uint8_t*)header, 
                 sizeof(QSFSHeader) - sizeof(uint32_t));
}

// SHA-256 calculation for file hash
void calculate_file_hash(const uint8_t* file_data, size_t length, 
                        uint8_t hash[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, file_data, length - 32); // Exclude footer hash
    SHA256_Final(hash, &ctx);
}
```

## Implementation Guidelines

### Reading QSFS Files

```c
int read_qsfs_file(const char* filename, QSFSFile* qsfs) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) return -1;
    
    // Read and validate header
    if (fread(&qsfs->header, sizeof(QSFSHeader), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }
    
    if (memcmp(qsfs->header.magic, "QSv2\x00\x00\x00\x00", 8) != 0) {
        fclose(fp);
        return -1; // Invalid magic
    }
    
    // Validate header checksum
    uint32_t calculated_checksum = calculate_header_checksum(&qsfs->header);
    if (calculated_checksum != qsfs->header.header_checksum) {
        fclose(fp);
        return -1; // Header corruption
    }
    
    // Read PAM section
    if (qsfs->header.flags & QSFS_FLAG_PAM_PRESENT) {
        fseek(fp, qsfs->header.pam_offset, SEEK_SET);
        qsfs->pam_data = malloc(qsfs->header.pam_length);
        fread(qsfs->pam_data, qsfs->header.pam_length, 1, fp);
    }
    
    // Read signature block
    if (qsfs->header.flags & QSFS_FLAG_SIGNATURES) {
        fseek(fp, qsfs->header.signature_offset, SEEK_SET);
        qsfs->signature_data = malloc(qsfs->header.signature_length);
        fread(qsfs->signature_data, qsfs->header.signature_length, 1, fp);
    }
    
    // Read encrypted payload
    fseek(fp, qsfs->header.payload_offset, SEEK_SET);
    qsfs->payload_data = malloc(qsfs->header.payload_length);
    fread(qsfs->payload_data, qsfs->header.payload_length, 1, fp);
    
    // Read and validate footer
    fseek(fp, qsfs->header.footer_offset, SEEK_SET);
    fread(&qsfs->footer, sizeof(QSFSFooter), 1, fp);
    
    fclose(fp);
    return 0;
}
```

### Writing QSFS Files

```c
int write_qsfs_file(const char* filename, const QSFSFile* qsfs) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) return -1;
    
    // Calculate section offsets
    uint32_t current_offset = sizeof(QSFSHeader);
    
    QSFSHeader header = qsfs->header;
    header.pam_offset = current_offset;
    current_offset += header.pam_length;
    
    header.signature_offset = current_offset;
    current_offset += header.signature_length;
    
    header.payload_offset = current_offset;
    current_offset += header.payload_length;
    
    header.footer_offset = current_offset;
    
    // Calculate and set header checksum
    header.header_checksum = calculate_header_checksum(&header);
    
    // Write header
    fwrite(&header, sizeof(QSFSHeader), 1, fp);
    
    // Write sections
    if (qsfs->pam_data) {
        fwrite(qsfs->pam_data, header.pam_length, 1, fp);
    }
    
    if (qsfs->signature_data) {
        fwrite(qsfs->signature_data, header.signature_length, 1, fp);
    }
    
    fwrite(qsfs->payload_data, header.payload_length, 1, fp);
    
    // Write footer
    fwrite(&qsfs->footer, sizeof(QSFSFooter), 1, fp);
    
    fclose(fp);
    return 0;
}
```

This complete file format specification enables full implementation of QSFS readers and writers while ensuring cryptographic technologies remain "loud" and immediately visible to analysis tools.

