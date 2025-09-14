# API Reference - Library Integration Guide

## Overview

The Crypto Analyzer API provides comprehensive programmatic access to cryptographic file analysis capabilities. This reference guide covers all available endpoints, data structures, authentication methods, and integration patterns for developers building applications that need to analyze encrypted files and detect cryptographic technologies.

## Base URL and Versioning

```
Production: https://mzhyi8c1yo8j.manus.space/api
Development: http://localhost:5000/api
API Version: v1
```

All API endpoints are prefixed with `/api/crypto` and follow RESTful conventions. The API uses JSON for request and response payloads unless otherwise specified.

## Authentication

### API Key Authentication

```http
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
```

### Request Headers

```http
X-API-Version: v1
X-Client-ID: your-client-identifier
User-Agent: YourApp/1.0 (contact@yourapp.com)
```

## Core Endpoints

### File Analysis

#### POST /crypto/analyze

Analyze an encrypted file to detect cryptographic technologies.

**Request:**
```http
POST /api/crypto/analyze
Content-Type: multipart/form-data

file: [binary file data]
options: {
  "include_entropy": true,
  "include_pam": true,
  "include_certificates": true,
  "deep_analysis": false,
  "timeout": 30
}
```

**Response:**
```json
{
  "status": "success",
  "analysis_id": "uuid-string",
  "timestamp": "2025-09-14T18:00:00Z",
  "file_info": {
    "name": "encrypted_file.qs",
    "size_bytes": 1048576,
    "mime_type": "application/octet-stream",
    "sha256": "abc123...",
    "md5": "def456..."
  },
  "basic_analysis": {
    "file_format": "QSFS v2",
    "encryption_detected": true,
    "compression_detected": false,
    "structure_analysis": {
      "average_entropy": 7.892,
      "encryption_likelihood": "Very High",
      "chunk_entropies": [7.85, 7.91, 7.88, 7.90],
      "suspicious_patterns": []
    },
    "file_hashes": {
      "sha256": "abc123...",
      "sha512": "def456...",
      "blake3": "ghi789..."
    }
  },
  "detailed_crypto_detection": {
    "summary": {
      "total_technologies_detected": 15,
      "categories_found": ["aead", "kem", "signature", "hash", "kdf"],
      "security_level": "High (Post-Quantum Ready)",
      "technologies_by_frequency": [
        {
          "name": "ML-KEM-768",
          "category": "kem",
          "count": 3,
          "confidence": 0.95,
          "description": "NIST standardized post-quantum key encapsulation"
        }
      ]
    },
    "aead_algorithms": {
      "AES-256-GCM": {
        "count": 5,
        "confidence": 0.98,
        "key_size": 256,
        "nonce_size": 96,
        "tag_size": 128,
        "locations": ["offset_1024", "offset_2048"]
      },
      "ChaCha20-Poly1305": {
        "count": 2,
        "confidence": 0.92,
        "key_size": 256,
        "nonce_size": 96,
        "tag_size": 128,
        "locations": ["offset_4096"]
      }
    },
    "kem_algorithms": {
      "ML-KEM-768": {
        "count": 3,
        "confidence": 0.95,
        "security_level": 3,
        "public_key_size": 1184,
        "private_key_size": 2400,
        "ciphertext_size": 1088,
        "quantum_safe": true
      },
      "X25519": {
        "count": 1,
        "confidence": 0.88,
        "security_level": 1,
        "public_key_size": 32,
        "private_key_size": 32,
        "quantum_safe": false
      }
    },
    "signature_algorithms": {
      "ML-DSA-65": {
        "count": 2,
        "confidence": 0.94,
        "security_level": 3,
        "public_key_size": 1952,
        "private_key_size": 4032,
        "signature_size": 3309,
        "quantum_safe": true
      },
      "Ed25519": {
        "count": 1,
        "confidence": 0.90,
        "security_level": 1,
        "public_key_size": 32,
        "private_key_size": 64,
        "signature_size": 64,
        "quantum_safe": false
      }
    },
    "hash_algorithms": {
      "SHA-256": {
        "count": 8,
        "confidence": 0.99,
        "output_size": 256,
        "block_size": 512,
        "quantum_safe": false
      },
      "BLAKE3": {
        "count": 3,
        "confidence": 0.87,
        "output_size": 256,
        "parallelizable": true,
        "quantum_safe": false
      }
    },
    "kdf_algorithms": {
      "HKDF-SHA256": {
        "count": 4,
        "confidence": 0.91,
        "hash_function": "SHA-256",
        "extract_expand": true
      },
      "Argon2id": {
        "count": 1,
        "confidence": 0.85,
        "memory_cost": 65536,
        "time_cost": 3,
        "parallelism": 4
      }
    }
  },
  "pam_analysis": {
    "pam_detected": true,
    "pam_version": "1.0",
    "manifest_size": 2048,
    "ascii_banner": "CRYPTO STACK: ML-KEM-768 + AES-256-GCM + ML-DSA-65",
    "manifest_content": {
      "suite_id": "QS-Hybrid-1",
      "algorithms": {
        "aead": {
          "algorithm": "AES-256-GCM",
          "key_size": 256,
          "nonce_size": 96,
          "tag_size": 128
        },
        "kem": {
          "algorithm": "ML-KEM-768",
          "security_level": 3,
          "quantum_safe": true
        },
        "signature": {
          "algorithm": "ML-DSA-65",
          "security_level": 3,
          "quantum_safe": true
        },
        "kdf": {
          "algorithm": "HKDF-SHA256",
          "hash_function": "SHA-256"
        }
      },
      "build_info": {
        "version": "1.2.3",
        "timestamp": "2025-09-14T12:00:00Z",
        "builder": "crypto-analyzer-v2.1"
      }
    },
    "signatures": [
      {
        "signer_id": "crypto_analyzer_ca",
        "algorithm": "ML-DSA-65",
        "signature_valid": true,
        "trust_level": "trusted",
        "timestamp": "2025-09-14T12:00:00Z"
      }
    ]
  },
  "certificate_analysis": {
    "certificates_found": 2,
    "certificate_details": [
      {
        "subject": "CN=CryptoAnalyzer CA,O=Manus,C=US",
        "issuer": "CN=Root CA,O=Manus,C=US",
        "serial_number": "123456789",
        "validity": {
          "not_before": "2024-01-01T00:00:00Z",
          "not_after": "2026-01-01T00:00:00Z"
        },
        "signature_algorithm": "ML-DSA-65",
        "public_key_algorithm": "ML-DSA-65",
        "key_usage": ["digitalSignature", "keyCertSign"],
        "revocation_status": "valid"
      }
    ]
  },
  "security_assessment": {
    "overall_security_level": "High",
    "quantum_readiness": "Fully Quantum-Safe",
    "compliance": ["NIST Post-Quantum", "FIPS 140-2 Level 1"],
    "recommendations": [
      "Consider hybrid classical+PQ signatures for transition period",
      "Verify certificate chain to trusted root"
    ],
    "warnings": [],
    "vulnerabilities": []
  }
}
```

**Error Response:**
```json
{
  "status": "error",
  "error_code": "ANALYSIS_FAILED",
  "message": "File analysis failed: unsupported format",
  "details": {
    "file_size": 1048576,
    "detected_format": "unknown",
    "supported_formats": ["QSFS", "PGP", "PKCS#7", "X.509"]
  }
}
```

#### GET /crypto/analyze/{analysis_id}

Retrieve previous analysis results.

**Response:**
```json
{
  "status": "success",
  "analysis_id": "uuid-string",
  "created_at": "2025-09-14T18:00:00Z",
  "file_info": { /* same as analyze response */ },
  "results": { /* complete analysis results */ }
}
```

### PAM Generation

#### POST /crypto/generate-pam

Generate a Public Algorithm Manifest file with specified cryptographic technologies.

**Request:**
```json
{
  "type": "comprehensive",
  "suite_id": "Custom-Suite-1",
  "algorithms": {
    "aead": {
      "algorithm": "AES-256-GCM",
      "key_size": 256,
      "nonce_size": 96,
      "tag_size": 128
    },
    "kem": {
      "algorithm": "ML-KEM-1024",
      "security_level": 5,
      "quantum_safe": true
    },
    "signature": {
      "algorithm": "ML-DSA-87",
      "security_level": 5,
      "quantum_safe": true
    },
    "hash": {
      "algorithm": "BLAKE3",
      "output_size": 256
    },
    "kdf": {
      "algorithm": "Argon2id",
      "memory_cost": 65536,
      "time_cost": 3,
      "parallelism": 4
    }
  },
  "include_banner": true,
  "banner_text": "QUANTUM-SAFE CRYPTO STACK",
  "metadata": {
    "version": "2.0.0",
    "description": "High-security quantum-resistant configuration",
    "compliance": ["NIST PQC", "CNSA 2.0"]
  }
}
```

**Response:**
```json
{
  "status": "success",
  "pam_id": "uuid-string",
  "file_size": 4096,
  "download_url": "/api/crypto/download-pam/uuid-string",
  "manifest_preview": {
    "suite_id": "Custom-Suite-1",
    "total_algorithms": 5,
    "security_level": "Maximum (Level 5)",
    "quantum_safe": true,
    "banner_included": true
  },
  "analysis_result": {
    /* Full analysis of the generated PAM file */
  }
}
```

#### GET /crypto/download-pam/{pam_id}

Download generated PAM file.

**Response:** Binary file download with appropriate headers.

### Health and Status

#### GET /crypto/health

Check API health and capabilities.

**Response:**
```json
{
  "status": "healthy",
  "version": "2.1.0",
  "uptime": 86400,
  "capabilities": {
    "supported_formats": ["QSFS", "PGP", "PKCS#7", "X.509", "CMS"],
    "max_file_size": 104857600,
    "analysis_timeout": 30,
    "supported_algorithms": {
      "aead": ["AES-256-GCM", "ChaCha20-Poly1305", "XChaCha20-Poly1305"],
      "kem": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519", "P-256"],
      "signature": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Ed25519", "ECDSA"],
      "hash": ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "BLAKE3"],
      "kdf": ["HKDF", "PBKDF2", "Argon2", "scrypt"]
    }
  },
  "statistics": {
    "total_analyses": 15420,
    "analyses_today": 342,
    "average_analysis_time": 2.3,
    "success_rate": 0.987
  }
}
```

## Data Structures

### CryptoAlgorithm

```typescript
interface CryptoAlgorithm {
  name: string;
  category: 'aead' | 'kem' | 'signature' | 'hash' | 'kdf';
  count: number;
  confidence: number; // 0.0 to 1.0
  security_level: number; // 1-5 (NIST levels)
  quantum_safe: boolean;
  key_sizes?: number[];
  parameters?: Record<string, any>;
  locations?: string[]; // File offsets where detected
  standards?: string[]; // Relevant standards (NIST, RFC, etc.)
}
```

### PAMManifest

```typescript
interface PAMManifest {
  version: string;
  suite_id: string;
  algorithms: {
    aead?: AEADInfo;
    kem?: KEMInfo;
    signature?: SignatureInfo;
    hash?: HashInfo;
    kdf?: KDFInfo;
  };
  build_info: BuildInfo;
  metadata?: Record<string, any>;
}

interface AEADInfo {
  algorithm: string;
  key_size: number;
  nonce_size: number;
  tag_size: number;
  mode?: string;
}

interface KEMInfo {
  algorithm: string;
  security_level: number;
  public_key_size: number;
  private_key_size: number;
  ciphertext_size: number;
  quantum_safe: boolean;
}

interface SignatureInfo {
  algorithm: string;
  security_level: number;
  public_key_size: number;
  private_key_size: number;
  signature_size: number;
  quantum_safe: boolean;
}
```

### AnalysisOptions

```typescript
interface AnalysisOptions {
  include_entropy?: boolean; // Default: true
  include_pam?: boolean; // Default: true
  include_certificates?: boolean; // Default: true
  deep_analysis?: boolean; // Default: false
  timeout?: number; // Seconds, default: 30
  output_format?: 'json' | 'xml' | 'yaml'; // Default: json
  confidence_threshold?: number; // 0.0-1.0, default: 0.7
}
```

## SDK Libraries

### Python SDK

```python
from crypto_analyzer_sdk import CryptoAnalyzer, AnalysisOptions

# Initialize client
client = CryptoAnalyzer(
    api_key="your-api-key",
    base_url="https://mzhyi8c1yo8j.manus.space/api"
)

# Analyze file
with open("encrypted_file.qs", "rb") as f:
    result = client.analyze_file(
        file_data=f.read(),
        options=AnalysisOptions(
            include_entropy=True,
            deep_analysis=True,
            timeout=60
        )
    )

print(f"Detected {result.total_technologies} cryptographic technologies")
for algo in result.algorithms:
    print(f"- {algo.name} (confidence: {algo.confidence:.2f})")

# Generate PAM
pam_config = {
    "type": "comprehensive",
    "algorithms": {
        "aead": {"algorithm": "AES-256-GCM"},
        "kem": {"algorithm": "ML-KEM-768"},
        "signature": {"algorithm": "ML-DSA-65"}
    }
}

pam_result = client.generate_pam(pam_config)
with open("generated.qs", "wb") as f:
    f.write(pam_result.file_data)
```

### JavaScript SDK

```javascript
import { CryptoAnalyzer } from 'crypto-analyzer-sdk';

const client = new CryptoAnalyzer({
  apiKey: 'your-api-key',
  baseUrl: 'https://mzhyi8c1yo8j.manus.space/api'
});

// Analyze file
const fileInput = document.getElementById('file-input');
const file = fileInput.files[0];

try {
  const result = await client.analyzeFile(file, {
    includeEntropy: true,
    deepAnalysis: false,
    timeout: 30
  });
  
  console.log(`Security Level: ${result.securityAssessment.overallSecurityLevel}`);
  console.log(`Quantum Safe: ${result.securityAssessment.quantumReadiness}`);
  
  // Display results
  result.detectedAlgorithms.forEach(algo => {
    console.log(`${algo.name}: ${algo.confidence * 100}% confidence`);
  });
  
} catch (error) {
  console.error('Analysis failed:', error.message);
}

// Generate PAM
const pamConfig = {
  type: 'comprehensive',
  algorithms: {
    aead: { algorithm: 'ChaCha20-Poly1305' },
    kem: { algorithm: 'ML-KEM-1024' },
    signature: { algorithm: 'ML-DSA-87' }
  },
  includeBanner: true
};

const pamResult = await client.generatePAM(pamConfig);
console.log(`Generated PAM file: ${pamResult.fileSize} bytes`);
```

### Go SDK

```go
package main

import (
    "fmt"
    "os"
    "github.com/crypto-analyzer/go-sdk"
)

func main() {
    client := cryptoanalyzer.NewClient(&cryptoanalyzer.Config{
        APIKey:  "your-api-key",
        BaseURL: "https://mzhyi8c1yo8j.manus.space/api",
    })
    
    // Read file
    fileData, err := os.ReadFile("encrypted_file.qs")
    if err != nil {
        panic(err)
    }
    
    // Analyze file
    result, err := client.AnalyzeFile(fileData, &cryptoanalyzer.AnalysisOptions{
        IncludeEntropy:      true,
        IncludePAM:         true,
        IncludeCertificates: true,
        Timeout:            30,
    })
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Detected %d technologies\n", result.Summary.TotalTechnologies)
    for _, algo := range result.Algorithms {
        fmt.Printf("- %s: %.2f confidence\n", algo.Name, algo.Confidence)
    }
    
    // Check quantum safety
    if result.SecurityAssessment.QuantumReadiness == "Fully Quantum-Safe" {
        fmt.Println("✓ File uses quantum-safe cryptography")
    }
}
```

## Rate Limiting

The API implements rate limiting to ensure fair usage:

```
Rate Limits:
- Free Tier: 100 requests/hour, 10 MB/request
- Pro Tier: 1000 requests/hour, 100 MB/request
- Enterprise: Custom limits

Headers:
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1694721600
```

## Error Handling

### Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_FILE_FORMAT` | Unsupported file format | 400 |
| `FILE_TOO_LARGE` | File exceeds size limit | 413 |
| `ANALYSIS_TIMEOUT` | Analysis exceeded timeout | 408 |
| `INVALID_API_KEY` | Authentication failed | 401 |
| `RATE_LIMIT_EXCEEDED` | Too many requests | 429 |
| `INTERNAL_ERROR` | Server error | 500 |

### Error Response Format

```json
{
  "status": "error",
  "error_code": "INVALID_FILE_FORMAT",
  "message": "Unsupported file format detected",
  "details": {
    "detected_format": "unknown",
    "supported_formats": ["QSFS", "PGP", "PKCS#7"],
    "file_size": 1048576,
    "mime_type": "application/octet-stream"
  },
  "timestamp": "2025-09-14T18:00:00Z",
  "request_id": "req_123456789"
}
```

## Webhooks

### Webhook Configuration

```json
{
  "webhook_url": "https://your-app.com/webhooks/crypto-analyzer",
  "events": ["analysis.completed", "analysis.failed", "pam.generated"],
  "secret": "webhook-secret-key",
  "retry_policy": {
    "max_retries": 3,
    "retry_delay": 5
  }
}
```

### Webhook Payload

```json
{
  "event": "analysis.completed",
  "timestamp": "2025-09-14T18:00:00Z",
  "analysis_id": "uuid-string",
  "data": {
    /* Complete analysis results */
  },
  "signature": "sha256=abc123..." // HMAC signature for verification
}
```

## Best Practices

### Performance Optimization

1. **File Size Limits**: Keep files under 100MB for optimal performance
2. **Batch Processing**: Use batch endpoints for multiple files
3. **Caching**: Cache analysis results for identical files
4. **Compression**: Compress large files before upload

### Security Considerations

1. **API Key Security**: Store API keys securely, rotate regularly
2. **HTTPS Only**: Always use HTTPS for API communications
3. **Input Validation**: Validate all file inputs before analysis
4. **Rate Limiting**: Implement client-side rate limiting

### Integration Patterns

```python
# Async processing pattern
import asyncio
from crypto_analyzer_sdk import AsyncCryptoAnalyzer

async def analyze_multiple_files(file_paths):
    client = AsyncCryptoAnalyzer(api_key="your-key")
    
    tasks = []
    for path in file_paths:
        with open(path, 'rb') as f:
            task = client.analyze_file_async(f.read())
            tasks.append(task)
    
    results = await asyncio.gather(*tasks)
    return results

# Streaming analysis for large files
def analyze_large_file_streaming(file_path):
    client = CryptoAnalyzer(api_key="your-key")
    
    with open(file_path, 'rb') as f:
        # Process file in chunks
        for chunk_result in client.analyze_file_streaming(f):
            yield chunk_result
```

This comprehensive API reference provides complete integration guidance for developers building applications with the Crypto Analyzer's cryptographic detection capabilities.

