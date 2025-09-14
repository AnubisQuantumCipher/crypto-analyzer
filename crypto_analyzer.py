#!/usr/bin/env python3
"""
Comprehensive Cryptographic File Analysis Tool
Implements Public Algorithm Manifest (PAM) detection and crypto technology identification
"""

import os
import struct
import hashlib
import math
import json
import base64
import binascii
import re
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
import cbor2

@dataclass
class AeadInfo:
    primary: str
    nonce_bits: int
    tag_bits: int
    chunk_bytes: int
    cascade: bool
    fallbacks: List[str]

@dataclass
class KemInfo:
    hybrid: bool
    pq: str
    classical: str

@dataclass
class SignatureInfo:
    pq: str
    classical: str

@dataclass
class KdfInfo:
    passphrase_mode: str
    mib: int
    t: int
    p: int

@dataclass
class BuildInfo:
    qs_version: str
    rustc: str
    crypto_crates: Dict[str, str]

@dataclass
class PubKeys:
    pq_sign_pub: str
    ed25519_pub: str

@dataclass
class ManifestSigs:
    dilithium5: str
    ed25519: str

@dataclass
class PublicManifest:
    suite: str
    created_unix: int
    aead: AeadInfo
    kem: KemInfo
    signatures: SignatureInfo
    kdf: Optional[KdfInfo]
    hkdf: str
    hash: str
    features: List[str]
    build: BuildInfo
    pubkeys: PubKeys
    signatures_over_manifest: ManifestSigs

class CryptoAnalyzer:
    def __init__(self):
        self.crypto_patterns = self._init_crypto_patterns()
        self.algorithm_signatures = self._init_algorithm_signatures()
        
    def _init_crypto_patterns(self) -> Dict[bytes, str]:
        """Initialize patterns for detecting cryptographic indicators"""
        return {
            # File format signatures
            b'QSv1\x00\x00\x00': 'Quantum-Shield container v1',
            b'QSFS': 'QuickSight File System',
            b'-----BEGIN': 'PEM format cryptographic data',
            b'-----END': 'PEM format end marker',
            
            # Encryption algorithms
            b'AES': 'Advanced Encryption Standard',
            b'ChaCha20': 'ChaCha20 stream cipher',
            b'Poly1305': 'Poly1305 authenticator',
            b'GCM': 'Galois/Counter Mode',
            b'CBC': 'Cipher Block Chaining',
            b'CTR': 'Counter mode',
            b'XChaCha20': 'Extended ChaCha20',
            
            # Post-quantum cryptography
            b'ML-KEM': 'Module Lattice Key Encapsulation Mechanism',
            b'ML-DSA': 'Module Lattice Digital Signature Algorithm',
            b'Kyber': 'Kyber post-quantum KEM',
            b'Dilithium': 'Dilithium post-quantum signature',
            b'CRYSTALS': 'CRYSTALS cryptographic suite',
            
            # Classical cryptography
            b'RSA': 'Rivest-Shamir-Adleman',
            b'ECDSA': 'Elliptic Curve Digital Signature Algorithm',
            b'Ed25519': 'Edwards-curve Digital Signature Algorithm',
            b'X25519': 'Curve25519 key exchange',
            b'P-256': 'NIST P-256 elliptic curve',
            b'P-384': 'NIST P-384 elliptic curve',
            b'P-521': 'NIST P-521 elliptic curve',
            
            # Hash functions
            b'SHA': 'Secure Hash Algorithm family',
            b'SHA-256': 'SHA-256 hash function',
            b'SHA-512': 'SHA-512 hash function',
            b'SHA3': 'SHA-3 hash function',
            b'BLAKE3': 'BLAKE3 hash function',
            b'BLAKE2': 'BLAKE2 hash function',
            b'MD5': 'Message Digest 5',
            
            # Key derivation
            b'HKDF': 'HMAC-based Key Derivation Function',
            b'PBKDF2': 'Password-Based Key Derivation Function 2',
            b'Argon2': 'Argon2 password hashing',
            b'scrypt': 'scrypt key derivation',
            
            # Certificate and signature formats
            b'X.509': 'X.509 certificate format',
            b'PKCS': 'Public Key Cryptography Standards',
            b'ASN.1': 'Abstract Syntax Notation One',
            b'recipient': 'Recipient information block',
            b'signature': 'Digital signature block',
            b'certificate': 'Digital certificate',
        }
    
    def _init_algorithm_signatures(self) -> Dict[bytes, Dict[str, Any]]:
        """Initialize binary signatures for specific algorithms"""
        return {
            # ASN.1 OIDs for various algorithms
            b'\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01': {
                'name': 'SHA-256',
                'type': 'hash',
                'description': 'SHA-256 hash algorithm OID'
            },
            b'\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02': {
                'name': 'SHA-384', 
                'type': 'hash',
                'description': 'SHA-384 hash algorithm OID'
            },
            b'\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03': {
                'name': 'SHA-512',
                'type': 'hash', 
                'description': 'SHA-512 hash algorithm OID'
            },
            b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01': {
                'name': 'RSA',
                'type': 'asymmetric',
                'description': 'RSA encryption OID'
            },
            b'\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02': {
                'name': 'ECDSA-SHA256',
                'type': 'signature',
                'description': 'ECDSA with SHA-256 OID'
            },
            b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07': {
                'name': 'P-256',
                'type': 'curve',
                'description': 'NIST P-256 curve OID'
            },
            b'\x06\x05\x2b\x81\x04\x00\x22': {
                'name': 'P-384',
                'type': 'curve', 
                'description': 'NIST P-384 curve OID'
            },
            b'\x06\x05\x2b\x81\x04\x00\x23': {
                'name': 'P-521',
                'type': 'curve',
                'description': 'NIST P-521 curve OID'
            },
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

    def detect_pam_header(self, filepath: str) -> Optional[PublicManifest]:
        """Detect and parse Public Algorithm Manifest (PAM) header"""
        try:
            with open(filepath, 'rb') as f:
                # Check for QS magic
                magic = f.read(8)
                if magic != b'QSv1\x00\x00\x00':
                    return None
                
                # Read version
                version_bytes = f.read(2)
                version = struct.unpack('>H', version_bytes)[0]
                
                # Read manifest length
                len_bytes = f.read(4)
                manifest_len = struct.unpack('>I', len_bytes)[0]
                
                # Read manifest data
                manifest_data = f.read(manifest_len)
                
                # Try to parse as CBOR
                try:
                    manifest_dict = cbor2.loads(manifest_data)
                    return self._dict_to_manifest(manifest_dict)
                except:
                    # If CBOR fails, try JSON
                    try:
                        manifest_dict = json.loads(manifest_data.decode('utf-8'))
                        return self._dict_to_manifest(manifest_dict)
                    except:
                        return None
                        
        except Exception as e:
            return None

    def _dict_to_manifest(self, data: Dict) -> PublicManifest:
        """Convert dictionary to PublicManifest object"""
        return PublicManifest(
            suite=data.get('suite', ''),
            created_unix=data.get('created_unix', 0),
            aead=AeadInfo(**data.get('aead', {})),
            kem=KemInfo(**data.get('kem', {})),
            signatures=SignatureInfo(**data.get('signatures', {})),
            kdf=KdfInfo(**data['kdf']) if data.get('kdf') else None,
            hkdf=data.get('hkdf', ''),
            hash=data.get('hash', ''),
            features=data.get('features', []),
            build=BuildInfo(**data.get('build', {})),
            pubkeys=PubKeys(**data.get('pubkeys', {})),
            signatures_over_manifest=ManifestSigs(**data.get('signatures_over_manifest', {}))
        )

    def analyze_file_structure(self, filepath: str) -> Dict[str, Any]:
        """Analyze file structure and detect encryption patterns"""
        file_size = os.path.getsize(filepath)
        
        # Calculate entropy for different sections
        chunk_size = 4096
        entropies = []
        
        with open(filepath, 'rb') as f:
            for i in range(min(10, file_size // chunk_size)):
                chunk = f.read(chunk_size)
                if chunk:
                    entropy = self.calculate_entropy(chunk)
                    entropies.append(entropy)
        
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0
        
        # Determine encryption likelihood
        encryption_likelihood = "Unknown"
        if avg_entropy > 7.5:
            encryption_likelihood = "Very High (Strong encryption detected)"
        elif avg_entropy > 6.5:
            encryption_likelihood = "High (Likely encrypted or compressed)"
        elif avg_entropy > 5.0:
            encryption_likelihood = "Medium (Possibly encoded)"
        else:
            encryption_likelihood = "Low (Likely plaintext)"
        
        return {
            'file_size': file_size,
            'chunk_entropies': entropies,
            'average_entropy': avg_entropy,
            'encryption_likelihood': encryption_likelihood
        }

    def scan_crypto_patterns(self, filepath: str) -> Dict[str, List[Dict[str, Any]]]:
        """Scan file for cryptographic patterns and algorithms"""
        found_patterns = {}
        found_signatures = {}
        
        with open(filepath, 'rb') as f:
            content = f.read()
        
        # Search for text patterns
        for pattern, description in self.crypto_patterns.items():
            positions = []
            start = 0
            while True:
                pos = content.find(pattern, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
                if len(positions) > 20:  # Limit results
                    break
            
            if positions:
                found_patterns[pattern.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'positions': positions[:10],  # Show first 10
                    'count': len(positions)
                }
        
        # Search for binary signatures
        for signature, info in self.algorithm_signatures.items():
            count = content.count(signature)
            if count > 0:
                found_signatures[info['name']] = {
                    'type': info['type'],
                    'description': info['description'],
                    'count': count,
                    'signature': binascii.hexlify(signature).decode()
                }
        
        return {
            'text_patterns': found_patterns,
            'binary_signatures': found_signatures
        }

    def detect_asn1_structures(self, filepath: str) -> List[Dict[str, Any]]:
        """Detect ASN.1 structures (certificates, signatures)"""
        asn1_structures = []
        
        with open(filepath, 'rb') as f:
            content = f.read()
        
        i = 0
        while i < len(content) - 10:
            if content[i] == 0x30:  # ASN.1 SEQUENCE tag
                try:
                    length_byte = content[i + 1]
                    if length_byte & 0x80:  # Long form length
                        length_octets = length_byte & 0x7F
                        if length_octets <= 4 and i + 1 + length_octets < len(content):
                            length = 0
                            for j in range(length_octets):
                                length = (length << 8) | content[i + 2 + j]
                            if 10 <= length <= 100000:  # Reasonable size
                                asn1_structures.append({
                                    'position': i,
                                    'length': length,
                                    'type': 'SEQUENCE (long form)',
                                    'header_hex': binascii.hexlify(content[i:i+min(20, length)]).decode()
                                })
                    else:  # Short form length
                        length = length_byte
                        if 10 <= length <= 127:
                            asn1_structures.append({
                                'position': i,
                                'length': length,
                                'type': 'SEQUENCE (short form)',
                                'header_hex': binascii.hexlify(content[i:i+min(20, length)]).decode()
                            })
                except:
                    pass
            i += 1
        
        return asn1_structures[:100]  # Limit to first 100

    def generate_crypto_report(self, filepath: str) -> Dict[str, Any]:
        """Generate comprehensive cryptographic analysis report"""
        
        # Basic file info
        file_info = {
            'filename': os.path.basename(filepath),
            'filepath': filepath,
            'size_bytes': os.path.getsize(filepath),
            'size_mb': round(os.path.getsize(filepath) / (1024 * 1024), 2)
        }
        
        # Try to detect PAM header
        pam_manifest = self.detect_pam_header(filepath)
        
        # Analyze file structure
        structure_analysis = self.analyze_file_structure(filepath)
        
        # Scan for crypto patterns
        crypto_patterns = self.scan_crypto_patterns(filepath)
        
        # Detect ASN.1 structures
        asn1_structures = self.detect_asn1_structures(filepath)
        
        # Calculate file hashes
        file_hashes = self._calculate_file_hashes(filepath)
        
        # Compile comprehensive report
        report = {
            'file_info': file_info,
            'pam_manifest': asdict(pam_manifest) if pam_manifest else None,
            'structure_analysis': structure_analysis,
            'crypto_patterns': crypto_patterns,
            'asn1_structures': {
                'count': len(asn1_structures),
                'structures': asn1_structures[:20]  # Show first 20
            },
            'file_hashes': file_hashes,
            'analysis_summary': self._generate_summary(pam_manifest, structure_analysis, crypto_patterns, asn1_structures)
        }
        
        return report

    def _calculate_file_hashes(self, filepath: str) -> Dict[str, str]:
        """Calculate various cryptographic hashes of the file"""
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                for hasher in hash_algorithms.values():
                    hasher.update(chunk)
        
        return {name: hasher.hexdigest() for name, hasher in hash_algorithms.items()}

    def _generate_summary(self, pam_manifest, structure_analysis, crypto_patterns, asn1_structures) -> Dict[str, Any]:
        """Generate analysis summary"""
        
        # Detected technologies
        technologies = []
        
        if pam_manifest:
            technologies.extend([
                f"AEAD: {pam_manifest.aead.primary}",
                f"KEM: {pam_manifest.kem.pq} + {pam_manifest.kem.classical}",
                f"Signatures: {pam_manifest.signatures.pq} + {pam_manifest.signatures.classical}",
                f"Hash: {pam_manifest.hash}",
                f"HKDF: {pam_manifest.hkdf}"
            ])
        
        # Add detected patterns
        for pattern, info in crypto_patterns['text_patterns'].items():
            technologies.append(f"{pattern}: {info['description']}")
        
        for sig_name, info in crypto_patterns['binary_signatures'].items():
            technologies.append(f"{sig_name}: {info['description']}")
        
        # Security assessment
        security_level = "Unknown"
        if structure_analysis['average_entropy'] > 7.5:
            security_level = "High (Strong encryption detected)"
        elif len(asn1_structures) > 50:
            security_level = "Medium-High (Multiple certificates/signatures)"
        elif len(crypto_patterns['text_patterns']) > 5:
            security_level = "Medium (Multiple crypto indicators)"
        else:
            security_level = "Low-Medium (Limited crypto indicators)"
        
        return {
            'detected_technologies': list(set(technologies)),  # Remove duplicates
            'technology_count': len(set(technologies)),
            'security_level': security_level,
            'has_pam_manifest': pam_manifest is not None,
            'encryption_detected': structure_analysis['average_entropy'] > 6.5,
            'certificates_detected': len(asn1_structures) > 0,
            'crypto_pattern_count': len(crypto_patterns['text_patterns']) + len(crypto_patterns['binary_signatures'])
        }

def main():
    """Main function for command-line usage"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python crypto_analyzer.py <file_path>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)
    
    analyzer = CryptoAnalyzer()
    report = analyzer.generate_crypto_report(filepath)
    
    # Pretty print the report
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()

