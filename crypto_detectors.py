#!/usr/bin/env python3
"""
Specialized Cryptographic Detection Modules
Advanced detection for specific encryption technologies and algorithms
"""

import re
import struct
import binascii
from typing import Dict, List, Tuple, Optional, Any

class PostQuantumDetector:
    """Detector for post-quantum cryptographic algorithms"""
    
    def __init__(self):
        self.pq_signatures = {
            # CRYSTALS-Dilithium signatures
            b'dilithium': 'CRYSTALS-Dilithium post-quantum signature',
            b'ML-DSA': 'Module Lattice Digital Signature Algorithm',
            b'CRYSTALS-DILITHIUM': 'CRYSTALS-Dilithium signature scheme',
            
            # CRYSTALS-Kyber KEMs
            b'kyber': 'CRYSTALS-Kyber post-quantum KEM',
            b'ML-KEM': 'Module Lattice Key Encapsulation Mechanism',
            b'CRYSTALS-KYBER': 'CRYSTALS-Kyber KEM scheme',
            
            # SPHINCS+ signatures
            b'sphincs': 'SPHINCS+ hash-based signature',
            b'SPHINCS+': 'SPHINCS+ post-quantum signature',
            
            # FALCON signatures
            b'falcon': 'FALCON post-quantum signature',
            b'FALCON': 'FALCON lattice-based signature',
            
            # Other PQ algorithms
            b'NTRU': 'NTRU lattice-based cryptography',
            b'McEliece': 'McEliece code-based cryptography',
            b'Rainbow': 'Rainbow multivariate signature',
            b'SIKE': 'Supersingular Isogeny Key Encapsulation',
        }
        
        # Parameter sets for different security levels
        self.pq_parameters = {
            b'kyber512': 'Kyber-512 (NIST Level 1)',
            b'kyber768': 'Kyber-768 (NIST Level 3)', 
            b'kyber1024': 'Kyber-1024 (NIST Level 5)',
            b'dilithium2': 'Dilithium2 (NIST Level 2)',
            b'dilithium3': 'Dilithium3 (NIST Level 3)',
            b'dilithium5': 'Dilithium5 (NIST Level 5)',
            b'falcon-512': 'FALCON-512 (NIST Level 1)',
            b'falcon-1024': 'FALCON-1024 (NIST Level 5)',
        }
    
    def detect_pq_algorithms(self, content: bytes) -> Dict[str, Any]:
        """Detect post-quantum algorithms in file content"""
        detected = {}
        
        # Search for PQ algorithm signatures
        for signature, description in self.pq_signatures.items():
            count = content.count(signature)
            if count > 0:
                detected[signature.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'post-quantum'
                }
        
        # Search for parameter sets
        for param, description in self.pq_parameters.items():
            count = content.count(param)
            if count > 0:
                detected[param.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'pq-parameter'
                }
        
        return detected

class SymmetricCryptoDetector:
    """Detector for symmetric encryption algorithms"""
    
    def __init__(self):
        self.symmetric_algorithms = {
            # AES variants
            b'AES-128': 'AES 128-bit key',
            b'AES-192': 'AES 192-bit key', 
            b'AES-256': 'AES 256-bit key',
            b'AES-GCM': 'AES Galois/Counter Mode',
            b'AES-CBC': 'AES Cipher Block Chaining',
            b'AES-CTR': 'AES Counter Mode',
            b'AES-OCB': 'AES Offset Codebook Mode',
            b'AES-GCM-SIV': 'AES-GCM Synthetic IV',
            
            # ChaCha/Salsa family
            b'ChaCha20': 'ChaCha20 stream cipher',
            b'XChaCha20': 'Extended ChaCha20',
            b'ChaCha20-Poly1305': 'ChaCha20-Poly1305 AEAD',
            b'XChaCha20-Poly1305': 'XChaCha20-Poly1305 AEAD',
            b'Salsa20': 'Salsa20 stream cipher',
            b'XSalsa20': 'Extended Salsa20',
            
            # Other symmetric algorithms
            b'Twofish': 'Twofish block cipher',
            b'Serpent': 'Serpent block cipher',
            b'Blowfish': 'Blowfish block cipher',
            b'3DES': 'Triple DES',
            b'DES': 'Data Encryption Standard',
            b'RC4': 'Rivest Cipher 4',
            b'RC6': 'Rivest Cipher 6',
            
            # Authenticated encryption
            b'Poly1305': 'Poly1305 authenticator',
            b'GMAC': 'Galois Message Authentication Code',
            b'HMAC': 'Hash-based Message Authentication Code',
            b'CMAC': 'Cipher-based Message Authentication Code',
        }
        
        # Block cipher modes
        self.cipher_modes = {
            b'ECB': 'Electronic Codebook (insecure)',
            b'CBC': 'Cipher Block Chaining',
            b'CFB': 'Cipher Feedback',
            b'OFB': 'Output Feedback', 
            b'CTR': 'Counter Mode',
            b'GCM': 'Galois/Counter Mode',
            b'OCB': 'Offset Codebook Mode',
            b'CCM': 'Counter with CBC-MAC',
            b'EAX': 'EAX authenticated encryption',
            b'SIV': 'Synthetic Initialization Vector',
        }
    
    def detect_symmetric_crypto(self, content: bytes) -> Dict[str, Any]:
        """Detect symmetric cryptographic algorithms"""
        detected = {}
        
        # Search for symmetric algorithms
        for algorithm, description in self.symmetric_algorithms.items():
            count = content.count(algorithm)
            if count > 0:
                detected[algorithm.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'symmetric'
                }
        
        # Search for cipher modes
        for mode, description in self.cipher_modes.items():
            count = content.count(mode)
            if count > 0:
                detected[mode.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'cipher-mode'
                }
        
        return detected

class HashFunctionDetector:
    """Detector for cryptographic hash functions"""
    
    def __init__(self):
        self.hash_functions = {
            # SHA family
            b'SHA-1': 'SHA-1 (deprecated)',
            b'SHA-224': 'SHA-224 hash function',
            b'SHA-256': 'SHA-256 hash function',
            b'SHA-384': 'SHA-384 hash function', 
            b'SHA-512': 'SHA-512 hash function',
            b'SHA-512/224': 'SHA-512/224 hash function',
            b'SHA-512/256': 'SHA-512/256 hash function',
            
            # SHA-3 family
            b'SHA3-224': 'SHA3-224 hash function',
            b'SHA3-256': 'SHA3-256 hash function',
            b'SHA3-384': 'SHA3-384 hash function',
            b'SHA3-512': 'SHA3-512 hash function',
            b'SHAKE128': 'SHAKE128 extendable output function',
            b'SHAKE256': 'SHAKE256 extendable output function',
            
            # BLAKE family
            b'BLAKE2b': 'BLAKE2b hash function',
            b'BLAKE2s': 'BLAKE2s hash function',
            b'BLAKE3': 'BLAKE3 hash function',
            
            # Other hash functions
            b'MD5': 'MD5 (deprecated)',
            b'MD4': 'MD4 (deprecated)',
            b'RIPEMD-160': 'RIPEMD-160 hash function',
            b'Whirlpool': 'Whirlpool hash function',
            b'Tiger': 'Tiger hash function',
            b'Skein': 'Skein hash function',
            
            # Specialized hashes
            b'bcrypt': 'bcrypt password hashing',
            b'scrypt': 'scrypt key derivation',
            b'Argon2': 'Argon2 password hashing',
            b'Argon2i': 'Argon2i (side-channel resistant)',
            b'Argon2d': 'Argon2d (GPU resistant)',
            b'Argon2id': 'Argon2id (hybrid)',
        }
        
        # Hash-based constructions
        self.hash_constructions = {
            b'HMAC': 'Hash-based Message Authentication Code',
            b'HKDF': 'HMAC-based Key Derivation Function',
            b'PBKDF2': 'Password-Based Key Derivation Function 2',
            b'MGF1': 'Mask Generation Function 1',
        }
    
    def detect_hash_functions(self, content: bytes) -> Dict[str, Any]:
        """Detect cryptographic hash functions"""
        detected = {}
        
        # Search for hash functions
        for hash_func, description in self.hash_functions.items():
            count = content.count(hash_func)
            if count > 0:
                detected[hash_func.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'hash-function'
                }
        
        # Search for hash constructions
        for construction, description in self.hash_constructions.items():
            count = content.count(construction)
            if count > 0:
                detected[construction.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'hash-construction'
                }
        
        return detected

class AsymmetricCryptoDetector:
    """Detector for asymmetric/public-key cryptography"""
    
    def __init__(self):
        self.asymmetric_algorithms = {
            # RSA variants
            b'RSA-1024': 'RSA 1024-bit (weak)',
            b'RSA-2048': 'RSA 2048-bit',
            b'RSA-3072': 'RSA 3072-bit',
            b'RSA-4096': 'RSA 4096-bit',
            b'RSA-OAEP': 'RSA Optimal Asymmetric Encryption Padding',
            b'RSA-PSS': 'RSA Probabilistic Signature Scheme',
            b'RSA-PKCS1': 'RSA PKCS#1 padding',
            
            # Elliptic Curve Cryptography
            b'ECDSA': 'Elliptic Curve Digital Signature Algorithm',
            b'ECDH': 'Elliptic Curve Diffie-Hellman',
            b'ECIES': 'Elliptic Curve Integrated Encryption Scheme',
            b'Ed25519': 'Edwards-curve Digital Signature Algorithm',
            b'Ed448': 'Edwards-curve 448-bit',
            b'X25519': 'Curve25519 key exchange',
            b'X448': 'Curve448 key exchange',
            
            # Elliptic curves
            b'P-256': 'NIST P-256 curve (secp256r1)',
            b'P-384': 'NIST P-384 curve (secp384r1)',
            b'P-521': 'NIST P-521 curve (secp521r1)',
            b'secp256k1': 'secp256k1 curve (Bitcoin)',
            b'Curve25519': 'Curve25519',
            b'Curve448': 'Curve448',
            
            # Other asymmetric algorithms
            b'DSA': 'Digital Signature Algorithm',
            b'ElGamal': 'ElGamal encryption',
            b'Diffie-Hellman': 'Diffie-Hellman key exchange',
            b'DH': 'Diffie-Hellman',
        }
        
        # Key formats and standards
        self.key_formats = {
            b'PKCS#1': 'RSA key format',
            b'PKCS#8': 'Private key format',
            b'X.509': 'Public key certificate format',
            b'SEC1': 'Elliptic curve key format',
            b'-----BEGIN RSA': 'PEM RSA key',
            b'-----BEGIN EC': 'PEM EC key',
            b'-----BEGIN PUBLIC': 'PEM public key',
            b'-----BEGIN PRIVATE': 'PEM private key',
            b'-----BEGIN CERTIFICATE': 'PEM certificate',
        }
    
    def detect_asymmetric_crypto(self, content: bytes) -> Dict[str, Any]:
        """Detect asymmetric cryptographic algorithms"""
        detected = {}
        
        # Search for asymmetric algorithms
        for algorithm, description in self.asymmetric_algorithms.items():
            count = content.count(algorithm)
            if count > 0:
                detected[algorithm.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'asymmetric'
                }
        
        # Search for key formats
        for key_format, description in self.key_formats.items():
            count = content.count(key_format)
            if count > 0:
                detected[key_format.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'key-format'
                }
        
        return detected

class ProtocolDetector:
    """Detector for cryptographic protocols and standards"""
    
    def __init__(self):
        self.protocols = {
            # TLS/SSL
            b'TLS': 'Transport Layer Security',
            b'SSL': 'Secure Sockets Layer (deprecated)',
            b'TLS 1.2': 'TLS version 1.2',
            b'TLS 1.3': 'TLS version 1.3',
            b'DTLS': 'Datagram TLS',
            
            # SSH
            b'SSH': 'Secure Shell',
            b'SSH-2': 'SSH protocol version 2',
            
            # IPSec
            b'IPSec': 'Internet Protocol Security',
            b'ESP': 'Encapsulating Security Payload',
            b'AH': 'Authentication Header',
            b'IKE': 'Internet Key Exchange',
            
            # PGP/GPG
            b'PGP': 'Pretty Good Privacy',
            b'GPG': 'GNU Privacy Guard',
            b'OpenPGP': 'OpenPGP standard',
            
            # S/MIME
            b'S/MIME': 'Secure/Multipurpose Internet Mail Extensions',
            b'PKCS#7': 'Cryptographic Message Syntax',
            b'CMS': 'Cryptographic Message Syntax',
            
            # Other protocols
            b'JOSE': 'JSON Object Signing and Encryption',
            b'JWE': 'JSON Web Encryption',
            b'JWS': 'JSON Web Signature',
            b'JWT': 'JSON Web Token',
            b'COSE': 'CBOR Object Signing and Encryption',
        }
        
        self.standards = {
            b'FIPS 140': 'Federal Information Processing Standard',
            b'Common Criteria': 'Common Criteria security evaluation',
            b'NIST': 'National Institute of Standards and Technology',
            b'RFC': 'Request for Comments standard',
            b'ISO 27001': 'Information security management',
            b'PKCS': 'Public Key Cryptography Standards',
        }
    
    def detect_protocols(self, content: bytes) -> Dict[str, Any]:
        """Detect cryptographic protocols and standards"""
        detected = {}
        
        # Search for protocols
        for protocol, description in self.protocols.items():
            count = content.count(protocol)
            if count > 0:
                detected[protocol.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'protocol'
                }
        
        # Search for standards
        for standard, description in self.standards.items():
            count = content.count(standard)
            if count > 0:
                detected[standard.decode('utf-8', errors='ignore')] = {
                    'description': description,
                    'count': count,
                    'type': 'standard'
                }
        
        return detected

class ComprehensiveCryptoDetector:
    """Comprehensive detector combining all specialized detectors"""
    
    def __init__(self):
        self.pq_detector = PostQuantumDetector()
        self.symmetric_detector = SymmetricCryptoDetector()
        self.hash_detector = HashFunctionDetector()
        self.asymmetric_detector = AsymmetricCryptoDetector()
        self.protocol_detector = ProtocolDetector()
    
    def detect_all_crypto_technologies(self, content: bytes) -> Dict[str, Any]:
        """Run all detectors and compile comprehensive results"""
        
        results = {
            'post_quantum': self.pq_detector.detect_pq_algorithms(content),
            'symmetric': self.symmetric_detector.detect_symmetric_crypto(content),
            'hash_functions': self.hash_detector.detect_hash_functions(content),
            'asymmetric': self.asymmetric_detector.detect_asymmetric_crypto(content),
            'protocols': self.protocol_detector.detect_protocols(content)
        }
        
        # Compile summary statistics
        total_technologies = sum(len(category) for category in results.values())
        
        # Create technology summary
        all_technologies = []
        for category, technologies in results.items():
            for tech_name, tech_info in technologies.items():
                all_technologies.append({
                    'name': tech_name,
                    'category': category,
                    'description': tech_info['description'],
                    'type': tech_info['type'],
                    'count': tech_info['count']
                })
        
        # Sort by count (most frequent first)
        all_technologies.sort(key=lambda x: x['count'], reverse=True)
        
        results['summary'] = {
            'total_technologies_detected': total_technologies,
            'technologies_by_frequency': all_technologies,
            'categories': {
                'post_quantum': len(results['post_quantum']),
                'symmetric': len(results['symmetric']),
                'hash_functions': len(results['hash_functions']),
                'asymmetric': len(results['asymmetric']),
                'protocols': len(results['protocols'])
            }
        }
        
        return results

def main():
    """Main function for testing the detectors"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python crypto_detectors.py <file_path>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    with open(filepath, 'rb') as f:
        content = f.read()
    
    detector = ComprehensiveCryptoDetector()
    results = detector.detect_all_crypto_technologies(content)
    
    import json
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()

