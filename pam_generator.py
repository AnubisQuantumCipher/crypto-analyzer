#!/usr/bin/env python3
"""
Public Algorithm Manifest (PAM) Generator
Creates "loud" cryptographic files that display all their encryption technologies
"""

import os
import json
import struct
import time
import cbor2
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from crypto_analyzer import PublicManifest, AeadInfo, KemInfo, SignatureInfo, KdfInfo, BuildInfo, PubKeys, ManifestSigs

class PAMGenerator:
    def __init__(self):
        self.default_suite = "QS-Default-1"
        
    def create_default_manifest(self) -> PublicManifest:
        """Create a default PAM manifest with comprehensive crypto technologies"""
        return PublicManifest(
            suite=self.default_suite,
            created_unix=int(time.time()),
            aead=AeadInfo(
                primary="AES-256-GCM",
                nonce_bits=96,
                tag_bits=128,
                chunk_bytes=1048576,  # 1 MiB
                cascade=False,
                fallbacks=["XChaCha20-Poly1305", "AES-256-GCM-SIV"]
            ),
            kem=KemInfo(
                hybrid=True,
                pq="ML-KEM-1024",
                classical="X25519"
            ),
            signatures=SignatureInfo(
                pq="ML-DSA-87",
                classical="Ed25519"
            ),
            kdf=KdfInfo(
                passphrase_mode="Argon2id",
                mib=4096 * 1024,  # 4 GiB
                t=64,
                p=1
            ),
            hkdf="HKDF-SHA3-512",
            hash="BLAKE3-256",
            features=[
                "forward-secrecy-per-file",
                "aad-bound-chunks", 
                "zeroization",
                "constant-time-compare",
                "hidden-volume-support",
                "hsm-pkcs11-optional"
            ],
            build=BuildInfo(
                qs_version="1.0.0",
                rustc="1.79.0",
                crypto_crates={
                    "aes-gcm": "0.10.x",
                    "chacha20poly1305": "0.10.x",
                    "pqcrypto-kyber": "0.8.x",
                    "pqcrypto-dilithium": "0.8.x",
                    "x25519-dalek": "2.x",
                    "ed25519-dalek": "2.x",
                    "blake3": "1.x"
                }
            ),
            pubkeys=PubKeys(
                pq_sign_pub="<base64-dilithium-pk-placeholder>",
                ed25519_pub="<base64-ed25519-pk-placeholder>"
            ),
            signatures_over_manifest=ManifestSigs(
                dilithium5="<base64-dilithium-sig-placeholder>",
                ed25519="<base64-ed25519-sig-placeholder>"
            )
        )
    
    def generate_ascii_banner(self, manifest: PublicManifest) -> str:
        """Generate ASCII banner for human-readable display"""
        banner = f"""
----- Quantum-Shield (QS) Public Algorithm Manifest -----
Suite: {manifest.suite}
AEAD: {manifest.aead.primary} ({manifest.aead.nonce_bits}-bit nonce, {manifest.aead.tag_bits}-bit tag), chunk={manifest.aead.chunk_bytes//1024//1024}MiB
Fallbacks: {', '.join(manifest.aead.fallbacks)}
KEM: {manifest.kem.pq} + {manifest.kem.classical} (hybrid)
Signatures: {manifest.signatures.pq} (Dilithium5) + {manifest.signatures.classical}
KDF (passphrase): {manifest.kdf.passphrase_mode if manifest.kdf else 'None'} m={manifest.kdf.mib//1024//1024 if manifest.kdf else 0}GiB t={manifest.kdf.t if manifest.kdf else 0} p={manifest.kdf.p if manifest.kdf else 0}
HKDF: {manifest.hkdf}
Hash: {manifest.hash}
Features: {', '.join(manifest.features)}
Build: QS {manifest.build.qs_version} / rustc {manifest.build.rustc}
--------------------------------------------------------

"""
        return banner.strip()
    
    def write_pam_header(self, output_file: str, manifest: PublicManifest, include_banner: bool = True) -> None:
        """Write PAM header to file"""
        with open(output_file, 'wb') as f:
            # Write magic and version
            f.write(b'QSv1\x00\x00\x00')  # 8 bytes magic
            f.write(struct.pack('>H', 1))   # 2 bytes version
            
            # Prepare manifest data
            manifest_dict = asdict(manifest)
            
            # Create combined data (banner + CBOR)
            combined_data = b''
            
            if include_banner:
                banner = self.generate_ascii_banner(manifest)
                banner_bytes = banner.encode('utf-8') + b'\n\n'
                combined_data += banner_bytes
            
            # Add CBOR data
            cbor_data = cbor2.dumps(manifest_dict)
            combined_data += cbor_data
            
            # Write length and data
            f.write(struct.pack('>I', len(combined_data)))  # 4 bytes length
            f.write(combined_data)
    
    def create_sample_encrypted_file(self, output_file: str, content: bytes = None, include_banner: bool = True) -> None:
        """Create a sample encrypted file with PAM header"""
        if content is None:
            content = b"This is sample encrypted content. " * 1000  # Create some dummy content
        
        manifest = self.create_default_manifest()
        
        # Write PAM header
        self.write_pam_header(output_file, manifest, include_banner)
        
        # Simulate encrypted content (just random-looking data for demo)
        import secrets
        encrypted_content = secrets.token_bytes(len(content))
        
        with open(output_file, 'ab') as f:
            f.write(encrypted_content)
    
    def create_comprehensive_test_file(self, output_file: str) -> None:
        """Create a comprehensive test file showcasing all crypto technologies"""
        
        # Enhanced manifest with more technologies
        manifest = PublicManifest(
            suite="QS-Comprehensive-Test-1",
            created_unix=int(time.time()),
            aead=AeadInfo(
                primary="AES-256-GCM",
                nonce_bits=96,
                tag_bits=128,
                chunk_bytes=1048576,
                cascade=True,  # Enable cascade mode
                fallbacks=[
                    "XChaCha20-Poly1305",
                    "AES-256-GCM-SIV", 
                    "ChaCha20-Poly1305",
                    "AES-256-OCB",
                    "AES-256-CTR-HMAC-SHA256"
                ]
            ),
            kem=KemInfo(
                hybrid=True,
                pq="ML-KEM-1024",
                classical="X25519"
            ),
            signatures=SignatureInfo(
                pq="ML-DSA-87",
                classical="Ed25519"
            ),
            kdf=KdfInfo(
                passphrase_mode="Argon2id",
                mib=8192 * 1024,  # 8 GiB
                t=128,
                p=4
            ),
            hkdf="HKDF-SHA3-512",
            hash="BLAKE3-256",
            features=[
                "forward-secrecy-per-file",
                "forward-secrecy-per-chunk",
                "aad-bound-chunks",
                "zeroization",
                "constant-time-compare",
                "hidden-volume-support",
                "hsm-pkcs11-optional",
                "quantum-resistant",
                "post-quantum-signatures",
                "hybrid-encryption",
                "multi-layer-encryption",
                "steganographic-headers",
                "deniable-encryption",
                "perfect-forward-secrecy",
                "authenticated-encryption",
                "compression-resistant",
                "timing-attack-resistant",
                "side-channel-resistant"
            ],
            build=BuildInfo(
                qs_version="2.0.0-comprehensive",
                rustc="1.79.0",
                crypto_crates={
                    "aes-gcm": "0.10.x",
                    "aes-gcm-siv": "0.11.x", 
                    "chacha20poly1305": "0.10.x",
                    "xchacha20poly1305": "0.10.x",
                    "pqcrypto-kyber": "0.8.x",
                    "pqcrypto-dilithium": "0.8.x",
                    "pqcrypto-sphincs": "0.8.x",
                    "x25519-dalek": "2.x",
                    "ed25519-dalek": "2.x",
                    "p256": "0.13.x",
                    "p384": "0.13.x",
                    "blake3": "1.x",
                    "sha3": "0.10.x",
                    "argon2": "0.5.x",
                    "hkdf": "0.12.x",
                    "ring": "0.17.x",
                    "rustls": "0.21.x"
                }
            ),
            pubkeys=PubKeys(
                pq_sign_pub="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
                ed25519_pub="MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE="
            ),
            signatures_over_manifest=ManifestSigs(
                dilithium5="MEUCIQDTGfn8c4pjU+sWQinV2OE4O+3Xr1tb1SiUK38oeAg+/wIgWFLw98L5bTxIlmEzDuBGASCWF+2mqRWBuAXuWhfSiQg=",
                ed25519="RGlnaXRhbCBzaWduYXR1cmUgcGxhY2Vob2xkZXIgZm9yIEVkMjU1MTkgYWxnb3JpdGhtIGRlbW9uc3RyYXRpb24="
            )
        )
        
        # Write the comprehensive test file
        self.write_pam_header(output_file, manifest, include_banner=True)
        
        # Add simulated encrypted content with embedded crypto indicators
        crypto_indicators = [
            b"RSA-4096-OAEP-SHA256",
            b"ECDSA-P521-SHA512", 
            b"AES-256-GCM-96",
            b"ChaCha20-Poly1305",
            b"ML-KEM-1024",
            b"ML-DSA-87",
            b"SPHINCS+-SHA256-256f",
            b"BLAKE3-256",
            b"SHA3-512",
            b"Argon2id",
            b"HKDF-SHA3-512",
            b"X25519",
            b"Ed25519",
            b"recipient-key-block",
            b"signature-block",
            b"certificate-chain",
            b"-----BEGIN CERTIFICATE-----",
            b"-----END CERTIFICATE-----",
            b"-----BEGIN PUBLIC KEY-----",
            b"-----END PUBLIC KEY-----"
        ]
        
        import secrets
        with open(output_file, 'ab') as f:
            # Write crypto indicators embedded in random data
            for i, indicator in enumerate(crypto_indicators):
                # Random padding before indicator
                f.write(secrets.token_bytes(100 + i * 50))
                f.write(indicator)
                # Random padding after indicator  
                f.write(secrets.token_bytes(200 + i * 30))
            
            # Add more random encrypted-looking content
            f.write(secrets.token_bytes(50000))

def main():
    """Main function for command-line usage"""
    import sys
    
    generator = PAMGenerator()
    
    if len(sys.argv) < 2:
        print("Usage: python pam_generator.py <command> [options]")
        print("Commands:")
        print("  create-sample <output_file>     - Create sample encrypted file with PAM")
        print("  create-comprehensive <output>   - Create comprehensive test file")
        print("  generate-manifest <output>      - Generate standalone manifest")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "create-sample":
        if len(sys.argv) != 3:
            print("Usage: python pam_generator.py create-sample <output_file>")
            sys.exit(1)
        output_file = sys.argv[2]
        generator.create_sample_encrypted_file(output_file)
        print(f"Created sample encrypted file: {output_file}")
        
    elif command == "create-comprehensive":
        if len(sys.argv) != 3:
            print("Usage: python pam_generator.py create-comprehensive <output_file>")
            sys.exit(1)
        output_file = sys.argv[2]
        generator.create_comprehensive_test_file(output_file)
        print(f"Created comprehensive test file: {output_file}")
        
    elif command == "generate-manifest":
        if len(sys.argv) != 3:
            print("Usage: python pam_generator.py generate-manifest <output_file>")
            sys.exit(1)
        output_file = sys.argv[2]
        manifest = generator.create_default_manifest()
        with open(output_file, 'w') as f:
            json.dump(asdict(manifest), f, indent=2)
        print(f"Generated manifest: {output_file}")
        
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()

