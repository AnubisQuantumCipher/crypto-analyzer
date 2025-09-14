# Trust Store - Signer Management and Verification [NEW]

## Overview

The Trust Store component provides comprehensive signer management and verification capabilities for the Crypto Analyzer system. It maintains a secure repository of trusted cryptographic identities, certificates, and public keys used to verify the authenticity and integrity of encrypted files and their embedded Public Algorithm Manifests (PAMs).

## Trust Store Architecture

### Core Components

The Trust Store implements a hierarchical trust model with multiple verification layers:

```
Trust Store Hierarchy:
┌─────────────────────────────────────────────────────────────┐
│ Root Certificate Authorities (CAs)                          │
├─────────────────────────────────────────────────────────────┤
│ Intermediate Certificate Authorities                        │
├─────────────────────────────────────────────────────────────┤
│ End-Entity Certificates                                     │
├─────────────────────────────────────────────────────────────┤
│ Direct Trust Anchors (Self-Signed)                        │
├─────────────────────────────────────────────────────────────┤
│ Revocation Lists (CRL/OCSP)                               │
└─────────────────────────────────────────────────────────────┘
```

### Trust Store Database Schema

```python
class TrustStoreEntry:
    """Individual trust store entry."""
    
    def __init__(self):
        self.certificate_id: str = ""           # Unique identifier
        self.subject_dn: str = ""               # Distinguished Name
        self.issuer_dn: str = ""                # Issuer Distinguished Name
        self.public_key: bytes = b""            # Public key material
        self.certificate_data: bytes = b""      # Full certificate
        self.trust_level: TrustLevel = TrustLevel.UNKNOWN
        self.key_usage: List[KeyUsage] = []     # Allowed key usages
        self.validity_period: ValidityPeriod = None
        self.signature_algorithm: str = ""      # Signature algorithm OID
        self.key_algorithm: str = ""            # Public key algorithm OID
        self.extensions: Dict[str, Any] = {}    # Certificate extensions
        self.revocation_status: RevocationStatus = RevocationStatus.UNKNOWN
        self.trust_path: List[str] = []         # Chain to root CA
        self.metadata: Dict[str, Any] = {}      # Additional metadata

class TrustLevel(Enum):
    """Trust levels for certificate validation."""
    UNKNOWN = 0
    UNTRUSTED = 1
    CONDITIONAL = 2
    TRUSTED = 3
    HIGHLY_TRUSTED = 4
    ROOT_CA = 5

class KeyUsage(Enum):
    """Certificate key usage flags."""
    DIGITAL_SIGNATURE = "digitalSignature"
    NON_REPUDIATION = "nonRepudiation"
    KEY_ENCIPHERMENT = "keyEncipherment"
    DATA_ENCIPHERMENT = "dataEncipherment"
    KEY_AGREEMENT = "keyAgreement"
    KEY_CERT_SIGN = "keyCertSign"
    CRL_SIGN = "crlSign"
    ENCIPHER_ONLY = "encipherOnly"
    DECIPHER_ONLY = "decipherOnly"
```

## Certificate Management

### Certificate Import and Validation

```python
class CertificateManager:
    """Manages certificate import, validation, and storage."""
    
    def __init__(self, trust_store_path: str):
        self.trust_store_path = trust_store_path
        self.certificate_cache = {}
        self.revocation_cache = {}
        
    def import_certificate(self, cert_data: bytes, 
                          trust_level: TrustLevel = TrustLevel.CONDITIONAL) -> str:
        """
        Import a certificate into the trust store.
        
        Args:
            cert_data: X.509 certificate in DER or PEM format
            trust_level: Initial trust level assignment
            
        Returns:
            Certificate ID for future reference
        """
        # Parse certificate
        certificate = x509.load_certificate(cert_data)
        
        # Validate certificate structure
        self._validate_certificate_structure(certificate)
        
        # Extract certificate information
        cert_info = self._extract_certificate_info(certificate)
        
        # Check for existing certificate
        cert_id = self._generate_certificate_id(certificate)
        if cert_id in self.certificate_cache:
            raise CertificateAlreadyExistsError(cert_id)
        
        # Validate certificate chain
        chain_valid, trust_path = self._validate_certificate_chain(certificate)
        
        # Create trust store entry
        entry = TrustStoreEntry()
        entry.certificate_id = cert_id
        entry.subject_dn = cert_info['subject']
        entry.issuer_dn = cert_info['issuer']
        entry.public_key = cert_info['public_key']
        entry.certificate_data = cert_data
        entry.trust_level = trust_level
        entry.key_usage = cert_info['key_usage']
        entry.validity_period = cert_info['validity']
        entry.signature_algorithm = cert_info['signature_algorithm']
        entry.key_algorithm = cert_info['key_algorithm']
        entry.extensions = cert_info['extensions']
        entry.trust_path = trust_path
        
        # Check revocation status
        entry.revocation_status = self._check_revocation_status(certificate)
        
        # Store in trust store
        self._store_certificate(entry)
        
        return cert_id
    
    def _validate_certificate_structure(self, certificate: x509.Certificate):
        """Validate certificate structure and required fields."""
        # Check certificate version
        if certificate.version != x509.Version.v3:
            raise InvalidCertificateError("Only X.509 v3 certificates supported")
        
        # Validate subject and issuer
        if not certificate.subject:
            raise InvalidCertificateError("Certificate must have subject")
        
        # Check validity period
        now = datetime.utcnow()
        if certificate.not_valid_before > now:
            raise InvalidCertificateError("Certificate not yet valid")
        if certificate.not_valid_after < now:
            raise InvalidCertificateError("Certificate has expired")
        
        # Validate public key
        public_key = certificate.public_key()
        if not self._is_supported_public_key(public_key):
            raise InvalidCertificateError("Unsupported public key algorithm")
        
        # Check signature algorithm
        sig_alg = certificate.signature_algorithm_oid._name
        if sig_alg not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise InvalidCertificateError(f"Unsupported signature algorithm: {sig_alg}")
```

### Certificate Chain Validation

```python
def validate_certificate_chain(self, certificate: x509.Certificate) -> Tuple[bool, List[str]]:
    """
    Validate certificate chain to a trusted root.
    
    Args:
        certificate: Certificate to validate
        
    Returns:
        Tuple of (is_valid, trust_path)
    """
    trust_path = []
    current_cert = certificate
    
    # Build chain to root
    while True:
        cert_id = self._generate_certificate_id(current_cert)
        trust_path.append(cert_id)
        
        # Check if this is a self-signed root
        if self._is_self_signed(current_cert):
            # Verify against trusted roots
            if cert_id in self.trusted_roots:
                return True, trust_path
            else:
                return False, trust_path
        
        # Find issuer certificate
        issuer_cert = self._find_issuer_certificate(current_cert)
        if not issuer_cert:
            return False, trust_path
        
        # Verify signature
        if not self._verify_certificate_signature(current_cert, issuer_cert):
            return False, trust_path
        
        # Check for chain loops
        issuer_id = self._generate_certificate_id(issuer_cert)
        if issuer_id in trust_path:
            return False, trust_path
        
        current_cert = issuer_cert
        
        # Prevent infinite loops
        if len(trust_path) > MAX_CHAIN_LENGTH:
            return False, trust_path

def _verify_certificate_signature(self, cert: x509.Certificate, 
                                 issuer_cert: x509.Certificate) -> bool:
    """Verify certificate signature using issuer's public key."""
    try:
        issuer_public_key = issuer_cert.public_key()
        
        # Get signature algorithm
        sig_alg = cert.signature_algorithm_oid._name
        
        # Verify signature based on algorithm
        if sig_alg.startswith('rsa'):
            return self._verify_rsa_signature(cert, issuer_public_key)
        elif sig_alg.startswith('ecdsa'):
            return self._verify_ecdsa_signature(cert, issuer_public_key)
        elif sig_alg.startswith('ed25519'):
            return self._verify_ed25519_signature(cert, issuer_public_key)
        elif sig_alg.startswith('ml_dsa'):
            return self._verify_ml_dsa_signature(cert, issuer_public_key)
        else:
            return False
            
    except Exception as e:
        logger.warning(f"Signature verification failed: {e}")
        return False
```

## Revocation Management

### Certificate Revocation Lists (CRL)

```python
class RevocationManager:
    """Manages certificate revocation checking."""
    
    def __init__(self):
        self.crl_cache = {}
        self.ocsp_cache = {}
        
    def check_revocation_status(self, certificate: x509.Certificate) -> RevocationStatus:
        """
        Check certificate revocation status using CRL and OCSP.
        
        Args:
            certificate: Certificate to check
            
        Returns:
            RevocationStatus indicating current status
        """
        cert_serial = certificate.serial_number
        
        # Try OCSP first (more current)
        ocsp_status = self._check_ocsp_status(certificate)
        if ocsp_status != RevocationStatus.UNKNOWN:
            return ocsp_status
        
        # Fall back to CRL
        crl_status = self._check_crl_status(certificate)
        return crl_status
    
    def _check_ocsp_status(self, certificate: x509.Certificate) -> RevocationStatus:
        """Check certificate status via OCSP."""
        try:
            # Extract OCSP URL from certificate
            ocsp_urls = self._extract_ocsp_urls(certificate)
            if not ocsp_urls:
                return RevocationStatus.UNKNOWN
            
            # Build OCSP request
            ocsp_request = self._build_ocsp_request(certificate)
            
            # Query OCSP responder
            for url in ocsp_urls:
                try:
                    response = self._send_ocsp_request(url, ocsp_request)
                    return self._parse_ocsp_response(response)
                except Exception as e:
                    logger.warning(f"OCSP query failed for {url}: {e}")
                    continue
            
            return RevocationStatus.UNKNOWN
            
        except Exception as e:
            logger.error(f"OCSP status check failed: {e}")
            return RevocationStatus.UNKNOWN
    
    def _check_crl_status(self, certificate: x509.Certificate) -> RevocationStatus:
        """Check certificate status via CRL."""
        try:
            # Extract CRL distribution points
            crl_urls = self._extract_crl_urls(certificate)
            if not crl_urls:
                return RevocationStatus.UNKNOWN
            
            # Download and verify CRL
            for url in crl_urls:
                try:
                    crl = self._download_crl(url)
                    if self._verify_crl_signature(crl, certificate):
                        return self._check_certificate_in_crl(certificate, crl)
                except Exception as e:
                    logger.warning(f"CRL check failed for {url}: {e}")
                    continue
            
            return RevocationStatus.UNKNOWN
            
        except Exception as e:
            logger.error(f"CRL status check failed: {e}")
            return RevocationStatus.UNKNOWN

class RevocationStatus(Enum):
    """Certificate revocation status."""
    UNKNOWN = 0
    VALID = 1
    REVOKED = 2
    SUSPENDED = 3
    EXPIRED = 4
```

## Signature Verification

### Multi-Algorithm Signature Verification

```python
class SignatureVerifier:
    """Verifies signatures using trust store certificates."""
    
    def __init__(self, trust_store: TrustStore):
        self.trust_store = trust_store
        
    def verify_signature(self, data: bytes, signature: bytes, 
                        signer_cert_id: str) -> VerificationResult:
        """
        Verify signature against data using specified certificate.
        
        Args:
            data: Original data that was signed
            signature: Signature to verify
            signer_cert_id: Certificate ID of the signer
            
        Returns:
            VerificationResult with detailed verification information
        """
        # Retrieve signer certificate
        signer_cert = self.trust_store.get_certificate(signer_cert_id)
        if not signer_cert:
            return VerificationResult(False, "Signer certificate not found")
        
        # Check certificate validity
        validity_check = self._check_certificate_validity(signer_cert)
        if not validity_check.is_valid:
            return VerificationResult(False, f"Certificate invalid: {validity_check.reason}")
        
        # Verify certificate chain
        chain_valid, trust_path = self.trust_store.validate_certificate_chain(signer_cert.certificate_data)
        if not chain_valid:
            return VerificationResult(False, "Certificate chain validation failed")
        
        # Check revocation status
        if signer_cert.revocation_status == RevocationStatus.REVOKED:
            return VerificationResult(False, "Certificate has been revoked")
        
        # Verify signature
        signature_valid = self._verify_cryptographic_signature(
            data, signature, signer_cert.public_key, signer_cert.signature_algorithm
        )
        
        if signature_valid:
            return VerificationResult(
                True, 
                "Signature verification successful",
                trust_level=signer_cert.trust_level,
                trust_path=trust_path,
                signer_info=self._extract_signer_info(signer_cert)
            )
        else:
            return VerificationResult(False, "Cryptographic signature verification failed")
    
    def _verify_cryptographic_signature(self, data: bytes, signature: bytes,
                                      public_key: bytes, algorithm: str) -> bool:
        """Verify cryptographic signature based on algorithm."""
        try:
            if algorithm.startswith('rsa'):
                return self._verify_rsa_pss_signature(data, signature, public_key)
            elif algorithm.startswith('ecdsa'):
                return self._verify_ecdsa_signature(data, signature, public_key)
            elif algorithm.startswith('ed25519'):
                return self._verify_ed25519_signature(data, signature, public_key)
            elif algorithm.startswith('ml_dsa'):
                return self._verify_ml_dsa_signature(data, signature, public_key)
            elif algorithm.startswith('falcon'):
                return self._verify_falcon_signature(data, signature, public_key)
            elif algorithm.startswith('sphincs'):
                return self._verify_sphincs_signature(data, signature, public_key)
            else:
                logger.error(f"Unsupported signature algorithm: {algorithm}")
                return False
                
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False

class VerificationResult:
    """Result of signature verification."""
    
    def __init__(self, is_valid: bool, message: str, **kwargs):
        self.is_valid = is_valid
        self.message = message
        self.trust_level = kwargs.get('trust_level', TrustLevel.UNKNOWN)
        self.trust_path = kwargs.get('trust_path', [])
        self.signer_info = kwargs.get('signer_info', {})
        self.verification_time = datetime.utcnow()
        self.algorithm_info = kwargs.get('algorithm_info', {})
```

## PAM Signature Verification

### Public Algorithm Manifest Verification

```python
class PAMVerifier:
    """Verifies PAM signatures and integrity."""
    
    def __init__(self, trust_store: TrustStore):
        self.trust_store = trust_store
        self.signature_verifier = SignatureVerifier(trust_store)
        
    def verify_pam_signature(self, pam_data: bytes) -> PAMVerificationResult:
        """
        Verify PAM signature and validate manifest integrity.
        
        Args:
            pam_data: Complete PAM data including signatures
            
        Returns:
            PAMVerificationResult with verification details
        """
        try:
            # Parse PAM structure
            pam_manifest = self._parse_pam_structure(pam_data)
            
            # Extract signature information
            signatures = pam_manifest.get('signatures', [])
            if not signatures:
                return PAMVerificationResult(False, "No signatures found in PAM")
            
            verification_results = []
            
            # Verify each signature
            for sig_info in signatures:
                signer_id = sig_info.get('signer_certificate_id')
                signature_data = sig_info.get('signature')
                signed_content = sig_info.get('signed_content', pam_manifest['content'])
                
                # Verify individual signature
                result = self.signature_verifier.verify_signature(
                    signed_content, signature_data, signer_id
                )
                
                verification_results.append({
                    'signer_id': signer_id,
                    'result': result,
                    'algorithm': sig_info.get('algorithm'),
                    'timestamp': sig_info.get('timestamp')
                })
            
            # Determine overall verification result
            all_valid = all(r['result'].is_valid for r in verification_results)
            
            if all_valid:
                return PAMVerificationResult(
                    True,
                    "All PAM signatures verified successfully",
                    signature_results=verification_results,
                    manifest_content=pam_manifest['content']
                )
            else:
                failed_signers = [r['signer_id'] for r in verification_results 
                                if not r['result'].is_valid]
                return PAMVerificationResult(
                    False,
                    f"PAM signature verification failed for signers: {failed_signers}",
                    signature_results=verification_results
                )
                
        except Exception as e:
            return PAMVerificationResult(False, f"PAM verification error: {e}")
    
    def _parse_pam_structure(self, pam_data: bytes) -> Dict[str, Any]:
        """Parse PAM structure and extract components."""
        # Check PAM magic header
        if not pam_data.startswith(b'QSv1\x00\x00\x00'):
            raise ValueError("Invalid PAM magic header")
        
        # Extract version and length
        version = struct.unpack('>H', pam_data[8:10])[0]
        manifest_length = struct.unpack('>I', pam_data[10:14])[0]
        
        # Extract manifest data
        manifest_start = 14
        manifest_end = manifest_start + manifest_length
        manifest_cbor = pam_data[manifest_start:manifest_end]
        
        # Parse CBOR manifest
        manifest = cbor2.loads(manifest_cbor)
        
        return {
            'version': version,
            'content': manifest,
            'raw_data': pam_data
        }

class PAMVerificationResult:
    """Result of PAM signature verification."""
    
    def __init__(self, is_valid: bool, message: str, **kwargs):
        self.is_valid = is_valid
        self.message = message
        self.signature_results = kwargs.get('signature_results', [])
        self.manifest_content = kwargs.get('manifest_content', {})
        self.verification_time = datetime.utcnow()
```

## Trust Store Configuration

### Configuration Management

```python
class TrustStoreConfig:
    """Trust store configuration management."""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load trust store configuration."""
        default_config = {
            'trust_store_path': './trust_store.db',
            'certificate_cache_size': 1000,
            'revocation_check_enabled': True,
            'ocsp_timeout': 10,
            'crl_cache_duration': 3600,
            'supported_algorithms': {
                'signature': [
                    'rsa_pss_sha256',
                    'ecdsa_sha256',
                    'ed25519',
                    'ml_dsa_44',
                    'ml_dsa_65',
                    'ml_dsa_87',
                    'falcon_512',
                    'falcon_1024',
                    'sphincs_sha256_128f',
                    'sphincs_sha256_192f',
                    'sphincs_sha256_256f'
                ],
                'hash': [
                    'sha256',
                    'sha384',
                    'sha512',
                    'sha3_256',
                    'sha3_384',
                    'sha3_512',
                    'blake2b',
                    'blake2s',
                    'blake3'
                ]
            },
            'trusted_roots': [
                # Default trusted root CAs
                'crypto_analyzer_root_ca',
                'nist_test_ca',
                'quantum_safe_ca'
            ],
            'revocation_sources': {
                'crl_urls': [],
                'ocsp_urls': []
            }
        }
        
        try:
            with open(self.config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except FileNotFoundError:
            # Create default config file
            self._save_config(default_config)
        
        return default_config
    
    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to file."""
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
```

## Integration with Crypto Analyzer

### Trust Store Integration

```python
class CryptoAnalyzerTrustIntegration:
    """Integration between Crypto Analyzer and Trust Store."""
    
    def __init__(self, trust_store: TrustStore):
        self.trust_store = trust_store
        self.pam_verifier = PAMVerifier(trust_store)
        
    def analyze_with_trust_verification(self, file_data: bytes) -> AnalysisResult:
        """
        Analyze file with trust store verification.
        
        Args:
            file_data: Encrypted file data
            
        Returns:
            AnalysisResult with trust verification information
        """
        # Perform standard crypto analysis
        analysis_result = self._perform_standard_analysis(file_data)
        
        # Check for PAM and verify signatures
        pam_result = self._check_and_verify_pam(file_data)
        if pam_result:
            analysis_result.pam_verification = pam_result
            analysis_result.trust_level = self._determine_trust_level(pam_result)
        
        # Check for embedded certificates
        cert_results = self._extract_and_verify_certificates(file_data)
        if cert_results:
            analysis_result.certificate_verification = cert_results
        
        # Generate trust assessment
        analysis_result.trust_assessment = self._generate_trust_assessment(
            analysis_result
        )
        
        return analysis_result
    
    def _determine_trust_level(self, pam_result: PAMVerificationResult) -> TrustLevel:
        """Determine overall trust level based on verification results."""
        if not pam_result.is_valid:
            return TrustLevel.UNTRUSTED
        
        # Check trust levels of all signers
        trust_levels = []
        for sig_result in pam_result.signature_results:
            if sig_result['result'].is_valid:
                trust_levels.append(sig_result['result'].trust_level)
        
        if not trust_levels:
            return TrustLevel.UNTRUSTED
        
        # Return highest trust level among valid signers
        return max(trust_levels, key=lambda x: x.value)
```

This comprehensive Trust Store documentation provides complete signer management and verification capabilities, ensuring robust authentication and integrity checking for all cryptographic operations within the Crypto Analyzer system.

