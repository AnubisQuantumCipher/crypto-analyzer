# Signature Guide - ML-DSA-87 Implementation Details [NEW]

## Overview

This guide provides comprehensive implementation details for ML-DSA-87 (Module-Lattice-Based Digital Signature Algorithm), the NIST-standardized post-quantum digital signature scheme. ML-DSA-87 represents the highest security level (Level 5) of the ML-DSA family, offering quantum-resistant digital signatures with security equivalent to AES-256.

## ML-DSA-87 Specification

### Algorithm Parameters

ML-DSA-87 operates with the following cryptographic parameters:

```
Security Level: NIST Level 5 (256-bit quantum security)
Modulus q: 8380417
Dimension n: 256
Dimensions (k, l): (8, 7)
Eta: 2
Tau: 60
Beta: 196
Gamma1: 2^19
Gamma2: (q-1)/32
Omega: 75
```

### Key Sizes

```
Public Key Size: 2592 bytes
Private Key Size: 4896 bytes
Signature Size: 4627 bytes (average)
```

### Security Properties

- **Quantum Security**: 256-bit security against quantum attacks
- **Classical Security**: >256-bit security against classical attacks
- **Signature Forgery**: Computationally infeasible under lattice assumptions
- **Key Recovery**: Protected by Module-LWE and Module-SIS problems

## Implementation Architecture

### Core Components

#### 1. Key Generation

The ML-DSA-87 key generation process involves several cryptographic operations:

```python
def ml_dsa_87_keygen(seed: bytes) -> Tuple[PublicKey, PrivateKey]:
    """
    Generate ML-DSA-87 key pair from a 32-byte seed.
    
    Args:
        seed: 32-byte random seed
        
    Returns:
        Tuple of (public_key, private_key)
    """
    # Expand seed using SHAKE-256
    rho, rho_prime, K = expand_seed(seed)
    
    # Generate matrix A from rho
    A = expand_A(rho)
    
    # Sample secret vectors s1, s2
    s1 = sample_in_ball(rho_prime, 0, l)
    s2 = sample_in_ball(rho_prime, l, k)
    
    # Compute t = A * s1 + s2
    t = matrix_vector_multiply(A, s1) + s2
    
    # Pack keys
    public_key = pack_public_key(rho, t1)
    private_key = pack_private_key(rho, K, tr, s1, s2, t0)
    
    return public_key, private_key
```

#### 2. Signature Generation

The signing process implements the Fiat-Shamir transform with rejection sampling:

```python
def ml_dsa_87_sign(message: bytes, private_key: PrivateKey) -> bytes:
    """
    Generate ML-DSA-87 signature for a message.
    
    Args:
        message: Message to be signed
        private_key: ML-DSA-87 private key
        
    Returns:
        Signature bytes
    """
    # Unpack private key
    rho, K, tr, s1, s2, t0 = unpack_private_key(private_key)
    
    # Expand matrix A
    A = expand_A(rho)
    
    # Message preprocessing
    mu = hash_message(tr, message)
    
    # Rejection sampling loop
    kappa = 0
    while True:
        # Sample mask y
        y = sample_mask(rho_prime, kappa)
        
        # Compute w = A * y
        w = matrix_vector_multiply(A, y)
        w1 = high_bits(w)
        
        # Compute challenge
        c_tilde = hash_challenge(mu, w1)
        c = sample_in_ball(c_tilde)
        
        # Compute signature components
        z = y + c * s1
        r0 = low_bits(w - c * s2)
        
        # Rejection sampling checks
        if norm_infinity(z) >= gamma1 - beta or \
           norm_infinity(r0) >= gamma2 - beta:
            kappa += 1
            continue
            
        # Additional checks for security
        if norm_infinity(c * t0) >= gamma2 or \
           hint_check_fails(w - c * s2 + c * t0, w1):
            kappa += 1
            continue
            
        break
    
    # Pack signature
    signature = pack_signature(c_tilde, z, h)
    return signature
```

#### 3. Signature Verification

The verification process validates the signature against the public key and message:

```python
def ml_dsa_87_verify(message: bytes, signature: bytes, 
                     public_key: PublicKey) -> bool:
    """
    Verify ML-DSA-87 signature.
    
    Args:
        message: Original message
        signature: Signature to verify
        public_key: ML-DSA-87 public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    # Unpack public key and signature
    rho, t1 = unpack_public_key(public_key)
    c_tilde, z, h = unpack_signature(signature)
    
    # Validation checks
    if norm_infinity(z) >= gamma1 - beta:
        return False
    
    # Expand matrix A
    A = expand_A(rho)
    
    # Recompute challenge
    c = sample_in_ball(c_tilde)
    
    # Compute verification equation
    w_approx = A * z - c * (2^d * t1)
    w1_prime = use_hint(h, w_approx)
    
    # Hash verification
    mu = hash_message(tr, message)
    c_tilde_prime = hash_challenge(mu, w1_prime)
    
    return c_tilde == c_tilde_prime
```

## Cryptographic Operations

### Lattice Operations

#### Matrix-Vector Multiplication

ML-DSA-87 relies heavily on efficient matrix-vector multiplication over polynomial rings:

```python
def matrix_vector_multiply(A: Matrix, s: Vector) -> Vector:
    """
    Multiply matrix A by vector s in the polynomial ring Rq.
    
    Uses Number Theoretic Transform (NTT) for efficiency.
    """
    result = [0] * len(A)
    
    for i in range(len(A)):
        for j in range(len(s)):
            # Polynomial multiplication in Rq
            result[i] += polynomial_multiply(A[i][j], s[j])
            result[i] = reduce_mod_q(result[i])
    
    return result
```

#### Rejection Sampling

The security of ML-DSA-87 depends on proper rejection sampling to ensure signature distribution independence:

```python
def rejection_sample(z: Vector, threshold: int) -> bool:
    """
    Perform rejection sampling check for signature security.
    
    Args:
        z: Signature component vector
        threshold: Maximum allowed norm
        
    Returns:
        True if sample should be accepted, False if rejected
    """
    # Check infinity norm
    if norm_infinity(z) >= threshold:
        return False
    
    # Additional statistical checks
    if not passes_statistical_tests(z):
        return False
    
    return True
```

### Hash Functions

ML-DSA-87 uses SHAKE-256 for various cryptographic operations:

```python
def shake256_absorb_squeeze(input_data: bytes, output_length: int) -> bytes:
    """
    SHAKE-256 hash function for ML-DSA operations.
    """
    shake = hashlib.shake_256()
    shake.update(input_data)
    return shake.digest(output_length)

def hash_message(tr: bytes, message: bytes) -> bytes:
    """Hash message with domain separation."""
    return shake256_absorb_squeeze(tr + message, 64)

def hash_challenge(mu: bytes, w1: Vector) -> bytes:
    """Generate challenge hash."""
    w1_packed = pack_w1(w1)
    return shake256_absorb_squeeze(mu + w1_packed, 32)
```

## Security Analysis

### Lattice Problem Hardness

ML-DSA-87 security is based on the hardness of lattice problems:

#### Module Learning With Errors (M-LWE)

The public key indistinguishability relies on the M-LWE problem:

```
Given: (A, t = A*s + e) where A is random, s,e are small
Find: s or distinguish from random
```

**Security Reduction:**
- Classical security: 2^256 operations
- Quantum security: 2^256 operations (Grover's algorithm considered)

#### Module Short Integer Solution (M-SIS)

Signature forgery is equivalent to solving M-SIS:

```
Given: Matrix A
Find: Short vector z such that A*z = 0 (mod q)
```

**Hardness Parameters:**
- Dimension: 256 × 1792
- Modulus: 8380417
- Solution bound: 2^19 - 196

### Side-Channel Resistance

The implementation includes protections against timing and power analysis attacks:

#### Constant-Time Operations

```python
def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0

def constant_time_select(condition: bool, a: int, b: int) -> int:
    """Constant-time conditional selection."""
    mask = -(condition & 1)
    return (mask & a) | (~mask & b)
```

#### Masking Countermeasures

Protection against power analysis through Boolean masking:

```python
def masked_polynomial_multiply(a: Polynomial, b: Polynomial, 
                              mask: Polynomial) -> Polynomial:
    """
    Polynomial multiplication with masking protection.
    """
    # Mask inputs
    a_masked = a ^ mask
    b_masked = b ^ rotate(mask, 1)
    
    # Perform multiplication
    result_masked = polynomial_multiply(a_masked, b_masked)
    
    # Unmask result
    return result_masked ^ compute_mask_correction(mask)
```

## Performance Optimization

### Number Theoretic Transform (NTT)

Efficient polynomial multiplication using NTT:

```python
def ntt_forward(poly: List[int]) -> List[int]:
    """Forward NTT transformation."""
    n = len(poly)
    result = poly.copy()
    
    length = n // 2
    while length >= 1:
        for start in range(0, n, 2 * length):
            zeta = primitive_root_powers[length]
            for j in range(length):
                u = result[start + j]
                v = (result[start + j + length] * zeta) % q
                result[start + j] = (u + v) % q
                result[start + j + length] = (u - v) % q
        length //= 2
    
    return result

def ntt_inverse(poly: List[int]) -> List[int]:
    """Inverse NTT transformation."""
    # Implementation mirrors forward NTT with inverse operations
    pass
```

### Memory Optimization

Efficient memory usage for large signature operations:

```python
class MemoryPool:
    """Memory pool for temporary polynomial storage."""
    
    def __init__(self, pool_size: int):
        self.pool = [bytearray(256 * 4) for _ in range(pool_size)]
        self.available = list(range(pool_size))
    
    def allocate(self) -> bytearray:
        if not self.available:
            raise MemoryError("Pool exhausted")
        return self.pool[self.available.pop()]
    
    def deallocate(self, buffer: bytearray):
        # Find buffer index and return to pool
        for i, pool_buffer in enumerate(self.pool):
            if buffer is pool_buffer:
                self.available.append(i)
                break
```

## Integration with Crypto Analyzer

### Detection Patterns

The Crypto Analyzer detects ML-DSA-87 signatures through multiple methods:

#### ASN.1 OID Detection

```python
ML_DSA_87_OID = "2.16.840.1.101.3.4.3.17"  # NIST assigned OID

def detect_ml_dsa_87_asn1(data: bytes) -> bool:
    """Detect ML-DSA-87 through ASN.1 structure."""
    try:
        decoded = asn1.decode(data)
        return check_oid_in_structure(decoded, ML_DSA_87_OID)
    except:
        return False
```

#### Binary Signature Detection

```python
def detect_ml_dsa_87_binary(data: bytes) -> bool:
    """Detect ML-DSA-87 through binary patterns."""
    # Check for characteristic signature size
    if len(data) == 4627:  # Average ML-DSA-87 signature size
        # Verify entropy and structure
        entropy = calculate_entropy(data)
        if 7.8 <= entropy <= 8.0:  # High entropy expected
            return verify_ml_dsa_structure(data)
    
    return False
```

#### PAM Manifest Integration

```python
def create_ml_dsa_87_pam_entry() -> Dict:
    """Create PAM entry for ML-DSA-87."""
    return {
        "algorithm": "ML-DSA-87",
        "type": "signature",
        "security_level": 5,
        "quantum_safe": True,
        "key_size": {
            "public": 2592,
            "private": 4896
        },
        "signature_size": 4627,
        "parameters": {
            "n": 256,
            "q": 8380417,
            "k": 8,
            "l": 7,
            "eta": 2,
            "tau": 60,
            "beta": 196,
            "gamma1": 524288,  # 2^19
            "gamma2": 261888,  # (q-1)/32
            "omega": 75
        },
        "standards": ["NIST FIPS 204", "ISO/IEC 14888-4"],
        "implementation": "Reference implementation v1.0"
    }
```

## Testing and Validation

### Test Vectors

Comprehensive test vectors ensure implementation correctness:

```python
def test_ml_dsa_87_known_vectors():
    """Test against NIST known answer tests."""
    test_vectors = load_nist_test_vectors("ML-DSA-87")
    
    for vector in test_vectors:
        # Test key generation
        pk, sk = ml_dsa_87_keygen(vector.seed)
        assert pk == vector.public_key
        assert sk == vector.private_key
        
        # Test signing
        signature = ml_dsa_87_sign(vector.message, sk)
        assert signature == vector.signature
        
        # Test verification
        assert ml_dsa_87_verify(vector.message, signature, pk)
        
        # Test invalid signature rejection
        invalid_sig = corrupt_signature(signature)
        assert not ml_dsa_87_verify(vector.message, invalid_sig, pk)
```

### Performance Benchmarks

```python
def benchmark_ml_dsa_87():
    """Benchmark ML-DSA-87 operations."""
    import time
    
    # Key generation benchmark
    start = time.time()
    for _ in range(1000):
        pk, sk = ml_dsa_87_keygen(os.urandom(32))
    keygen_time = (time.time() - start) / 1000
    
    # Signing benchmark
    message = b"benchmark message"
    start = time.time()
    for _ in range(1000):
        signature = ml_dsa_87_sign(message, sk)
    sign_time = (time.time() - start) / 1000
    
    # Verification benchmark
    start = time.time()
    for _ in range(1000):
        ml_dsa_87_verify(message, signature, pk)
    verify_time = (time.time() - start) / 1000
    
    print(f"ML-DSA-87 Performance:")
    print(f"Key Generation: {keygen_time:.3f}ms")
    print(f"Signing: {sign_time:.3f}ms")
    print(f"Verification: {verify_time:.3f}ms")
```

## Migration and Deployment

### Hybrid Signatures

For migration scenarios, ML-DSA-87 can be combined with classical signatures:

```python
def create_hybrid_signature(message: bytes, rsa_key: RSAKey, 
                           ml_dsa_key: MLDSAKey) -> bytes:
    """Create hybrid RSA + ML-DSA-87 signature."""
    # Generate both signatures
    rsa_sig = rsa_pss_sign(message, rsa_key)
    ml_dsa_sig = ml_dsa_87_sign(message, ml_dsa_key)
    
    # Combine in ASN.1 structure
    hybrid_sig = asn1.encode({
        'rsa_signature': rsa_sig,
        'ml_dsa_signature': ml_dsa_sig,
        'algorithm_id': HYBRID_RSA_ML_DSA_87_OID
    })
    
    return hybrid_sig
```

### Certificate Integration

ML-DSA-87 integration with X.509 certificates:

```python
def create_ml_dsa_87_certificate(subject: str, issuer_key: MLDSAKey) -> bytes:
    """Create X.509 certificate with ML-DSA-87 signature."""
    cert_info = {
        'version': 3,
        'subject': subject,
        'public_key': extract_public_key(issuer_key),
        'signature_algorithm': ML_DSA_87_OID,
        'validity': {
            'not_before': datetime.now(),
            'not_after': datetime.now() + timedelta(days=365)
        }
    }
    
    # Encode certificate info
    tbs_certificate = asn1.encode(cert_info)
    
    # Sign with ML-DSA-87
    signature = ml_dsa_87_sign(tbs_certificate, issuer_key)
    
    # Create final certificate
    certificate = asn1.encode({
        'tbs_certificate': tbs_certificate,
        'signature_algorithm': ML_DSA_87_OID,
        'signature': signature
    })
    
    return certificate
```

This comprehensive guide provides all necessary implementation details for ML-DSA-87 integration within the Crypto Analyzer system, ensuring robust post-quantum signature detection and analysis capabilities.

