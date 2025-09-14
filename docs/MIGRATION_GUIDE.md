# Migration Guide - Upgrading to Signature Support

## Overview

This migration guide provides comprehensive instructions for upgrading existing Crypto Analyzer deployments to support the new signature verification and trust store capabilities. The upgrade introduces enhanced security features, post-quantum signature support, and improved cryptographic analysis while maintaining backward compatibility with existing encrypted files.

## Migration Overview

### What's New in Version 2.1

**Enhanced Security Features:**
- Digital signature verification for PAM manifests
- Trust store management for certificate validation
- Multi-signature support with hybrid classical+post-quantum schemes
- Certificate chain validation and revocation checking
- Timestamping support for non-repudiation

**New Cryptographic Algorithms:**
- ML-DSA (CRYSTALS-Dilithium) post-quantum signatures
- FALCON lattice-based signatures
- SPHINCS+ hash-based signatures
- Hybrid signature schemes combining classical and post-quantum algorithms

**Improved Analysis Capabilities:**
- Enhanced PAM parsing with signature validation
- Certificate extraction and analysis
- Trust level assessment based on signature verification
- Comprehensive security assessment reporting

### Compatibility Matrix

| Component | v1.x | v2.0 | v2.1 | Notes |
|-----------|------|------|------|-------|
| QSFS File Format | ✓ | ✓ | ✓ | Backward compatible |
| PAM Structure | ✓ | ✓ | ✓ | Extended with signatures |
| API Endpoints | ✓ | ✓ | ✓ | New endpoints added |
| Database Schema | - | ✓ | ✓ | Migration required |
| Trust Store | - | - | ✓ | New component |

## Pre-Migration Assessment

### System Requirements Check

```bash
#!/bin/bash
# Pre-migration system check script

echo "=== Crypto Analyzer Migration Assessment ==="

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "Python version: $python_version"

if [[ $(echo "$python_version 3.9" | awk '{print ($1 >= $2)}') == 1 ]]; then
    echo "✓ Python version compatible"
else
    echo "✗ Python 3.9+ required"
    exit 1
fi

# Check available disk space
available_space=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
echo "Available disk space: ${available_space}GB"

if [[ $available_space -ge 5 ]]; then
    echo "✓ Sufficient disk space"
else
    echo "✗ At least 5GB free space required"
    exit 1
fi

# Check memory
total_memory=$(free -g | awk '/^Mem:/{print $2}')
echo "Total memory: ${total_memory}GB"

if [[ $total_memory -ge 4 ]]; then
    echo "✓ Sufficient memory"
else
    echo "✗ At least 4GB RAM recommended"
fi

# Check existing installation
if [[ -f "crypto_analyzer.py" ]]; then
    current_version=$(grep -o "version.*[0-9]\+\.[0-9]\+\.[0-9]\+" crypto_analyzer.py | head -1)
    echo "Current installation: $current_version"
else
    echo "No existing installation found"
fi

echo "=== Assessment Complete ==="
```

### Data Backup

```bash
#!/bin/bash
# Backup existing data before migration

BACKUP_DIR="./backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Creating backup in $BACKUP_DIR..."

# Backup configuration files
if [[ -f "config.json" ]]; then
    cp config.json "$BACKUP_DIR/"
    echo "✓ Configuration backed up"
fi

# Backup database
if [[ -f "crypto_analyzer.db" ]]; then
    cp crypto_analyzer.db "$BACKUP_DIR/"
    echo "✓ Database backed up"
fi

# Backup analysis cache
if [[ -d "cache" ]]; then
    cp -r cache "$BACKUP_DIR/"
    echo "✓ Cache backed up"
fi

# Backup custom certificates
if [[ -d "certificates" ]]; then
    cp -r certificates "$BACKUP_DIR/"
    echo "✓ Certificates backed up"
fi

echo "Backup completed: $BACKUP_DIR"
```

## Step-by-Step Migration

### Step 1: Environment Preparation

```bash
# 1. Stop existing services
sudo systemctl stop crypto-analyzer
sudo systemctl stop nginx  # if using reverse proxy

# 2. Create backup
./backup_data.sh

# 3. Update system packages
sudo apt update && sudo apt upgrade -y

# 4. Install new dependencies
sudo apt install -y libssl-dev libffi-dev

# 5. Update Python packages
pip3 install --upgrade pip setuptools wheel
```

### Step 2: Code Update

```bash
# 1. Download new version
git fetch origin
git checkout v2.1.0

# 2. Install new Python dependencies
pip3 install -r requirements.txt

# 3. Install new cryptographic libraries
pip3 install pycryptodome cryptography cbor2 asn1crypto

# 4. Verify installation
python3 -c "import crypto_analyzer; print('Installation successful')"
```

### Step 3: Database Migration

```python
#!/usr/bin/env python3
"""Database migration script for Crypto Analyzer v2.1"""

import sqlite3
import os
import json
from datetime import datetime

class DatabaseMigrator:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def migrate(self):
        """Perform complete database migration."""
        print("Starting database migration...")
        
        # 1. Create backup
        self._create_backup()
        
        # 2. Check current schema version
        current_version = self._get_schema_version()
        print(f"Current schema version: {current_version}")
        
        # 3. Apply migrations
        if current_version < 2:
            self._migrate_to_v2()
        
        if current_version < 3:
            self._migrate_to_v3()
        
        # 4. Update schema version
        self._update_schema_version(3)
        
        print("Database migration completed successfully")
    
    def _create_backup(self):
        """Create database backup."""
        if os.path.exists(self.db_path):
            import shutil
            shutil.copy2(self.db_path, self.backup_path)
            print(f"Database backed up to: {self.backup_path}")
    
    def _get_schema_version(self) -> int:
        """Get current schema version."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT version FROM schema_version ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else 1
        except sqlite3.OperationalError:
            return 1  # No schema_version table exists
    
    def _migrate_to_v2(self):
        """Migrate to schema version 2 - Add trust store tables."""
        print("Migrating to schema version 2...")
        
        conn = sqlite3.connect(self.db_path)
        
        # Create schema_version table if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version INTEGER NOT NULL,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create certificates table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                certificate_id TEXT PRIMARY KEY,
                subject_dn TEXT NOT NULL,
                issuer_dn TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                public_key BLOB NOT NULL,
                certificate_data BLOB NOT NULL,
                trust_level INTEGER NOT NULL DEFAULT 0,
                key_usage TEXT,
                validity_not_before TIMESTAMP,
                validity_not_after TIMESTAMP,
                signature_algorithm TEXT,
                key_algorithm TEXT,
                revocation_status INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create certificate_chains table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certificate_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_certificate_id TEXT NOT NULL,
                intermediate_certificate_id TEXT,
                end_entity_certificate_id TEXT NOT NULL,
                chain_order INTEGER NOT NULL,
                validation_status INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (root_certificate_id) REFERENCES certificates(certificate_id),
                FOREIGN KEY (intermediate_certificate_id) REFERENCES certificates(certificate_id),
                FOREIGN KEY (end_entity_certificate_id) REFERENCES certificates(certificate_id)
            )
        """)
        
        # Create revocation_lists table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS revocation_lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issuer_certificate_id TEXT NOT NULL,
                crl_url TEXT,
                ocsp_url TEXT,
                last_update TIMESTAMP,
                next_update TIMESTAMP,
                crl_data BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (issuer_certificate_id) REFERENCES certificates(certificate_id)
            )
        """)
        
        # Create indexes for performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_certificates_subject ON certificates(subject_dn)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_certificates_issuer ON certificates(issuer_dn)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_certificates_trust_level ON certificates(trust_level)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_certificate_chains_root ON certificate_chains(root_certificate_id)")
        
        conn.commit()
        conn.close()
        
        print("✓ Trust store tables created")
    
    def _migrate_to_v3(self):
        """Migrate to schema version 3 - Add signature verification tables."""
        print("Migrating to schema version 3...")
        
        conn = sqlite3.connect(self.db_path)
        
        # Add signature verification tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signature_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL,
                signer_certificate_id TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                signature_data BLOB NOT NULL,
                verification_status INTEGER NOT NULL,
                verification_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                trust_level INTEGER,
                error_message TEXT,
                FOREIGN KEY (signer_certificate_id) REFERENCES certificates(certificate_id)
            )
        """)
        
        # Add PAM signature table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pam_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pam_hash TEXT NOT NULL,
                signature_count INTEGER NOT NULL DEFAULT 0,
                all_signatures_valid BOOLEAN DEFAULT FALSE,
                highest_trust_level INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Extend analysis_results table if it exists
        try:
            conn.execute("ALTER TABLE analysis_results ADD COLUMN signature_verification_id INTEGER")
            conn.execute("ALTER TABLE analysis_results ADD COLUMN trust_assessment TEXT")
        except sqlite3.OperationalError:
            # Columns already exist or table doesn't exist
            pass
        
        conn.commit()
        conn.close()
        
        print("✓ Signature verification tables created")
    
    def _update_schema_version(self, version: int):
        """Update schema version."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
        conn.commit()
        conn.close()

# Run migration
if __name__ == "__main__":
    migrator = DatabaseMigrator("crypto_analyzer.db")
    migrator.migrate()
```

### Step 4: Configuration Update

```python
#!/usr/bin/env python3
"""Configuration migration script"""

import json
import os
from typing import Dict, Any

class ConfigMigrator:
    def __init__(self, config_path: str = "config.json"):
        self.config_path = config_path
        self.backup_path = f"{config_path}.backup"
    
    def migrate_config(self):
        """Migrate configuration to new format."""
        print("Migrating configuration...")
        
        # Load existing config
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Create backup
            with open(self.backup_path, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"Configuration backed up to: {self.backup_path}")
        else:
            config = {}
        
        # Add new configuration sections
        config = self._add_trust_store_config(config)
        config = self._add_signature_config(config)
        config = self._add_performance_config(config)
        
        # Save updated config
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print("✓ Configuration updated")
    
    def _add_trust_store_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Add trust store configuration."""
        if 'trust_store' not in config:
            config['trust_store'] = {
                'database_path': './trust_store.db',
                'certificate_cache_size': 1000,
                'revocation_check_enabled': True,
                'ocsp_timeout': 10,
                'crl_cache_duration': 3600,
                'default_trust_level': 'conditional',
                'trusted_roots': [
                    'crypto_analyzer_root_ca',
                    'nist_test_ca'
                ]
            }
        return config
    
    def _add_signature_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Add signature verification configuration."""
        if 'signature_verification' not in config:
            config['signature_verification'] = {
                'enabled': True,
                'require_valid_signatures': False,
                'supported_algorithms': [
                    'rsa_pss_sha256',
                    'ecdsa_sha256',
                    'ed25519',
                    'ml_dsa_44',
                    'ml_dsa_65',
                    'ml_dsa_87',
                    'falcon_512',
                    'falcon_1024'
                ],
                'timestamp_verification': True,
                'certificate_chain_validation': True
            }
        return config
    
    def _add_performance_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Add performance configuration."""
        if 'performance' not in config:
            config['performance'] = {
                'max_file_size': 104857600,  # 100MB
                'analysis_timeout': 30,
                'parallel_workers': 4,
                'cache_enabled': True,
                'cache_ttl': 3600
            }
        return config

# Run configuration migration
if __name__ == "__main__":
    migrator = ConfigMigrator()
    migrator.migrate_config()
```

### Step 5: Trust Store Initialization

```python
#!/usr/bin/env python3
"""Initialize trust store with default certificates"""

import os
import sys
sys.path.append('.')

from src.trust_store import TrustStore, TrustLevel
from src.certificate_manager import CertificateManager

class TrustStoreInitializer:
    def __init__(self):
        self.trust_store = TrustStore()
        self.cert_manager = CertificateManager(self.trust_store)
    
    def initialize(self):
        """Initialize trust store with default certificates."""
        print("Initializing trust store...")
        
        # Create default root CA
        self._create_root_ca()
        
        # Import NIST test certificates
        self._import_nist_certificates()
        
        # Import existing certificates from old installation
        self._import_legacy_certificates()
        
        print("✓ Trust store initialized")
    
    def _create_root_ca(self):
        """Create default root CA certificate."""
        print("Creating default root CA...")
        
        # Generate root CA certificate (simplified for example)
        root_ca_cert = self._generate_root_ca_certificate()
        
        # Import into trust store
        cert_id = self.cert_manager.import_certificate(
            root_ca_cert,
            trust_level=TrustLevel.ROOT_CA
        )
        
        print(f"✓ Root CA created: {cert_id}")
    
    def _import_nist_certificates(self):
        """Import NIST test certificates."""
        print("Importing NIST test certificates...")
        
        nist_certs_dir = "./certificates/nist"
        if os.path.exists(nist_certs_dir):
            for cert_file in os.listdir(nist_certs_dir):
                if cert_file.endswith('.pem') or cert_file.endswith('.crt'):
                    cert_path = os.path.join(nist_certs_dir, cert_file)
                    
                    with open(cert_path, 'rb') as f:
                        cert_data = f.read()
                    
                    try:
                        cert_id = self.cert_manager.import_certificate(
                            cert_data,
                            trust_level=TrustLevel.TRUSTED
                        )
                        print(f"✓ Imported NIST certificate: {cert_file}")
                    except Exception as e:
                        print(f"✗ Failed to import {cert_file}: {e}")
    
    def _import_legacy_certificates(self):
        """Import certificates from previous installation."""
        print("Importing legacy certificates...")
        
        legacy_cert_dir = "./backup/certificates"
        if os.path.exists(legacy_cert_dir):
            for cert_file in os.listdir(legacy_cert_dir):
                cert_path = os.path.join(legacy_cert_dir, cert_file)
                
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                
                try:
                    cert_id = self.cert_manager.import_certificate(
                        cert_data,
                        trust_level=TrustLevel.CONDITIONAL
                    )
                    print(f"✓ Imported legacy certificate: {cert_file}")
                except Exception as e:
                    print(f"✗ Failed to import {cert_file}: {e}")
    
    def _generate_root_ca_certificate(self) -> bytes:
        """Generate a self-signed root CA certificate."""
        # This is a simplified example - in production, use proper CA generation
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Crypto Analyzer"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Crypto Analyzer Root CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        return cert.public_bytes(serialization.Encoding.PEM)

# Run trust store initialization
if __name__ == "__main__":
    initializer = TrustStoreInitializer()
    initializer.initialize()
```

### Step 6: Service Update

```bash
#!/bin/bash
# Update systemd service configuration

# 1. Update service file
sudo tee /etc/systemd/system/crypto-analyzer.service > /dev/null <<EOF
[Unit]
Description=Crypto Analyzer Service
After=network.target

[Service]
Type=exec
User=crypto-analyzer
Group=crypto-analyzer
WorkingDirectory=/opt/crypto-analyzer
Environment=PATH=/opt/crypto-analyzer/venv/bin
ExecStart=/opt/crypto-analyzer/venv/bin/python src/main.py
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/crypto-analyzer/data

# Resource limits
MemoryMax=1G
CPUQuota=200%

[Install]
WantedBy=multi-user.target
EOF

# 2. Reload systemd and restart service
sudo systemctl daemon-reload
sudo systemctl enable crypto-analyzer
sudo systemctl start crypto-analyzer

# 3. Check service status
sudo systemctl status crypto-analyzer
```

## Post-Migration Verification

### Verification Script

```python
#!/usr/bin/env python3
"""Post-migration verification script"""

import requests
import json
import os
import sys

class MigrationVerifier:
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.errors = []
    
    def verify_migration(self):
        """Run complete migration verification."""
        print("=== Post-Migration Verification ===")
        
        # Test basic functionality
        self._test_health_endpoint()
        self._test_analysis_endpoint()
        self._test_signature_verification()
        self._test_trust_store()
        self._test_database_integrity()
        
        # Report results
        if self.errors:
            print(f"\n❌ Verification failed with {len(self.errors)} errors:")
            for error in self.errors:
                print(f"  - {error}")
            sys.exit(1)
        else:
            print("\n✅ Migration verification successful!")
    
    def _test_health_endpoint(self):
        """Test health endpoint."""
        try:
            response = requests.get(f"{self.base_url}/api/crypto/health")
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'healthy':
                    print("✓ Health endpoint working")
                else:
                    self.errors.append("Health endpoint returned unhealthy status")
            else:
                self.errors.append(f"Health endpoint returned {response.status_code}")
        except Exception as e:
            self.errors.append(f"Health endpoint error: {e}")
    
    def _test_analysis_endpoint(self):
        """Test file analysis endpoint."""
        try:
            # Create test file
            test_data = b"Test encrypted file content"
            files = {'file': ('test.bin', test_data, 'application/octet-stream')}
            
            response = requests.post(
                f"{self.base_url}/api/crypto/analyze",
                files=files
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    print("✓ Analysis endpoint working")
                else:
                    self.errors.append("Analysis endpoint returned error status")
            else:
                self.errors.append(f"Analysis endpoint returned {response.status_code}")
        except Exception as e:
            self.errors.append(f"Analysis endpoint error: {e}")
    
    def _test_signature_verification(self):
        """Test signature verification functionality."""
        try:
            # Test PAM generation with signatures
            pam_config = {
                "type": "sample",
                "include_signatures": True
            }
            
            response = requests.post(
                f"{self.base_url}/api/crypto/generate-pam",
                json=pam_config
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'signatures' in data.get('analysis_result', {}):
                    print("✓ Signature verification working")
                else:
                    print("⚠ Signature verification available but no signatures in test")
            else:
                self.errors.append(f"PAM generation returned {response.status_code}")
        except Exception as e:
            self.errors.append(f"Signature verification test error: {e}")
    
    def _test_trust_store(self):
        """Test trust store functionality."""
        try:
            from src.trust_store import TrustStore
            
            trust_store = TrustStore()
            
            # Test certificate retrieval
            certificates = trust_store.list_certificates()
            if certificates:
                print(f"✓ Trust store working ({len(certificates)} certificates)")
            else:
                print("⚠ Trust store working but no certificates found")
        except Exception as e:
            self.errors.append(f"Trust store test error: {e}")
    
    def _test_database_integrity(self):
        """Test database integrity."""
        try:
            import sqlite3
            
            # Check database file exists
            if not os.path.exists("crypto_analyzer.db"):
                self.errors.append("Database file not found")
                return
            
            # Check database schema
            conn = sqlite3.connect("crypto_analyzer.db")
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            required_tables = [
                'certificates',
                'certificate_chains',
                'revocation_lists',
                'signature_verifications',
                'schema_version'
            ]
            
            missing_tables = [table for table in required_tables if table not in tables]
            if missing_tables:
                self.errors.append(f"Missing database tables: {missing_tables}")
            else:
                print("✓ Database schema updated correctly")
        except Exception as e:
            self.errors.append(f"Database integrity test error: {e}")

# Run verification
if __name__ == "__main__":
    verifier = MigrationVerifier()
    verifier.verify_migration()
```

## Rollback Procedures

### Emergency Rollback

```bash
#!/bin/bash
# Emergency rollback script

echo "=== EMERGENCY ROLLBACK ==="
echo "This will restore the previous version of Crypto Analyzer"
read -p "Are you sure you want to proceed? (yes/no): " confirm

if [[ $confirm != "yes" ]]; then
    echo "Rollback cancelled"
    exit 0
fi

# 1. Stop current service
sudo systemctl stop crypto-analyzer

# 2. Restore code
git checkout v2.0.0  # or previous stable version

# 3. Restore database
if [[ -f "crypto_analyzer.db.backup" ]]; then
    cp crypto_analyzer.db.backup crypto_analyzer.db
    echo "✓ Database restored"
fi

# 4. Restore configuration
if [[ -f "config.json.backup" ]]; then
    cp config.json.backup config.json
    echo "✓ Configuration restored"
fi

# 5. Reinstall dependencies
pip3 install -r requirements.txt

# 6. Restart service
sudo systemctl start crypto-analyzer

# 7. Verify rollback
sleep 5
if curl -f http://localhost:5000/api/crypto/health > /dev/null 2>&1; then
    echo "✅ Rollback successful - service is running"
else
    echo "❌ Rollback failed - service not responding"
fi
```

## Troubleshooting

### Common Migration Issues

#### Issue 1: Database Migration Fails

**Symptoms:**
- Migration script exits with database errors
- Missing table errors in logs

**Solution:**
```bash
# Check database permissions
ls -la crypto_analyzer.db

# Repair database if corrupted
sqlite3 crypto_analyzer.db ".recover" | sqlite3 crypto_analyzer_recovered.db

# Restore from backup and retry
cp crypto_analyzer.db.backup crypto_analyzer.db
python3 migrate_database.py
```

#### Issue 2: Certificate Import Errors

**Symptoms:**
- Trust store initialization fails
- Certificate validation errors

**Solution:**
```bash
# Check certificate file formats
file certificates/*.pem

# Validate certificate syntax
openssl x509 -in certificate.pem -text -noout

# Import certificates manually
python3 -c "
from src.certificate_manager import CertificateManager
from src.trust_store import TrustStore
cm = CertificateManager(TrustStore())
with open('certificate.pem', 'rb') as f:
    cm.import_certificate(f.read())
"
```

#### Issue 3: Performance Degradation

**Symptoms:**
- Slower analysis times after migration
- High memory usage

**Solution:**
```bash
# Check database indexes
sqlite3 crypto_analyzer.db ".schema" | grep INDEX

# Rebuild database statistics
sqlite3 crypto_analyzer.db "ANALYZE;"

# Clear analysis cache
rm -rf cache/*

# Restart with performance monitoring
sudo systemctl restart crypto-analyzer
```

### Migration Validation Checklist

- [ ] All services start successfully
- [ ] Health endpoint returns 200 OK
- [ ] File analysis works with existing files
- [ ] New signature verification features work
- [ ] Trust store contains expected certificates
- [ ] Database schema version is correct
- [ ] Configuration includes new sections
- [ ] Performance is acceptable
- [ ] Logs show no critical errors
- [ ] Backup files are preserved

## Best Practices

### Migration Planning

1. **Schedule Downtime**: Plan migration during low-usage periods
2. **Test Environment**: Perform migration on test environment first
3. **Backup Strategy**: Create multiple backup copies
4. **Rollback Plan**: Prepare and test rollback procedures
5. **Monitoring**: Monitor system health during and after migration

### Security Considerations

1. **Certificate Validation**: Verify all imported certificates
2. **Trust Levels**: Review and adjust certificate trust levels
3. **Access Control**: Update access controls for new features
4. **Audit Logging**: Enable audit logging for trust store operations

### Performance Optimization

1. **Database Tuning**: Optimize database configuration post-migration
2. **Cache Warming**: Pre-populate caches with frequently accessed data
3. **Resource Monitoring**: Monitor CPU, memory, and disk usage
4. **Load Testing**: Perform load testing with new features enabled

This comprehensive migration guide ensures a smooth upgrade to Crypto Analyzer v2.1 with full signature support while maintaining system reliability and security.

