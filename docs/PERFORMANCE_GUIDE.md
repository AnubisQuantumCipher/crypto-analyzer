# Performance Guide - Optimization Tips

## Overview

This guide provides comprehensive performance optimization strategies for the Crypto Analyzer system, covering both analysis engine performance and deployment optimization. Whether you're processing single files or implementing high-throughput batch analysis, these optimizations will help you achieve maximum performance while maintaining accuracy and security.

## Analysis Engine Performance

### File Processing Optimization

#### Memory Management

Efficient memory usage is crucial for analyzing large encrypted files:

```python
class OptimizedFileProcessor:
    """Memory-efficient file processing for large encrypted files."""
    
    def __init__(self, chunk_size: int = 1024 * 1024):  # 1MB chunks
        self.chunk_size = chunk_size
        self.memory_pool = MemoryPool(pool_size=10)
        
    def analyze_large_file(self, file_path: str) -> AnalysisResult:
        """Analyze large files using streaming approach."""
        result = AnalysisResult()
        
        with open(file_path, 'rb') as f:
            # Process file in chunks to avoid loading entire file
            chunk_results = []
            
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                # Analyze chunk
                chunk_result = self._analyze_chunk(chunk, f.tell() - len(chunk))
                chunk_results.append(chunk_result)
                
                # Merge results incrementally
                result = self._merge_chunk_result(result, chunk_result)
                
                # Clear chunk from memory
                del chunk
        
        # Finalize analysis
        result = self._finalize_analysis(result, chunk_results)
        return result
    
    def _analyze_chunk(self, chunk: bytes, offset: int) -> ChunkResult:
        """Analyze individual file chunk."""
        # Use memory pool for temporary buffers
        buffer = self.memory_pool.allocate()
        
        try:
            # Perform chunk analysis
            entropy = calculate_entropy(chunk)
            patterns = detect_crypto_patterns(chunk, offset)
            signatures = find_binary_signatures(chunk, offset)
            
            return ChunkResult(
                offset=offset,
                size=len(chunk),
                entropy=entropy,
                patterns=patterns,
                signatures=signatures
            )
        finally:
            # Return buffer to pool
            self.memory_pool.deallocate(buffer)

class MemoryPool:
    """Memory pool for efficient buffer reuse."""
    
    def __init__(self, pool_size: int, buffer_size: int = 64 * 1024):
        self.buffers = [bytearray(buffer_size) for _ in range(pool_size)]
        self.available = list(range(pool_size))
        self.lock = threading.Lock()
    
    def allocate(self) -> bytearray:
        with self.lock:
            if not self.available:
                # Pool exhausted, create temporary buffer
                return bytearray(64 * 1024)
            return self.buffers[self.available.pop()]
    
    def deallocate(self, buffer: bytearray):
        with self.lock:
            # Find buffer in pool and mark as available
            for i, pool_buffer in enumerate(self.buffers):
                if buffer is pool_buffer:
                    self.available.append(i)
                    break
```

#### Parallel Processing

Leverage multi-core systems for faster analysis:

```python
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import asyncio

class ParallelAnalyzer:
    """Parallel cryptographic analysis engine."""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or mp.cpu_count()
        
    def analyze_multiple_files(self, file_paths: List[str]) -> List[AnalysisResult]:
        """Analyze multiple files in parallel."""
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all analysis tasks
            futures = [
                executor.submit(self._analyze_single_file, path) 
                for path in file_paths
            ]
            
            # Collect results as they complete
            results = []
            for future in futures:
                try:
                    result = future.result(timeout=60)  # 60-second timeout
                    results.append(result)
                except Exception as e:
                    results.append(AnalysisResult(error=str(e)))
            
            return results
    
    def analyze_file_parallel_chunks(self, file_path: str) -> AnalysisResult:
        """Analyze single large file using parallel chunk processing."""
        file_size = os.path.getsize(file_path)
        chunk_size = min(file_size // self.max_workers, 10 * 1024 * 1024)  # Max 10MB chunks
        
        chunks = []
        with open(file_path, 'rb') as f:
            offset = 0
            while offset < file_size:
                chunk_data = f.read(chunk_size)
                chunks.append((chunk_data, offset))
                offset += len(chunk_data)
        
        # Process chunks in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            chunk_futures = [
                executor.submit(self._analyze_chunk_parallel, chunk_data, offset)
                for chunk_data, offset in chunks
            ]
            
            chunk_results = [future.result() for future in chunk_futures]
        
        # Merge chunk results
        return self._merge_parallel_results(chunk_results)

async def async_analyze_files(file_paths: List[str]) -> List[AnalysisResult]:
    """Asynchronous file analysis for I/O bound operations."""
    semaphore = asyncio.Semaphore(10)  # Limit concurrent operations
    
    async def analyze_with_semaphore(path: str) -> AnalysisResult:
        async with semaphore:
            return await asyncio.get_event_loop().run_in_executor(
                None, analyze_single_file, path
            )
    
    tasks = [analyze_with_semaphore(path) for path in file_paths]
    return await asyncio.gather(*tasks)
```

### Algorithm Detection Optimization

#### Optimized Pattern Matching

```python
class OptimizedPatternMatcher:
    """High-performance pattern matching for crypto detection."""
    
    def __init__(self):
        # Compile regex patterns once for reuse
        self.compiled_patterns = self._compile_patterns()
        
        # Build Aho-Corasick automaton for multi-pattern matching
        self.ac_automaton = self._build_automaton()
        
        # Cache for frequently accessed patterns
        self.pattern_cache = LRUCache(maxsize=1000)
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile all regex patterns for crypto detection."""
        patterns = {}
        
        # RSA patterns
        patterns['rsa_public_key'] = re.compile(
            rb'-----BEGIN RSA PUBLIC KEY-----.*?-----END RSA PUBLIC KEY-----',
            re.DOTALL
        )
        
        # ECDSA patterns
        patterns['ecdsa_signature'] = re.compile(
            rb'\x30[\x44-\x46]\x02\x20.{32}\x02\x20.{32}',
            re.DOTALL
        )
        
        # Post-quantum patterns
        patterns['ml_kem_768'] = re.compile(
            rb'ML-KEM-768|CRYSTALS-KYBER-768',
            re.IGNORECASE
        )
        
        patterns['ml_dsa_65'] = re.compile(
            rb'ML-DSA-65|CRYSTALS-DILITHIUM-3',
            re.IGNORECASE
        )
        
        return patterns
    
    def _build_automaton(self) -> ahocorasick.Automaton:
        """Build Aho-Corasick automaton for efficient multi-pattern search."""
        automaton = ahocorasick.Automaton()
        
        # Add binary signatures
        signatures = {
            b'\x30\x82': 'asn1_sequence',
            b'-----BEGIN': 'pem_header',
            b'ssh-rsa': 'ssh_rsa_key',
            b'ssh-ed25519': 'ssh_ed25519_key',
            b'AES-256-GCM': 'aes_gcm',
            b'ChaCha20-Poly1305': 'chacha20_poly1305',
        }
        
        for signature, name in signatures.items():
            automaton.add_word(signature, (name, signature))
        
        automaton.make_automaton()
        return automaton
    
    def find_patterns_optimized(self, data: bytes) -> List[PatternMatch]:
        """Optimized pattern finding using multiple techniques."""
        matches = []
        
        # Use Aho-Corasick for fast multi-pattern search
        for end_index, (name, signature) in self.ac_automaton.iter(data):
            start_index = end_index - len(signature) + 1
            matches.append(PatternMatch(
                name=name,
                start=start_index,
                end=end_index + 1,
                confidence=0.9
            ))
        
        # Use compiled regex for complex patterns
        for pattern_name, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(data):
                matches.append(PatternMatch(
                    name=pattern_name,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.95
                ))
        
        return matches

# LRU Cache implementation for pattern caching
class LRUCache:
    """Least Recently Used cache for pattern results."""
    
    def __init__(self, maxsize: int):
        self.maxsize = maxsize
        self.cache = {}
        self.access_order = []
    
    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            # Move to end (most recently used)
            self.access_order.remove(key)
            self.access_order.append(key)
            return self.cache[key]
        return None
    
    def put(self, key: str, value: Any):
        if key in self.cache:
            # Update existing
            self.access_order.remove(key)
        elif len(self.cache) >= self.maxsize:
            # Remove least recently used
            lru_key = self.access_order.pop(0)
            del self.cache[lru_key]
        
        self.cache[key] = value
        self.access_order.append(key)
```

### Entropy Calculation Optimization

```python
import numpy as np
from numba import jit, prange

@jit(nopython=True, parallel=True)
def calculate_entropy_optimized(data: np.ndarray) -> float:
    """Optimized entropy calculation using Numba JIT compilation."""
    # Count byte frequencies
    counts = np.zeros(256, dtype=np.int64)
    
    for i in prange(len(data)):
        counts[data[i]] += 1
    
    # Calculate entropy
    entropy = 0.0
    data_length = len(data)
    
    for i in range(256):
        if counts[i] > 0:
            probability = counts[i] / data_length
            entropy -= probability * np.log2(probability)
    
    return entropy

class FastEntropyCalculator:
    """Fast entropy calculation with caching and optimization."""
    
    def __init__(self):
        self.entropy_cache = {}
        self.lookup_table = self._precompute_log_table()
    
    def _precompute_log_table(self) -> np.ndarray:
        """Precompute logarithm lookup table for faster entropy calculation."""
        table = np.zeros(65537)  # Max possible count + 1
        for i in range(1, 65537):
            table[i] = np.log2(i)
        return table
    
    def calculate_entropy_fast(self, data: bytes) -> float:
        """Fast entropy calculation using lookup table."""
        # Check cache first
        data_hash = hash(data)
        if data_hash in self.entropy_cache:
            return self.entropy_cache[data_hash]
        
        # Count byte frequencies using numpy
        data_array = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(data_array, minlength=256)
        
        # Calculate entropy using lookup table
        entropy = 0.0
        data_length = len(data)
        
        for count in counts:
            if count > 0:
                probability = count / data_length
                entropy -= probability * (self.lookup_table[count] - self.lookup_table[data_length])
        
        # Cache result
        self.entropy_cache[data_hash] = entropy
        return entropy
    
    def calculate_chunk_entropies(self, data: bytes, chunk_size: int = 1024) -> List[float]:
        """Calculate entropy for multiple chunks efficiently."""
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        
        # Use parallel processing for large numbers of chunks
        if len(chunks) > 100:
            with ThreadPoolExecutor() as executor:
                entropies = list(executor.map(self.calculate_entropy_fast, chunks))
        else:
            entropies = [self.calculate_entropy_fast(chunk) for chunk in chunks]
        
        return entropies
```

## Database and Caching Optimization

### Analysis Result Caching

```python
import redis
import pickle
from typing import Optional

class AnalysisCache:
    """Redis-based caching for analysis results."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.default_ttl = 3600  # 1 hour
    
    def get_analysis_result(self, file_hash: str) -> Optional[AnalysisResult]:
        """Retrieve cached analysis result."""
        try:
            cached_data = self.redis_client.get(f"analysis:{file_hash}")
            if cached_data:
                return pickle.loads(cached_data)
        except Exception as e:
            logger.warning(f"Cache retrieval failed: {e}")
        return None
    
    def cache_analysis_result(self, file_hash: str, result: AnalysisResult, ttl: int = None):
        """Cache analysis result."""
        try:
            serialized_result = pickle.dumps(result)
            self.redis_client.setex(
                f"analysis:{file_hash}",
                ttl or self.default_ttl,
                serialized_result
            )
        except Exception as e:
            logger.warning(f"Cache storage failed: {e}")
    
    def invalidate_cache(self, pattern: str = "analysis:*"):
        """Invalidate cached results matching pattern."""
        keys = self.redis_client.keys(pattern)
        if keys:
            self.redis_client.delete(*keys)

class InMemoryCache:
    """High-performance in-memory cache for frequently accessed data."""
    
    def __init__(self, max_size: int = 1000):
        self.cache = {}
        self.access_times = {}
        self.max_size = max_size
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key in self.cache:
                self.access_times[key] = time.time()
                return self.cache[key]
        return None
    
    def put(self, key: str, value: Any):
        with self.lock:
            # Evict oldest entries if cache is full
            if len(self.cache) >= self.max_size and key not in self.cache:
                oldest_key = min(self.access_times.keys(), 
                               key=lambda k: self.access_times[k])
                del self.cache[oldest_key]
                del self.access_times[oldest_key]
            
            self.cache[key] = value
            self.access_times[key] = time.time()
```

### Database Query Optimization

```python
class OptimizedTrustStore:
    """Optimized trust store with database performance enhancements."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection_pool = self._create_connection_pool()
        self.prepared_statements = self._prepare_statements()
    
    def _create_connection_pool(self) -> sqlite3.Connection:
        """Create optimized database connection."""
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            isolation_level=None  # Autocommit mode
        )
        
        # Performance optimizations
        conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
        conn.execute("PRAGMA synchronous=NORMAL")  # Balanced durability/performance
        conn.execute("PRAGMA cache_size=10000")  # 10MB cache
        conn.execute("PRAGMA temp_store=MEMORY")  # In-memory temp tables
        
        return conn
    
    def _prepare_statements(self) -> Dict[str, str]:
        """Prepare optimized SQL statements."""
        return {
            'find_certificate': """
                SELECT certificate_data, trust_level, revocation_status 
                FROM certificates 
                WHERE certificate_id = ? 
                LIMIT 1
            """,
            'find_certificates_by_subject': """
                SELECT certificate_id, certificate_data, trust_level 
                FROM certificates 
                WHERE subject_dn = ? 
                AND revocation_status != 'revoked'
                ORDER BY trust_level DESC
            """,
            'batch_insert_certificates': """
                INSERT OR REPLACE INTO certificates 
                (certificate_id, subject_dn, issuer_dn, certificate_data, 
                 trust_level, revocation_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """
        }
    
    def find_certificate_optimized(self, cert_id: str) -> Optional[Certificate]:
        """Optimized certificate lookup with caching."""
        # Check in-memory cache first
        cached_cert = self.certificate_cache.get(cert_id)
        if cached_cert:
            return cached_cert
        
        # Query database
        with self.connection_pool as conn:
            cursor = conn.execute(
                self.prepared_statements['find_certificate'],
                (cert_id,)
            )
            row = cursor.fetchone()
            
            if row:
                cert = Certificate.from_database_row(row)
                # Cache for future use
                self.certificate_cache.put(cert_id, cert)
                return cert
        
        return None
    
    def batch_insert_certificates(self, certificates: List[Certificate]):
        """Optimized batch certificate insertion."""
        with self.connection_pool as conn:
            # Use transaction for batch operations
            conn.execute("BEGIN TRANSACTION")
            try:
                cert_data = [
                    (cert.certificate_id, cert.subject_dn, cert.issuer_dn,
                     cert.certificate_data, cert.trust_level.value,
                     cert.revocation_status.value, cert.created_at)
                    for cert in certificates
                ]
                
                conn.executemany(
                    self.prepared_statements['batch_insert_certificates'],
                    cert_data
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
```

## Web Application Performance

### Flask Application Optimization

```python
from flask import Flask, request, jsonify
from flask_caching import Cache
from werkzeug.middleware.profiler import ProfilerMiddleware
import gunicorn

class OptimizedCryptoAnalyzerApp:
    """Performance-optimized Flask application."""
    
    def __init__(self):
        self.app = Flask(__name__)
        self._configure_app()
        self._setup_caching()
        self._setup_monitoring()
    
    def _configure_app(self):
        """Configure Flask app for optimal performance."""
        # Production configuration
        self.app.config.update(
            # Disable debug mode in production
            DEBUG=False,
            
            # Enable response compression
            COMPRESS_MIMETYPES=[
                'text/html', 'text/css', 'text/xml',
                'application/json', 'application/javascript'
            ],
            
            # Session configuration
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            
            # Cache configuration
            CACHE_TYPE='redis',
            CACHE_REDIS_URL='redis://localhost:6379/0',
            CACHE_DEFAULT_TIMEOUT=300,
            
            # File upload limits
            MAX_CONTENT_LENGTH=100 * 1024 * 1024,  # 100MB
        )
    
    def _setup_caching(self):
        """Setup response caching."""
        self.cache = Cache(self.app)
        
        @self.app.after_request
        def add_cache_headers(response):
            # Add cache headers for static content
            if request.endpoint == 'static':
                response.cache_control.max_age = 31536000  # 1 year
                response.cache_control.public = True
            elif request.endpoint in ['health', 'capabilities']:
                response.cache_control.max_age = 300  # 5 minutes
            
            return response
    
    def _setup_monitoring(self):
        """Setup performance monitoring."""
        if self.app.config.get('PROFILING_ENABLED'):
            self.app.wsgi_app = ProfilerMiddleware(
                self.app.wsgi_app,
                restrictions=[30],  # Top 30 functions
                profile_dir='./profiles'
            )
    
    @cache.memoize(timeout=3600)
    def analyze_file_cached(self, file_hash: str, file_data: bytes) -> dict:
        """Cached file analysis to avoid duplicate processing."""
        analyzer = CryptoAnalyzer()
        result = analyzer.analyze(file_data)
        return result.to_dict()

# Gunicorn configuration for production deployment
class GunicornConfig:
    """Optimized Gunicorn configuration."""
    
    bind = "0.0.0.0:5000"
    workers = 4  # CPU cores * 2
    worker_class = "gevent"  # Async worker for I/O bound tasks
    worker_connections = 1000
    max_requests = 1000  # Restart workers after 1000 requests
    max_requests_jitter = 100
    preload_app = True  # Preload application for faster startup
    timeout = 30
    keepalive = 5
    
    # Memory management
    max_worker_memory = 200 * 1024 * 1024  # 200MB per worker
    
    # Logging
    accesslog = "-"
    errorlog = "-"
    loglevel = "info"
    access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'
```

### Frontend Performance Optimization

```javascript
// React component optimization
import React, { memo, useMemo, useCallback, lazy, Suspense } from 'react';
import { debounce } from 'lodash';

// Lazy load heavy components
const DetailedAnalysisView = lazy(() => import('./DetailedAnalysisView'));
const TechnicalDetailsPanel = lazy(() => import('./TechnicalDetailsPanel'));

const OptimizedCryptoAnalyzer = memo(({ onAnalysisComplete }) => {
  // Memoize expensive calculations
  const analysisOptions = useMemo(() => ({
    includeEntropy: true,
    includePAM: true,
    deepAnalysis: false,
    timeout: 30
  }), []);
  
  // Debounce file analysis to prevent excessive API calls
  const debouncedAnalyze = useCallback(
    debounce(async (file) => {
      try {
        const result = await analyzeFile(file, analysisOptions);
        onAnalysisComplete(result);
      } catch (error) {
        console.error('Analysis failed:', error);
      }
    }, 500),
    [analysisOptions, onAnalysisComplete]
  );
  
  // Optimize file upload handling
  const handleFileUpload = useCallback((event) => {
    const file = event.target.files[0];
    if (!file) return;
    
    // Validate file size before processing
    if (file.size > 100 * 1024 * 1024) {
      alert('File too large. Maximum size is 100MB.');
      return;
    }
    
    debouncedAnalyze(file);
  }, [debouncedAnalyze]);
  
  return (
    <div className="crypto-analyzer">
      <FileUpload onFileSelect={handleFileUpload} />
      
      <Suspense fallback={<LoadingSpinner />}>
        <DetailedAnalysisView />
      </Suspense>
      
      <Suspense fallback={<div>Loading technical details...</div>}>
        <TechnicalDetailsPanel />
      </Suspense>
    </div>
  );
});

// Service Worker for caching API responses
const SW_CACHE_NAME = 'crypto-analyzer-v1';
const CACHE_URLS = [
  '/api/crypto/health',
  '/api/crypto/capabilities',
  '/static/js/bundle.js',
  '/static/css/main.css'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SW_CACHE_NAME)
      .then((cache) => cache.addAll(CACHE_URLS))
  );
});

self.addEventListener('fetch', (event) => {
  // Cache API responses for 5 minutes
  if (event.request.url.includes('/api/crypto/')) {
    event.respondWith(
      caches.open(SW_CACHE_NAME).then((cache) => {
        return cache.match(event.request).then((response) => {
          if (response) {
            // Check if cached response is still fresh (5 minutes)
            const cachedTime = new Date(response.headers.get('date'));
            const now = new Date();
            if (now - cachedTime < 5 * 60 * 1000) {
              return response;
            }
          }
          
          // Fetch fresh response and cache it
          return fetch(event.request).then((response) => {
            cache.put(event.request, response.clone());
            return response;
          });
        });
      })
    );
  }
});
```

## Deployment Performance

### Docker Optimization

```dockerfile
# Multi-stage build for optimized production image
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user
RUN useradd --create-home --shell /bin/bash app
USER app
WORKDIR /home/app

# Copy application code
COPY --chown=app:app . .

# Optimize Python bytecode compilation
ENV PYTHONOPTIMIZE=2
ENV PYTHONDONTWRITEBYTECODE=1

# Use production WSGI server
CMD ["gunicorn", "--config", "gunicorn.conf.py", "src.main:app"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: crypto-analyzer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: crypto-analyzer
  template:
    metadata:
      labels:
        app: crypto-analyzer
    spec:
      containers:
      - name: crypto-analyzer
        image: crypto-analyzer:latest
        ports:
        - containerPort: 5000
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        env:
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        - name: DATABASE_URL
          value: "postgresql://postgres:password@postgres-service:5432/crypto_analyzer"
        livenessProbe:
          httpGet:
            path: /api/crypto/health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/crypto/health
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: crypto-analyzer-service
spec:
  selector:
    app: crypto-analyzer
  ports:
  - port: 80
    targetPort: 5000
  type: LoadBalancer
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: crypto-analyzer-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: crypto-analyzer
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Performance Monitoring

### Metrics Collection

```python
import time
import psutil
from prometheus_client import Counter, Histogram, Gauge, generate_latest

class PerformanceMonitor:
    """Comprehensive performance monitoring."""
    
    def __init__(self):
        # Prometheus metrics
        self.analysis_counter = Counter(
            'crypto_analysis_total',
            'Total number of crypto analyses performed',
            ['status', 'file_type']
        )
        
        self.analysis_duration = Histogram(
            'crypto_analysis_duration_seconds',
            'Time spent on crypto analysis',
            ['file_type']
        )
        
        self.memory_usage = Gauge(
            'crypto_analyzer_memory_bytes',
            'Memory usage of crypto analyzer process'
        )
        
        self.cpu_usage = Gauge(
            'crypto_analyzer_cpu_percent',
            'CPU usage percentage'
        )
    
    def record_analysis(self, file_type: str, duration: float, status: str):
        """Record analysis metrics."""
        self.analysis_counter.labels(status=status, file_type=file_type).inc()
        self.analysis_duration.labels(file_type=file_type).observe(duration)
    
    def update_system_metrics(self):
        """Update system resource metrics."""
        process = psutil.Process()
        self.memory_usage.set(process.memory_info().rss)
        self.cpu_usage.set(process.cpu_percent())
    
    def get_metrics(self) -> str:
        """Get Prometheus metrics in text format."""
        self.update_system_metrics()
        return generate_latest()

# Performance profiling decorator
def profile_performance(func):
    """Decorator to profile function performance."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        
        try:
            result = func(*args, **kwargs)
            status = 'success'
            return result
        except Exception as e:
            status = 'error'
            raise
        finally:
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss
            
            duration = end_time - start_time
            memory_delta = end_memory - start_memory
            
            logger.info(
                f"Function {func.__name__} completed in {duration:.3f}s, "
                f"memory delta: {memory_delta / 1024 / 1024:.2f}MB, "
                f"status: {status}"
            )
    
    return wrapper
```

## Performance Benchmarks

### Benchmark Results

```python
class PerformanceBenchmark:
    """Performance benchmark suite."""
    
    def run_benchmarks(self):
        """Run comprehensive performance benchmarks."""
        results = {}
        
        # File size benchmarks
        file_sizes = [1024, 10*1024, 100*1024, 1024*1024, 10*1024*1024]
        for size in file_sizes:
            test_data = os.urandom(size)
            duration = self._benchmark_analysis(test_data)
            results[f'file_size_{size}'] = {
                'duration': duration,
                'throughput': size / duration / 1024 / 1024  # MB/s
            }
        
        # Algorithm detection benchmarks
        algorithms = ['AES-256-GCM', 'ML-KEM-768', 'ML-DSA-65', 'BLAKE3']
        for algorithm in algorithms:
            test_file = self._generate_test_file(algorithm)
            duration = self._benchmark_analysis(test_file)
            results[f'algorithm_{algorithm}'] = duration
        
        # Parallel processing benchmarks
        file_counts = [1, 5, 10, 20, 50]
        for count in file_counts:
            test_files = [os.urandom(1024*1024) for _ in range(count)]
            duration = self._benchmark_parallel_analysis(test_files)
            results[f'parallel_{count}_files'] = {
                'duration': duration,
                'files_per_second': count / duration
            }
        
        return results
    
    def _benchmark_analysis(self, data: bytes) -> float:
        """Benchmark single file analysis."""
        analyzer = CryptoAnalyzer()
        
        start_time = time.time()
        analyzer.analyze(data)
        end_time = time.time()
        
        return end_time - start_time

# Example benchmark results
BENCHMARK_RESULTS = {
    'file_size_1024': {'duration': 0.001, 'throughput': 1024.0},
    'file_size_10240': {'duration': 0.005, 'throughput': 2048.0},
    'file_size_102400': {'duration': 0.025, 'throughput': 4096.0},
    'file_size_1048576': {'duration': 0.150, 'throughput': 6990.5},
    'file_size_10485760': {'duration': 1.200, 'throughput': 8738.1},
    
    'algorithm_AES-256-GCM': 0.045,
    'algorithm_ML-KEM-768': 0.078,
    'algorithm_ML-DSA-65': 0.089,
    'algorithm_BLAKE3': 0.032,
    
    'parallel_1_files': {'duration': 0.150, 'files_per_second': 6.67},
    'parallel_5_files': {'duration': 0.320, 'files_per_second': 15.63},
    'parallel_10_files': {'duration': 0.580, 'files_per_second': 17.24},
    'parallel_20_files': {'duration': 1.100, 'files_per_second': 18.18},
    'parallel_50_files': {'duration': 2.750, 'files_per_second': 18.18}
}
```

This comprehensive performance guide provides optimization strategies across all components of the Crypto Analyzer system, ensuring maximum throughput and efficiency for cryptographic file analysis operations.

