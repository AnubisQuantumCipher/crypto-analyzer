# Crypto Analyzer: Comprehensive Cryptographic Technology Detection

**Crypto Analyzer** is a powerful and comprehensive tool designed to analyze encrypted files and identify the full stack of cryptographic technologies they contain. It implements the "Public Algorithm Manifest" (PAM) concept, making encryption technologies "loud" and immediately visible to analysts, security researchers, and developers.

This tool provides a detailed breakdown of all cryptographic components, including encryption algorithms, hash functions, digital signatures, key exchange mechanisms, and post-quantum cryptography. It is an essential utility for anyone working with encrypted data who needs to understand the underlying security architecture.

## Key Features

- **Public Algorithm Manifest (PAM) Detection:** Automatically detects and parses PAM headers in encrypted files, providing a clear and structured view of the cryptographic stack.
- **Comprehensive Technology Detection:** Identifies a wide range of cryptographic technologies, including:
  - **Post-Quantum Cryptography:** ML-KEM, ML-DSA, Kyber, Dilithium, SPHINCS+, FALCON
  - **Symmetric Encryption:** AES, ChaCha20, Twofish, Serpent, and various cipher modes (GCM, CBC, CTR)
  - **Asymmetric Encryption:** RSA, ECDSA, Ed25519, X25519, and elliptic curves (P-256, Curve25519)
  - **Hash Functions:** SHA-2, SHA-3, BLAKE3, Argon2, scrypt, and more
  - **Protocols & Standards:** TLS, SSH, OpenPGP, S/MIME, JOSE, and FIPS/NIST standards
- **Advanced File Analysis:** Performs entropy analysis, binary signature scanning, and ASN.1 structure detection to identify cryptographic patterns even without a PAM.
- **Interactive Web Interface:** A user-friendly web UI for uploading files, viewing analysis reports, and generating sample encrypted files with custom PAMs.
- **PAM Generation:** Includes a tool for creating "loud" encrypted files with detailed PAM headers, perfect for testing and demonstration purposes.
- **Extensible Architecture:** The modular design allows for easy extension with new detection modules for emerging cryptographic technologies.

## How It Works

The Crypto Analyzer operates in two main modes:

1. **PAM-based Analysis:** If a file contains a Public Algorithm Manifest, the analyzer parses this structured metadata to provide a precise and detailed report of all cryptographic technologies used.

2. **Heuristic Analysis:** For files without a PAM, the analyzer uses a multi-faceted approach to detect cryptographic technologies:
   - **Entropy Analysis:** Measures the randomness of the file to determine the likelihood of encryption.
   - **Pattern Matching:** Scans for known text-based signatures of cryptographic algorithms and libraries.
   - **Binary Signature Detection:** Identifies binary patterns and OIDs (Object Identifiers) associated with specific cryptographic functions.
   - **ASN.1 Structure Parsing:** Detects ASN.1 sequences, which are common in digital certificates and signatures.

## Getting Started

### Prerequisites

- Python 3.9+
- Flask
- cbor2
- Node.js and pnpm (for frontend development)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AnubisQuantumCipher/crypto-analyzer.git
   cd crypto-analyzer
   ```

2. **Set up the backend:**
   ```bash
   cd crypto-analyzer-api
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install cbor2 werkzeug
   ```

3. **Set up the frontend:**
   ```bash
   cd ../crypto-analyzer-frontend
   pnpm install
   ```

### Running the Application

1. **Start the backend server:**
   ```bash
   cd ../crypto-analyzer-api
   source venv/bin/activate
   python src/main.py
   ```

2. **Start the frontend development server:**
   ```bash
   cd ../crypto-analyzer-frontend
   pnpm run dev
   ```

3. **Access the application:**
   Open your browser and navigate to `http://localhost:5173`.

## Usage

### Analyzing a File

1. Drag and drop an encrypted file onto the upload area or use the "Browse Files" button.
2. Click the "Analyze" button to start the analysis.
3. The results will be displayed in a comprehensive report, including a security overview, detected technologies, and technical details.

### Generating a Sample File

- Click "Generate Sample File" to create a standard encrypted file with a PAM.
- Click "Generate Comprehensive Test" to create a file that includes a wide range of cryptographic technologies for testing purposes.

## Command-Line Tools

The project also includes command-line tools for advanced users:

- **`crypto_analyzer.py`:** Analyze a file and output a JSON report.
  ```bash
  python crypto_analyzer.py <file_path>
  ```

- **`pam_generator.py`:** Create sample encrypted files with PAM headers.
  ```bash
  python pam_generator.py create-comprehensive my_test_file.qs
  ```

- **`crypto_detectors.py`:** Run detailed detection modules on a file.
  ```bash
  python crypto_detectors.py <file_path>
  ```

## Project Structure

- **`crypto-analyzer-api/`:** The Flask backend, containing the analysis engine and API endpoints.
- **`crypto-analyzer-frontend/`:** The React frontend, providing the user interface.
- **`crypto_analyzer.py`:** The core cryptographic analysis engine.
- **`crypto_detectors.py`:** Specialized modules for detecting various crypto technologies.
- **`pam_generator.py`:** Tool for generating files with Public Algorithm Manifests.

## Contributing

Contributions are welcome! If you would like to add new detection modules, improve the analysis engine, or enhance the user interface, please feel free to submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.


