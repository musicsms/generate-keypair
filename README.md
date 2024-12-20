# Key Generator Application

[![Unit Tests](https://github.com/${{ github.repository }}/actions/workflows/unit-tests.yml/badge.svg?branch=dev)](https://github.com/${{ github.repository }}/actions/workflows/unit-tests.yml)
[![API Tests](https://github.com/${{ github.repository }}/actions/workflows/api-tests.yml/badge.svg?branch=dev)](https://github.com/${{ github.repository }}/actions/workflows/api-tests.yml)
[![Code Quality](https://github.com/${{ github.repository }}/actions/workflows/code-quality.yml/badge.svg?branch=dev)](https://github.com/${{ github.repository }}/actions/workflows/code-quality.yml)
[![Security Scan](https://github.com/${{ github.repository }}/actions/workflows/security.yml/badge.svg?branch=dev)](https://github.com/${{ github.repository }}/actions/workflows/security.yml)
[![Docker Build](https://github.com/${{ github.repository }}/actions/workflows/docker-build.yml/badge.svg?branch=dev)](https://github.com/${{ github.repository }}/actions/workflows/docker-build.yml)
[![codecov](https://codecov.io/gh/${{ github.repository }}/branch/dev/graph/badge.svg)](https://codecov.io/gh/${{ github.repository }})

A modern, secure API and web application for generating various types of cryptographic keys and passphrases. Built with FastAPI for the backend API and Streamlit for the user interface, featuring a modular architecture for easy maintenance and extensibility.

## Features

- **Passphrase Generation**
  - Customizable length and count
  - Character type selection (uppercase, lowercase, digits, special)
  - Character exclusion support
  - Uniqueness verification

- **RSA Key Generation**
  - Multiple key sizes (2048, 3072, 4096 bits)
  - Optional password protection
  - PEM format output
  - Configurable public exponent

- **SSH Key Generation**
  - RSA and Ed25519 key types
  - Customizable key sizes for RSA
  - Optional password protection
  - OpenSSH format
  - Custom key comments

- **PGP Key Generation**
  - RSA key support
  - Customizable key sizes
  - Optional key comments
  - Customizable expiration
  - Email and name attributes

- **CSR (Certificate Signing Request) Generation**
  - Support for various fields (CN, O, OU, etc.)
  - Multiple key sizes
  - Optional password protection
  - PEM format output

## Installation

### Prerequisites
- Python 3.12 or higher
- pip package manager
- Virtual environment (recommended)

### Local Installation

1. Clone the repository:
```bash
git clone https://github.com/${{ github.repository }}.git
cd ${{ github.repository }}
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:
- On Windows:
```bash
venv\Scripts\activate
```
- On macOS/Linux:
```bash
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

### Docker Installation

Pull and run the latest Docker image:
```bash
docker pull ghcr.io/${{ github.repository }}:latest
docker run -p 8000:8000 -p 8501:8501 ghcr.io/${{ github.repository }}:latest
```

Or build locally:
```bash
docker build -t keypair-gen .
docker run -p 8000:8000 -p 8501:8501 keypair-gen
```

## Usage

### Starting the Application

1. Start the API server:
```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

2. Start the web interface:
```bash
streamlit run src/frontend/app.py
```

3. Access the applications:
   - Web Interface: http://localhost:8501
   - API Documentation: http://localhost:8000/docs
   - Alternative API Documentation: http://localhost:8000/redoc

### API Rate Limits
- 100 requests per minute per IP address
- Rate limit headers included in responses
- Automatic cooldown period after limit reached

## Project Structure

```
generate-keypair/
├── README.md
├── requirements.txt
├── Dockerfile
├── docs/
│   └── test_report.md
├── tests/
│   ├── api/
│   │   ├── test_csr.py
│   │   ├── test_passphrase.py
│   │   ├── test_pgp.py
│   │   ├── test_rsa.py
│   │   └── test_ssh.py
│   ├── rate_limit/
│   │   └── test_rate_limit.py
│   ├── test_csr_service.py
│   ├── test_passphrase_service.py
│   ├── test_pgp_service.py
│   ├── test_rsa_service.py
│   └── test_ssh_service.py
└── src/
    ├── api/
    │   ├── main.py
    │   ├── middleware.py
    │   └── routers/
    │       ├── csr.py
    │       ├── passphrase.py
    │       ├── pgp.py
    │       ├── rsa.py
    │       └── ssh.py
    ├── services/
    │   ├── csr_service.py
    │   ├── passphrase_service.py
    │   ├── pgp_service.py
    │   ├── rsa_service.py
    │   └── ssh_service.py
    └── frontend/
        ├── app.py
        └── sections/
            ├── csr_section.py
            ├── passphrase_section.py
            ├── pgp_section.py
            ├── rsa_section.py
            └── ssh_section.py
```

## CI/CD Workflows

The project uses GitHub Actions for continuous integration and deployment:

### Unit Tests
- Runs all unit tests
- Enforces 85% minimum code coverage
- Excludes API and integration tests
- Triggered on code changes in `src/` and `tests/`

### API Tests
- Tests all API endpoints
- Enforces 90% coverage for API code
- Includes rate limiting and error handling tests
- Triggered on changes in `src/api/` and `tests/api/`

### Code Quality
- Checks code formatting with Black
- Lints code with Flake8
- Performs type checking with MyPy
- Triggered on any Python file changes

### Security Scan
- Weekly security scans with Bandit
- Dependency vulnerability checks
- Generates security reports
- Runs on all PRs and weekly

### Docker Build
- Builds multi-arch Docker images
- Publishes to GitHub Container Registry
- Creates versioned and latest tags
- Triggered on main branch pushes and tags

## Test Coverage

Current test coverage statistics:
- Overall Coverage: 89%
- API Coverage: 92%
- Unit Test Coverage: 87%
- Integration Test Coverage: 85%

View detailed coverage reports on [Codecov](https://codecov.io/gh/${{ github.repository }}).

## Development

### Running Tests

Run all tests with coverage:
```bash
pytest --cov=src --cov-report=term-missing
```

Run specific test file:
```bash
pytest tests/api/test_passphrase.py -v
```

View test report:
```bash
cat docs/test_report.md
```

### Current Test Coverage
- Overall Coverage: 89%
- Total Tests: 86
- Pass Rate: 100%
- See `docs/test_report.md` for detailed analysis

## Dependencies

### Core Dependencies
- fastapi>=0.68.0: API framework
- uvicorn>=0.15.0: ASGI server
- streamlit==1.41.1: Web interface
- pydantic>=1.8.0: Data validation
- email-validator>=2.1.0: Email validation

### Cryptographic Libraries
- cryptography==44.0.0: Core cryptographic operations
- python-gnupg==0.5.3: PGP key generation
- paramiko==3.5.0: SSH key generation
- pyopenssl==24.3.0: SSL/TLS toolkit

### Testing
- pytest==8.3.4: Testing framework
- pytest-cov==6.0.0: Coverage reporting

## Security Features

- Rate limiting per IP address
- Input validation and sanitization
- Secure key generation defaults
- No permanent key storage
- Temporary file cleanup
- Password encryption for protected keys
- CORS protection
- Well-tested cryptographic libraries

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the test suite
5. Create a pull request

See `docs/test_report.md` for current test coverage and areas needing improvement.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
