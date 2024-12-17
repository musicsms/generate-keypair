# Key Generator Application

A modern, microservice-based application for generating various types of cryptographic keys and passphrases. Built with Streamlit for a user-friendly interface and modular architecture for easy maintenance.

## Features

- **Passphrase Generation**
  - Customizable word count
  - Optional capitalization
  - Custom separators
  - Numbers and special characters

- **RSA Key Generation**
  - Multiple key sizes (2048, 3072, 4096 bits)
  - Optional password protection
  - PEM format output

- **SSH Key Generation**
  - RSA and Ed25519 key types
  - Customizable key sizes for RSA
  - Optional password protection
  - OpenSSH format

- **PGP Key Generation**
  - Multiple key types (RSA, DSA)
  - Customizable key sizes
  - Optional key comments
  - Customizable expiration (0-10 years)
  - Full key management

## Installation

### Local Installation

1. Create a virtual environment:
```bash
python -m venv venv
```

2. Activate the virtual environment:
- On Windows:
```bash
venv\Scripts\activate
```
- On macOS/Linux:
```bash
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Docker Installation

Pull and run the latest Docker image:
```bash
docker pull ghcr.io/musicsms/generate-keypair:latest
docker run -p 8501:8501 ghcr.io/musicsms/generate-keypair:latest
```

Or build locally:
```bash
docker build -t keypair-gen .
docker run -p 8501:8501 keypair-gen
```

## Usage

1. Start the application:
```bash
streamlit run src/frontend/app.py
```

2. Open your web browser and navigate to the URL shown in the terminal (usually http://localhost:8501)

3. Select the type of key you want to generate from the tabs

4. Configure the options according to your needs

5. Click the generate button to create your keys

6. Download your keys using the download buttons or copy them from the display

## Project Structure

```
key-generator/
├── README.md
├── requirements.txt
├── Dockerfile
├── tests/
│   ├── test_ssh_service.py
│   ├── test_pgp_service.py
│   └── test_rsa_service.py
└── src/
    ├── services/
    │   ├── passphrase_service.py
    │   ├── rsa_service.py
    │   ├── ssh_service.py
    │   └── pgp_service.py
    └── frontend/
        ├── app.py
        ├── utils.py
        └── sections/
            ├── ssh_section.py
            ├── pgp_section.py
            ├── rsa_section.py
            └── about_section.py
```

## Development

### Running Tests

Run all tests with coverage:
```bash
pytest tests/ --cov=src
```

Run specific test file:
```bash
pytest tests/test_ssh_service.py
```

### CI/CD Pipeline

The project uses GitHub Actions for:
1. Automated testing on Python 3.8, 3.9, and 3.10
2. Code coverage reporting to Codecov
3. Automatic Docker image building and publishing to GitHub Container Registry

## Security Notes

- Generated keys are not stored permanently
- PGP keys are generated in a temporary directory that is cleaned up after use
- Password-protected keys use strong encryption
- All cryptographic operations use well-tested libraries
- Default key sizes follow current security recommendations (2048 bits minimum)

## Dependencies

- streamlit: Web interface
- cryptography: RSA and Ed25519 key generation
- python-gnupg: PGP key generation
- paramiko: SSH key generation
- pytest: Testing framework
- pytest-cov: Test coverage reporting

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the tests
5. Create a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
