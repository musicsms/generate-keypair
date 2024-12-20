# API Documentation

## Overview

The Key Generator API provides endpoints for generating various types of cryptographic keys and passphrases. All endpoints are rate-limited to 100 requests per minute per IP address.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

No authentication is required for API access. Rate limiting is applied based on IP address.

## Rate Limiting

- Limit: 100 requests per minute per IP address
- Headers:
  - `X-RateLimit-Limit`: Maximum requests allowed per window
  - `X-RateLimit-Remaining`: Remaining requests in current window
  - `X-RateLimit-Reset`: Time until rate limit resets (in seconds)

## Endpoints

### Generate Passphrase
`POST /passphrase/generate`

Generate one or more secure passphrases.

**Request Body:**
```json
{
    "length": 16,
    "count": 1,
    "use_digits": true,
    "use_special": true,
    "use_uppercase": true,
    "use_lowercase": true,
    "excluded_chars": ""
}
```

**Response:**
```json
{
    "passphrases": ["generated-passphrase-1", "generated-passphrase-2"]
}
```

### Generate RSA Key
`POST /rsa/generate`

Generate an RSA key pair.

**Request Body:**
```json
{
    "key_size": 2048,
    "password": null,
    "public_exponent": 65537
}
```

**Response:**
```json
{
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### Generate SSH Key
`POST /ssh/generate`

Generate an SSH key pair.

**Request Body:**
```json
{
    "key_type": "rsa",
    "key_size": 2048,
    "comment": "user@example.com",
    "password": null
}
```

**Response:**
```json
{
    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
    "public_key": "ssh-rsa AAAA..."
}
```

### Generate PGP Key
`POST /pgp/generate`

Generate a PGP key pair.

**Request Body:**
```json
{
    "name": "Test User",
    "email": "test@example.com",
    "key_length": 2048,
    "passphrase": "strongpassphrase123",
    "comment": null,
    "expiry_days": null
}
```

**Response:**
```json
{
    "private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n...",
    "public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."
}
```

### Generate CSR
`POST /csr/generate`

Generate a Certificate Signing Request.

**Request Body:**
```json
{
    "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
    "common_name": "example.com",
    "country": "US",
    "state": "California",
    "locality": "San Francisco",
    "organization": "Example Corp",
    "organizational_unit": "IT",
    "email": "admin@example.com",
    "password": null
}
```

**Response:**
```json
{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\n..."
}
```

## Error Responses

All endpoints return standard HTTP status codes:

- `200`: Success
- `400`: Bad Request (invalid input)
- `422`: Validation Error (invalid parameters)
- `429`: Too Many Requests (rate limit exceeded)
- `500`: Internal Server Error

Error Response Format:
```json
{
    "detail": "Error message describing the problem"
}
```

## Examples

### Generate a Password-Protected RSA Key

```bash
curl -X POST "http://localhost:8000/api/v1/rsa/generate" \
     -H "Content-Type: application/json" \
     -d '{
         "key_size": 4096,
         "password": "secure-password",
         "public_exponent": 65537
     }'
```

### Generate Multiple Passphrases

```bash
curl -X POST "http://localhost:8000/api/v1/passphrase/generate" \
     -H "Content-Type: application/json" \
     -d '{
         "length": 20,
         "count": 5,
         "use_digits": true,
         "use_special": true,
         "use_uppercase": true,
         "use_lowercase": true,
         "excluded_chars": "0O1lI"
     }'
```

## Best Practices

1. Always use HTTPS in production
2. Use appropriate key sizes (minimum 2048 bits for RSA)
3. Store generated keys securely
4. Use strong passwords for protected keys
5. Implement proper rate limiting in production
6. Monitor API usage and errors
7. Keep dependencies updated

## Version History

- v1.0.0 (Current)
  - Initial release with key generation endpoints
  - Rate limiting implementation
  - Input validation
  - Error handling
