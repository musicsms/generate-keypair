import pytest
import asyncio
import uuid
from datetime import datetime, timedelta

# Test data for different endpoints
ENDPOINT_TEST_DATA = {
    '/api/v1/csr/generate': {
        'json': {
            'private_key_pem': """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCKvoc+gyRyDYw9
pSiB3lCcJOzGkpuJAwSubManzFMCXb3y2gl+zMY2txRHs19DTs52cjjZ2DVjKVca
g/vljmiQTjrjHfZK56uYvp/WgTJq9lswCUZX09paJ5PQ8kfrmlz0fFp/+xkkCc4Y
huJnJxAfEvwYJ6BhZiO0gLMFdHeVkR2bnuu3M3lH+VBwG94md2EZPspVSrUCeNn+
Se1O61aECbl4W7dBlnAVYMewWatWCoFX6q+jYaRzgzz3kU6RfRBlIYyhjrnnclC+
E4rUjC2XrLI7CLlUvHmFUG+glwruUe5t+lWT1xWM989n3f4Q43rKPVbpdF/h+o5i
NSdTLLojAgMBAAECggEADBym335WUP3oHLzixOI8pOzqSJ7QJM1WfB2d1/8pI0no
r58jeLt1SvMqOjopRPhyY0+vBoFujloJCGpg3pYogFR7+otejq/Ga0lU2HEjOXLe
h1p/7AyKrBfMD8+0F0K8qPvZcKu3HaNyJ5z60xN2FP20yS0IaLL1x1JRjoEvgVHE
B/ylizMdMd7AlGp6BsB5MMKEIXEJApMDqJL2sIdYhqZ4UxTNqSqBamVl+hsdeG3Y
OdsfoM2E8ncbt5Sj72pF5m1xt9avuvKsXxClr41rMe5MkxxSEUbud/SVL/t6Y4Az
GY2oQRqnMds0Dqv+iYYCvo3mXHj44sC9tAmkLr3dhQKBgQC9TDLIPr8z7xGqyd4f
u2KtBgEa6+oa4pmudWpEGWaFJIAqXr1LGYGRHSNWqkSRz3kELYIs/FF1z8PTXri0
tXbDbugOXJZLR4yPgOGcz+Ir0RwCH93Dagf9pTd+y+H+NXAtG2gxXGPXchTG4/ft
ky++LssYaB0PJOonanNhruoMrwKBgQC7ohrz63O9GJeXTuTs5E46JX7eys36iFaD
MDf8R9NrX+U+sktZEt8zqeAhD+/257SbkbJMI+QNI/Fe7ntMFK3FcHDOzqaroUJT
5hDpK1PYPFCakJ274HF7AgUoFPwt7qXX03NXpeUq8iCwmD2u0SEMB1ZuRwWfbe6u
Nql49aEOzQKBgQCPrZlR0gZwVcHUHtqAvUrdRxRpqayL8XhyKV6aB6l/3z+EaVpF
+TsVuMcMzbmz7oTM/fmzSWRPBn59HYUWbDGTjseFtxLAWrM+bLVRv5vMZDBdEHDT
FNSx2cgwbnG+8DKPmiDQbm69pTJN79RLt47iTEQM52E/EGbFug+PkiLFswKBgQCx
TPT7GLo9LUfRipN35iSlfVjtXeZVnw9g1+ePVK/K/sq4+/GHMfYH87X+h/jQ7xIT
DxHUMPYGFLi4Y9HOipvJvf5a7ZtBAxiR/wxryK1p31SrOYxTRDr3aWlF/s5s+N1t
nDmZ0QFEG5gYR0PCNYtsumJJwoLlrBOmO7DYxAJ04QKBgAmsYFBY/svL7kwv0kxw
RH86jned56fVOG0+9GkleGD1Zpi8vSOXpV67wO6HSo4Zq6ty2Ylw5/wcxsUnCR69
2S6Nb317h+AUqKUJKepa2GCyY68NeDfZ2zKwXkT0lrMCCCZRmm2vVaZiUq9V5xL3
4vAAjwL5o5O8+6W9w0y4N7yt
-----END PRIVATE KEY-----""",
            'common_name': 'test.example.com',
            'country': 'US',
            'state': 'California',
            'locality': 'San Francisco',
            'organization': 'Test Corp',
            'organizational_unit': 'IT',
            'email': 'test@example.com',
            'password': None
        }
    },
    '/api/v1/pgp/generate': {
        'json': {
            'name': 'Test User',
            'email': 'test@example.com',
            'key_length': 2048,
            'passphrase': 'strongpassphrase123'
        }
    },
    '/api/v1/rsa/generate': {
        'json': {
            'key_size': 2048,
            'password': None,
            'public_exponent': 65537
        }
    },
    '/api/v1/ssh/generate': {
        'json': {
            'key_type': 'rsa',
            'key_size': 2048,
            'comment': 'test@example.com',
            'password': None
        }
    },
    '/api/v1/passphrase/generate': {
        'json': {
            'length': 16,
            'use_digits': True,
            'use_special': True,
            'use_uppercase': True,
            'use_lowercase': True,
            'excluded_chars': '',
            'count': 1
        }
    }
}

@pytest.mark.rate_limit
class TestRateLimit:
    """Test suite for rate limiting functionality"""

    @pytest.mark.parametrize('endpoint', ENDPOINT_TEST_DATA.keys())
    def test_basic_rate_limit(self, endpoint, make_request, unique_ip, rate_limit_config):
        """Test basic rate limiting behavior for each endpoint"""
        test_data = ENDPOINT_TEST_DATA[endpoint]

        # Make requests up to the limit
        for _ in range(rate_limit_config['requests_per_minute']):
            response = make_request(endpoint, unique_ip, test_data['json'])
            assert response.status_code == 200, f"Request to {endpoint} failed before limit"

        # Next request should be rate limited
        response = make_request(endpoint, unique_ip, test_data['json'])
        assert response.status_code == 429, f"Rate limit not enforced for {endpoint}"
        assert "Rate limit exceeded" in response.json()['detail']

    @pytest.mark.parametrize('endpoint', ENDPOINT_TEST_DATA.keys())
    def test_rate_limit_cooldown(self, endpoint, make_request, unique_ip, rate_limit_config, advance_time):
        """Test rate limit cooldown period"""
        test_data = ENDPOINT_TEST_DATA[endpoint]

        # Make requests up to the limit
        for _ in range(rate_limit_config['requests_per_minute']):
            response = make_request(endpoint, unique_ip, test_data['json'])
            assert response.status_code == 200

        # Verify rate limit is enforced
        response = make_request(endpoint, unique_ip, test_data['json'])
        assert response.status_code == 429

        # Advance time past the cooldown period
        advance_time(rate_limit_config['time_window'])

        # Verify requests are allowed again
        response = make_request(endpoint, unique_ip, test_data['json'])
        assert response.status_code == 200

    def test_ip_isolation(self, make_request, rate_limit_config):
        """Test that rate limits are properly isolated by IP"""
        endpoint = '/api/v1/passphrase/generate'  # Using passphrase endpoint as it's fastest
        test_data = ENDPOINT_TEST_DATA[endpoint]

        # Create two different IPs
        ip1 = f"test-ip-1-{uuid.uuid4()}"
        ip2 = f"test-ip-2-{uuid.uuid4()}"

        # Make requests up to the limit with first IP
        for _ in range(rate_limit_config['requests_per_minute']):
            response = make_request(endpoint, ip1, test_data['json'])
            assert response.status_code == 200

        # Verify first IP is rate limited
        response = make_request(endpoint, ip1, test_data['json'])
        assert response.status_code == 429

        # Verify second IP can still make requests
        for _ in range(rate_limit_config['requests_per_minute']):
            response = make_request(endpoint, ip2, test_data['json'])
            assert response.status_code == 200

    def test_partial_window_reset(self, make_request, unique_ip, rate_limit_config, advance_time):
        """Test rate limit behavior with partial window reset"""
        endpoint = '/api/v1/passphrase/generate'
        test_data = ENDPOINT_TEST_DATA[endpoint]

        # Make half the allowed requests
        for _ in range(rate_limit_config['requests_per_minute'] // 2):
            response = make_request(endpoint, unique_ip, test_data['json'])
            assert response.status_code == 200

        # Advance time by half the window
        advance_time(rate_limit_config['time_window'] // 2)

        # Make remaining requests
        for _ in range(rate_limit_config['requests_per_minute'] // 2):
            response = make_request(endpoint, unique_ip, test_data['json'])
            assert response.status_code == 200

        # Verify rate limit is enforced
        response = make_request(endpoint, unique_ip, test_data['json'])
        assert response.status_code == 429

    @pytest.mark.parametrize('endpoint', ENDPOINT_TEST_DATA.keys())
    def test_rate_limit_headers(self, endpoint, make_request, unique_ip):
        """Test rate limit headers in response"""
        test_data = ENDPOINT_TEST_DATA[endpoint]

        response = make_request(endpoint, unique_ip, test_data['json'])
        assert response.status_code == 200

        # Verify rate limit headers (if implemented)
        # Note: This test may need to be updated based on your header implementation
        headers = response.headers
        if 'X-RateLimit-Limit' in headers:
            assert headers['X-RateLimit-Limit'].isdigit()
            assert headers['X-RateLimit-Remaining'].isdigit()
            assert int(headers['X-RateLimit-Remaining']) >= 0
