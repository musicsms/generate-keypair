from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
import time
import logging
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

class RateLimitMiddleware(BaseHTTPMiddleware):
    _instance = None
    _request_history: Dict[str, Tuple[int, float]] = {}

    def __init__(self, app, requests_per_minute: int = 100):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.time_window = 60  # seconds
        RateLimitMiddleware._instance = self

    @classmethod
    def reset_state(cls):
        """Reset the rate limit state"""
        cls._request_history.clear()
        logger.debug("Rate limit state reset")

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Get client IP from headers or request
        client_ip = request.headers.get("X-Test-IP") or request.client.host
        
        current_time = time.time()
        
        # Clean up old entries
        RateLimitMiddleware._request_history = {
            ip: (count, timestamp) 
            for ip, (count, timestamp) in RateLimitMiddleware._request_history.items()
            if current_time - timestamp < self.time_window
        }
        
        # Get current count and timestamp for this IP
        count, timestamp = RateLimitMiddleware._request_history.get(client_ip, (0, current_time))
        
        # Reset count if outside time window
        if current_time - timestamp >= self.time_window:
            count = 0
            timestamp = current_time
        
        # Increment request count
        count += 1
        RateLimitMiddleware._request_history[client_ip] = (count, timestamp)
        
        # Check if rate limit exceeded
        if count > self.requests_per_minute:
            logger.warning(f"Rate limit exceeded for IP {client_ip}: {count} requests")
            response = Response(
                content='{"detail": "Rate limit exceeded. Please try again later."}',
                status_code=429,
                media_type="application/json"
            )
            self._add_rate_limit_headers(response, count)
            return response
        
        # Process the request
        response = await call_next(request)
        
        # Add rate limit headers
        self._add_rate_limit_headers(response, count)
        return response

    def _add_rate_limit_headers(self, response: Response, current_count: int):
        """Add rate limit headers to response"""
        response.headers['X-RateLimit-Limit'] = str(self.requests_per_minute)
        response.headers['X-RateLimit-Remaining'] = str(max(0, self.requests_per_minute - current_count))
        response.headers['X-RateLimit-Reset'] = str(int(time.time() + self.time_window))
