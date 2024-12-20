from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from .routers import passphrase, rsa, ssh, pgp, csr
from .middleware import RateLimitMiddleware

app = FastAPI(
    title="Secure Key Generator API",
    description="RESTful API for generating various types of cryptographic keys and certificates",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware)

# Include routers
app.include_router(passphrase.router, prefix="/api/v1/passphrase", tags=["passphrase"])
app.include_router(rsa.router, prefix="/api/v1/rsa", tags=["rsa"])
app.include_router(ssh.router, prefix="/api/v1/ssh", tags=["ssh"])
app.include_router(pgp.router, prefix="/api/v1/pgp", tags=["pgp"])
app.include_router(csr.router, prefix="/api/v1/csr", tags=["csr"])

# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secure Key Generator API",
        version="1.0.0",
        description="RESTful API for generating various types of cryptographic keys and certificates",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
