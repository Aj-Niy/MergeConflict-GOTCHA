import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.db.base import Base
from app.db.session import engine
from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.batches import router as batches_router
from app.api.policies import router as policies_router
from app.api.attestations import router as attestations_router

# Initialize database schema
Base.metadata.create_all(bind=engine)

# Structured logger
logger = structlog.get_logger()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="GOTCHA Repository Trust Verification & Semantic Security Audit Platform"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(scans_router, prefix=settings.API_V1_STR)
app.include_router(batches_router, prefix=settings.API_V1_STR)
app.include_router(policies_router, prefix=settings.API_V1_STR)
app.include_router(attestations_router, prefix=settings.API_V1_STR)

# Also mount legacy direct paths without /api prefix for backward compatibility
app.include_router(scans_router)
app.include_router(batches_router)
app.include_router(policies_router)
app.include_router(attestations_router)

@app.get("/")
def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "docs_url": "/docs"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }
