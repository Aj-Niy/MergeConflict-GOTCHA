import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Settings:
    PROJECT_NAME: str = "GOTCHA Trust Verification Engine"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./scan_results.db")
    
    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    
    # Security / Auth
    JWT_SECRET: str = os.getenv("JWT_SECRET", "gotcha-super-secret-key-change-in-production-2026")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # External APIs
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", os.getenv("OPENAI_API_KEY", os.getenv("XAI_API_KEY", "")))
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1" if not os.getenv("XAI_API_KEY") else "https://api.x.ai/v1")
    LLM_MODEL: str = os.getenv("LLM_MODEL", os.getenv("MODEL_NAME", "gpt-4o-mini" if not os.getenv("XAI_API_KEY") else "grok-4.5"))
    
    # Limits & Constraints
    MAX_FILES: int = int(os.getenv("MAX_FILES", "500"))
    MAX_TOTAL_SIZE_MB: int = int(os.getenv("MAX_TOTAL_SIZE_MB", "50"))
    MAX_FILE_SIZE_KB: int = int(os.getenv("MAX_FILE_SIZE_KB", "1024"))
    
    # Attestation Keys (Ed25519)
    ATTESTATION_PRIVATE_KEY: str = os.getenv("ATTESTATION_PRIVATE_KEY", "")
    ATTESTATION_PUBLIC_KEY: str = os.getenv("ATTESTATION_PUBLIC_KEY", "")
    
    # Observability
    SENTRY_DSN: str = os.getenv("SENTRY_DSN", "")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

settings = Settings()
