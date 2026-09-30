from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.batches import router as batches_router
from app.api.policies import router as policies_router
from app.api.attestations import router as attestations_router

__all__ = [
    "auth_router",
    "scans_router",
    "batches_router",
    "policies_router",
    "attestations_router"
]
