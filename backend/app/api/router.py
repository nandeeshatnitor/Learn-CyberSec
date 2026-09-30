from fastapi import APIRouter

from app.api.routes import cves, health, research, sources

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(cves.router)
api_router.include_router(research.router)
api_router.include_router(sources.router)
