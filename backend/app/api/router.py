from fastapi import APIRouter

from app.api.routes import admin_labs, cves, health, learning, research, sandbox, sources

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(cves.router)
api_router.include_router(research.router)
api_router.include_router(learning.router)
api_router.include_router(sandbox.router)
api_router.include_router(sandbox.public_router)
api_router.include_router(sources.router)
api_router.include_router(admin_labs.router)
