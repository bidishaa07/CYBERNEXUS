from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.db.session import Base, engine, run_migrations
from backend.app.models.models import Scan, CommunityReport
from backend.app.api.routes import router
from backend.app.core.config import settings

Base.metadata.create_all(bind=engine)
run_migrations()
app = FastAPI(title="Digital Trust Intelligence", version="0.1.0")
allowed_origins = list({settings.public_app_url, "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:3000"})
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=True, allow_methods=["GET", "POST", "DELETE", "OPTIONS"], allow_headers=["Authorization", "Content-Type", "X-User-ID", "X-Admin-Token"])
app.include_router(router, prefix="/api")
