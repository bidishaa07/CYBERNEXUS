from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.db.session import Base, engine, run_migrations
from backend.app.models.models import Scan, CommunityReport
from backend.app.api.routes import router

Base.metadata.create_all(bind=engine)
run_migrations()
app = FastAPI(title="Digital Trust Intelligence", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router, prefix="/api")
