"""Production FastAPI ASGI entrypoint for Vercel Serverless & Uvicorn.

Exports the top-level `app` variable for Vercel Zero-Configuration Python deployments.
"""
from app import app

__all__ = ["app"]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
