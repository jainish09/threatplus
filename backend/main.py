import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from routes.reports import router as reports_router
from routes.cache import router as cache_router
from routes.working_set import router as working_set_router
from routes.random_read import router as random_read_router
from routes.new_reports import router as new_reports_router
from routes.real_reports import router as real_reports_router
from routes.lab71 import router as lab71_router
from routes.taxonomy import router as taxonomy_router
from routes.live_sync import router as live_sync_router
from routes.ioc import router as ioc_router

from database import get_database


app = FastAPI(
    title="MongoDB Lab 7.1 & 7.2 - Threat Intelligence & WiredTiger SOC Dashboard",
    description=(
        "SOC-grade dashboard and REST API for analyzing "
        "Lab 7.1 Schema ($bsonSize, Embedding vs Referencing) and "
        "Lab 7.2 Working Set & WiredTiger Cache Telemetry with Live VirusTotal & MalwareBazaar Feeds."
    ),
    version="2.1.0"
)


# Enable unrestricted CORS for frontend clients (LiveServer, localhost, 127.0.0.1)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Register existing API routers
app.include_router(reports_router, prefix="/api")
app.include_router(cache_router, prefix="/api")
app.include_router(working_set_router, prefix="/api")
app.include_router(random_read_router, prefix="/api")
app.include_router(new_reports_router, prefix="/api")
app.include_router(real_reports_router, prefix="/api")

# Register Lab 7.1, Taxonomy & Live Feed Sync API routers
app.include_router(lab71_router, prefix="/api")
app.include_router(taxonomy_router, prefix="/api")
app.include_router(live_sync_router, prefix="/api")
app.include_router(ioc_router, prefix="/api")




@app.get("/api/health")
def health_check():
    db = get_database()

    return {
        "status": "online",
        "service": "Threat Intelligence SOC API",
        "mongoConnected": db is not None,
        "wiredTigerCacheMonitoring": "Active"
    }


# Serve frontend static files if present
frontend_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "frontend"
    )
)

if os.path.exists(frontend_dir):
    css_dir = os.path.join(frontend_dir, "css")
    js_dir = os.path.join(frontend_dir, "js")
    if os.path.exists(css_dir):
        app.mount("/css", StaticFiles(directory=css_dir), name="css")
    if os.path.exists(js_dir):
        app.mount("/js", StaticFiles(directory=js_dir), name="js")
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(
            os.path.join(frontend_dir, "index.html")
        )



if __name__ == "__main__":
    import uvicorn
    from config import HOST, PORT

    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=True
    )