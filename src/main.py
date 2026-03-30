import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

from src.config.settings import settings
from src.config.security_config import setup_cors
from src.api.auth_controller import router as auth_router
from src.api.admin_controller import router as admin_router
from src.middlewares.timing_middleware import TimingMiddleware
from src.middlewares.rate_limit_middleware import RateLimitMiddleware

app = FastAPI(title=settings.APP_NAME)

# Cấu hình CORS
setup_cors(app)

# Middleware 
app.add_middleware(RateLimitMiddleware)
app.add_middleware(TimingMiddleware)

# Gắn API Router
app.include_router(auth_router)
app.include_router(admin_router)

@app.get("/api/health", tags=["System"])
def health_check():
    return {"status": "running", "current_mode": settings.AUTH_MODE}

# File Static
frontend_path = os.path.join(os.getcwd(), "frontend")

# Gắn thư mục css và js
app.mount("/css", StaticFiles(directory=os.path.join(frontend_path, "css")), name="css")
app.mount("/js", StaticFiles(directory=os.path.join(frontend_path, "js")), name="js")

# Định tuyến cho các trang HTML
@app.get("/", include_in_schema=False)
async def read_index():
    from fastapi.responses import FileResponse
    return FileResponse(os.path.join(frontend_path, "index.html"))

@app.get("/dashboard.html", include_in_schema=False)
async def read_dashboard():
    from fastapi.responses import FileResponse
    return FileResponse(os.path.join(frontend_path, "dashboard.html"))