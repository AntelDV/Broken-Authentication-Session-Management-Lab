from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os

from src.config.settings import settings
from src.config.security_config import setup_cors
from src.api.auth_controller import router as auth_router

from src.middlewares.timing_middleware import TimingMiddleware
from src.middlewares.rate_limit_middleware import RateLimitMiddleware

from src.api.admin_controller import router as admin_router

app = FastAPI(title=settings.APP_NAME)
setup_cors(app)

# Gắn Middleware
app.add_middleware(RateLimitMiddleware)
app.add_middleware(TimingMiddleware)

# Gắn API Router
app.include_router(auth_router)
app.include_router(admin_router)

# Dịch chuyển API kiểm tra sức khỏe hệ thống sang đường dẫn khác
@app.get("/api/health")
def health_check():
    return {"status": "running", "current_mode": settings.AUTH_MODE}

# Xác định đường dẫn tới thư mục frontend 
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

# Gắn toàn bộ thư mục frontend vào đường dẫn /app
app.mount("/app", StaticFiles(directory=frontend_path, html=True), name="frontend")

# Khi truy cập link gốc (http://127.0.0.1:8000), tự động chuyển hướng vào giao diện
@app.get("/")
def root():
    return RedirectResponse(url="/app/index.html")