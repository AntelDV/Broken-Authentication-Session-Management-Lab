# WORKFLOW: Entry point của ứng dụng.
# 1. Khởi tạo FastAPI app.
# 2. Gắn CORS và các Middleware (như TimingMiddleware, RateLimitMiddleware).
# 3. Include các Router từ thư mục api/.
from fastapi import FastAPI
from src.config.settings import settings
from src.config.security_config import setup_cors

from src.api.auth_controller import router as auth_router

app = FastAPI(title=settings.APP_NAME)
setup_cors(app)

# Gắn router vào app
app.include_router(auth_router)

@app.get("/")
def health_check():
    return {"status": "running", "current_mode": settings.AUTH_MODE}