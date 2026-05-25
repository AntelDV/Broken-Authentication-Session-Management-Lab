# HOẠT ĐỘNG:
# 1. Chặn ngay Request trước khi nó kịp chạm tới Controller.
# 2. Trích xuất IP của Client.
# 3. Gọi thuật toán Token Bucket (từ src/security/rate_limit.py) để kiểm tra IP này còn lượt (token) không.
# 4. Nếu hết -> Ném thẳng lỗi HTTP 429 Too Many Requests. Nếu còn -> Trừ 1 token và cho đi tiếp.

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from src.config.settings import settings
from src.security.rate_limit import check_rate_limit
from src.config.database import SessionLocal
from src.repositories.log_repository import LogRepository

log_repo = LogRepository()

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if settings.AUTH_MODE == "secure":
            protected_paths = ["/api/auth/login", "/api/auth/mfa/verify", "/api/auth/sso/google", "/api/auth/password/forgot"]
            if request.url.path in protected_paths:
                client_ip = request.client.host
                if not check_rate_limit(client_ip):
                    db = SessionLocal()
                    try:
                        log_repo.log_attack(db=db, ip=client_ip, attack_type="Rate Limit Triggered", request_data=request.url.path)
                    finally:
                        db.close()
                    return JSONResponse(status_code=429, content={"detail": "Too Many Requests. IP đã bị ghi log!"})
        
        return await call_next(request)