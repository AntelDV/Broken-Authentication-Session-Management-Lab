# WORKFLOW: MIDDLEWARE CHẶN BRUTE-FORCE.
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
        if request.url.path == "/api/auth/login" and settings.AUTH_MODE == "secure":
            client_ip = request.client.host
            
            if not check_rate_limit(client_ip):
                # [BLUE TEAM] - GHI LOG LẠI BẰNG CHỨNG TẤN CÔNG
                db = SessionLocal()
                try:
                    log_repo.log_attack(
                        db=db, 
                        ip=client_ip, 
                        attack_type="Brute-force / Rate Limit Exceeded",
                        request_data=f"Target API: {request.url.path}"
                    )
                finally:
                    db.close()

                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Too Many Requests. IP của bạn đã bị ghi log!"}
                )
        
        return await call_next(request)