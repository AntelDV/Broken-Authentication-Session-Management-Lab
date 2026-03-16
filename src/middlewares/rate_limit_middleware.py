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

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Chỉ kích hoạt khi đang ở bản Vá lỗi (Secure) và là API Đăng nhập
        if request.url.path == "/api/auth/login" and settings.AUTH_MODE == "secure":
            client_ip = request.client.host
            
            # Gọi thuật toán Token Bucket
            if not check_rate_limit(client_ip):
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Too Many Requests. Vượt quá số lần thử, vui lòng đợi."}
                )
        
        # Nếu còn lượt, cho phép Request đi tiếp vào bên trong
        response = await call_next(request)
        return response