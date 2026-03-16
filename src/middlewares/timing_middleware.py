# WORKFLOW: CHỐNG/MÔ PHỎNG TIMING ATTACK.
# CONCEPT:
# Ở mode 'vulnerable': Đo thời gian từ lúc nhận request đến lúc xử lý xong hàm login, in ra log để thấy User tồn tại tốn nhiều ms hơn.
# Ở mode 'secure': Tính toán thời gian xử lý thực, sau đó dùng `time.sleep(độ_trễ_bù_trừ)` để đảm bảo MỌI request đều mất đúng 500ms.

import time
import asyncio
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from src.config.settings import settings

# Độ trễ mục tiêu 
TARGET_RESPONSE_TIME = 0.5

class TimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/api/auth/login":
            start_time = time.time()
            
            # Cho Request chạy vào Controller xử lý bình thường
            response = await call_next(request)
            
            process_time = time.time() - start_time
            
            if settings.AUTH_MODE == "secure":
                # Bù trừ thời gian sao cho tổng thời gian luôn bằng TARGET_RESPONSE_TIME
                delay = TARGET_RESPONSE_TIME - process_time
                if delay > 0:
                    await asyncio.sleep(delay)
            else:
                #  Cố tình in ra Terminal để nhóm bạn dễ quay video demo lỗi
                print(f"[TIMING LEAK] Thời gian xử lý: {process_time:.4f} giây")
                
            return response
            
        return await call_next(request)