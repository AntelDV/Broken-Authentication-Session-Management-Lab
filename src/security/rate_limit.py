# WORKFLOW: THUẬT TOÁN TOKEN BUCKET
# CONCEPT: Một biến Dictionary/Redis lưu trữ { "IP_123": { "tokens": 5, "last_refill": timestamp } }
# Hàm check_rate_limit(ip): Tính toán số token hiện tại dựa trên thời gian trôi qua, cập nhật và trả về True/False.
import time
from typing import Dict

class TokenBucket:
    def __init__(self, capacity: int, refill_time_sec: float):
        self.capacity = capacity
        self.refill_time_sec = refill_time_sec  # Thời gian cần để hồi 1 token
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self) -> bool:
        now = time.time()
        time_passed = now - self.last_refill
        
        # Tính số token được phục hồi dựa trên thời gian trôi qua
        refill_amount = int(time_passed / self.refill_time_sec)
        
        if refill_amount > 0:
            # Hồi token nhưng không được vượt quá sức chứa (capacity)
            self.tokens = min(self.capacity, self.tokens + refill_amount)
            self.last_refill = now
        
        # Nếu còn token thì trừ đi 1 và cho phép đi tiếp
        if self.tokens >= 1:
            self.tokens -= 1
            return True
            
        # Hết token -> Chặn
        return False

# Biến toàn cục lưu trữ rổ token của từng IP
ip_buckets: Dict[str, TokenBucket] = {}

def check_rate_limit(ip: str) -> bool:
    """Kiểm tra giới hạn. Mỗi IP có 5 token, cứ 2 giây sẽ hồi 1 token."""
    if ip not in ip_buckets:
        ip_buckets[ip] = TokenBucket(capacity=5, refill_time_sec=2.0)
    
    return ip_buckets[ip].consume()