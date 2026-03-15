# WORKFLOW: THUẬT TOÁN TOKEN BUCKET
# CONCEPT: Một biến Dictionary/Redis lưu trữ { "IP_123": { "tokens": 5, "last_refill": timestamp } }
# Hàm check_rate_limit(ip): Tính toán số token hiện tại dựa trên thời gian trôi qua, cập nhật và trả về True/False.
