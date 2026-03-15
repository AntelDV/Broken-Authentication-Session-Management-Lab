# WORKFLOW: MIDDLEWARE CHẶN BRUTE-FORCE[cite: 75].
# HOẠT ĐỘNG:
# 1. Chặn ngay Request trước khi nó kịp chạm tới Controller.
# 2. Trích xuất IP của Client.
# 3. Gọi thuật toán Token Bucket (từ src/security/rate_limit.py) để kiểm tra IP này còn lượt (token) không.
# 4. Nếu hết -> Ném thẳng lỗi HTTP 429 Too Many Requests. Nếu còn -> Trừ 1 token và cho đi tiếp.
