# HƯỚNG DẪN CREDENTIAL STUFFING BẰNG AIOHTTP[cite: 58, 59]:
# Workflow: Đọc list 10k tài khoản -> asyncio.gather() để bắn 100 request/giây vào endpoint /login.
# Mục đích: Đánh sập Server hoặc thu hoạch các account dùng chung mật khẩu.
