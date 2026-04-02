import time
import threading
import psutil
import requests

URL = "http://127.0.0.1:8000/api/auth/login"
NUM_REQUESTS = 300 # Số lượng request ném vào Server
cpu_logs = []
is_running = True

def monitor_cpu():
    """Hàm chạy ngầm để đo CPU mỗi 0.5 giây"""
    global is_running
    while is_running:
        # Lấy % CPU sử dụng
        cpu_logs.append(psutil.cpu_percent(interval=0.5))

def send_requests():
    """Hàm bắn request liên tục (Cố tình nhập sai pass để Server phải băm lại từ đầu)"""
    for i in range(NUM_REQUESTS):
        # Dùng Header giả để không bị Rate Limit chặn 
        headers = {"X-Forwarded-For": f"10.0.1.{i % 250}"}
        requests.post(URL, json={"username": "victim_1", "password": "wrong_password"}, headers=headers)

if __name__ == "__main__":
    print(f"🚀 BẮT ĐẦU ĐO TẢI CPU ({NUM_REQUESTS} REQUESTS) 🚀")
    
    # Khởi động luồng đo CPU
    t = threading.Thread(target=monitor_cpu)
    t.start()

    start_time = time.time()
    send_requests() # Bắt đầu nã đạn
    end_time = time.time()

    # Dừng đo CPU
    is_running = False
    t.join()

    # Thống kê
    avg_cpu = sum(cpu_logs) / len(cpu_logs) if cpu_logs else 0
    total_time = end_time - start_time
    
    print("-" * 40)
    print(f"⏱️ Tổng thời gian hoàn thành: {total_time:.2f} giây")
    print(f"🔥 Mức ngốn CPU trung bình:  {avg_cpu:.2f}%")
    print(f"⚡ Tốc độ xử lý:             {NUM_REQUESTS/total_time:.2f} request/giây")
    print("-" * 40)
