# Vòng lặp 1: Gửi 50 request tới tài khoản 'admin' (Có trong DB) -> Tính Average Time 1.
# Vòng lặp 2: Gửi 50 request tới tài khoản 'no_exist' (Không có trong DB) -> Tính Average Time 2.
# Khẳng định lỗ hổng dựa trên Delta = (Time 1 - Time 2).

import requests
import time

URL = "http://127.0.0.1:8000/api/auth/login"
NUM_REQUESTS = 20

def measure_time(username, password):
    times = []
    for _ in range(NUM_REQUESTS):
        start = time.time()
        requests.post(URL, json={"username": username, "password": password})
        # Ghi nhận thời gian phản hồi của từng request
        times.append(time.time() - start)
    # Trả về thời gian trung bình
    return sum(times) / len(times)

def run_attack():
    print("⏱️ BẮT ĐẦU ĐO TIMING ATTACK ⏱️\n")
    
    # Đo tài khoản đã tạo 
    print(f"Đang gửi {NUM_REQUESTS} requests cho tài khoản thật...")
    time_exist = measure_time("duong_test", "wrong_password")
    
    # Đo tài khoản chưa tạo
    print(f"Đang gửi {NUM_REQUESTS} requests cho tài khoản giả...")
    time_not_exist = measure_time("ghost_user", "wrong_password")
    
    print("\n📊 KẾT QUẢ ĐO ĐẠC:")
    print(f"- Thời gian phản hồi User TỒN TẠI:      {time_exist:.4f} giây")
    print(f"- Thời gian phản hồi User KHÔNG TỒN TẠI: {time_not_exist:.4f} giây")
    
    delta = abs(time_exist - time_not_exist)
    print(f"\n=> ĐỘ LỆCH THỜI GIAN (Delta): {delta:.4f} giây")
    
    if delta > 0.003: 
        print("🚨 KẾT LUẬN: HỆ THỐNG CÓ LỖ HỔNG TIMING ATTACK!")
    else:
        print("🛡️ KẾT LUẬN: HỆ THỐNG AN TOÀN!")

if __name__ == "__main__":
    run_attack()