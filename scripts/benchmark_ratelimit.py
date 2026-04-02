import requests
import time

URL = "http://127.0.0.1:8000/api/auth/login"

def run_rate_limit_test():
    print("🛡️ BẮT ĐẦU TEST HIỆU QUẢ RATE LIMIT (TRONG 10 GIÂY) 🛡️")
    print("Dữ liệu này dùng để vẽ biểu đồ đường Line Chart trong báo cáo:")
    print("=" * 45)
    print(" Giây thứ | Cho phép lọt (Req) | Bị chặn lại (Req) ")
    print("-" * 45)

    for second in range(1, 11):
        allowed = 0
        blocked = 0
        
        # Trong 1 giây, hacker cố tình gửi dồn dập 15 requests
        for _ in range(15): 
            # Không xài fake IP để ép Rate Limit phải hoạt động
            res = requests.post(URL, json={"username": "victim_1", "password": "123"})
            if res.status_code == 429:
                blocked += 1
            else:
                allowed += 1
                
        print(f"    {second:02d}    |        {allowed:02d}          |        {blocked:02d} ")
        time.sleep(1) # Nghỉ 1 giây để quan sát cơ chế "Hồi token" của Token Bucket
        
    print("=" * 45)

if __name__ == "__main__":
    run_rate_limit_test()