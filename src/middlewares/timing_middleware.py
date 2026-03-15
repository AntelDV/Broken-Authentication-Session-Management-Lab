# WORKFLOW: CHỐNG/MÔ PHỎNG TIMING ATTACK[cite: 31, 54, 73].
# CONCEPT:
# Ở mode 'vulnerable': Đo thời gian từ lúc nhận request đến lúc xử lý xong hàm login, in ra log để thấy User tồn tại tốn nhiều ms hơn.
# Ở mode 'secure': Tính toán thời gian xử lý thực, sau đó dùng `time.sleep(độ_trễ_bù_trừ)` để đảm bảo MỌI request đều mất đúng 500ms.
