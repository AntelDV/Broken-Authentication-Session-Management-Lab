# HƯỚNG DẪN ĐO ĐỘ LỆCH THỜI GIAN[cite: 54, 55]:
# Workflow:
# Vòng lặp 1: Gửi 50 request tới tài khoản 'admin' (Có trong DB) -> Tính Average Time 1.
# Vòng lặp 2: Gửi 50 request tới tài khoản 'no_exist' (Không có trong DB) -> Tính Average Time 2.
# Khẳng định lỗ hổng dựa trên Delta = (Time 1 - Time 2).
