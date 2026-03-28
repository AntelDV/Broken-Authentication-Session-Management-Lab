document.getElementById('loginForm').addEventListener('submit', async function(event) {
    // Ngăn chặn việc form tự động load lại trang khi bấm submit
    event.preventDefault();

    const usernameInput = document.getElementById('username').value;
    const passwordInput = document.getElementById('password').value;
    const messageBox = document.getElementById('messageBox');
    const loginBtn = document.getElementById('loginBtn');

    // Reset giao diện hộp thoại
    messageBox.className = 'message hidden';
    messageBox.textContent = '';
    loginBtn.textContent = 'Đang xử lý...';
    loginBtn.disabled = true;

    try {
        // Bắn API xuống Backend
        const response = await fetch('http://127.0.0.1:8000/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({
                username: usernameInput,
                password: passwordInput
            })
        });

        // Phân tích dữ liệu JSON trả về
        const data = await response.json();

        // Xử lý hiển thị dựa trên HTTP Status Code
        if (response.ok) { // Status 200
            messageBox.className = 'message success';
            messageBox.textContent = data.message;
            
            // Xử lý lưu trữ dựa trên Chế độ (Vulnerable / Secure)
            if (data.session_id !== "[Đã được bảo mật trong HttpOnly Cookie]") {
                // Chế độ VULNERABLE: Lưu hớ hênh ở localStorage
                localStorage.setItem('auth_session_id', data.session_id);
            } else {
                // Chế độ SECURE: Xóa sạch localStorage. 
                // Trình duyệt đã tự động giữ Cookie HttpOnly ngầm bên dưới.
                localStorage.removeItem('auth_session_id');
            }
            
            localStorage.setItem('auth_role', data.role);
            localStorage.setItem('auth_username', usernameInput);
            
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1000);
            
        } else { // Nhận các lỗi 401, 404, 429...
            messageBox.className = 'message error';
            messageBox.textContent = data.detail || 'Có lỗi xảy ra từ máy chủ.';
        }
    } catch (error) {
        // Lỗi này xảy ra khi Backend chưa bật (chưa chạy uvicorn)
        messageBox.className = 'message error';
        messageBox.textContent = 'Không thể kết nối đến Máy chủ (Server Offline).';
    } finally {
        loginBtn.textContent = 'Đăng nhập';
        loginBtn.disabled = false;
    }
});