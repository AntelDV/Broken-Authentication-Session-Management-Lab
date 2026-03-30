// --- XỬ LÝ NÚT GẠT THEME VÀ ĐỒNG BỘ UI ---
const modeToggle = document.getElementById('modeToggle');
const modeLabel = document.getElementById('modeLabel');
const body = document.body;

// Hàm đồng bộ Theme từ LocalStorage
function syncTheme() {
    const savedMode = localStorage.getItem('ui_mode') || 'vulnerable';
    if (savedMode === 'secure') {
        body.classList.add('theme-secure');
        if (modeToggle) modeToggle.checked = true;
        if (modeLabel) modeLabel.textContent = "🛡️ SECURE MODE";
        
        const dashLabel = document.getElementById('modeLabelDashboard');
        if (dashLabel) dashLabel.textContent = "🛡️ SECURE MODE";
        
        const vulnPanels = document.querySelectorAll('.panel-vuln');
        vulnPanels.forEach(panel => panel.classList.add('hidden'));
        
    } else {
        body.classList.remove('theme-secure');
        if (modeToggle) modeToggle.checked = false;
        if (modeLabel) modeLabel.textContent = "VULNERABLE ";
        
        const dashLabel = document.getElementById('modeLabelDashboard');
        if (dashLabel) dashLabel.textContent = "VULNERABLE";
        
        // HIỆN LẠI PANEL Ở MODE VULN
        const vulnPanels = document.querySelectorAll('.panel-vuln');
        vulnPanels.forEach(panel => panel.classList.remove('hidden'));
    }
}

// Bắt sự kiện khi gạt cần
if (modeToggle) {
    modeToggle.addEventListener('change', function() {
        if (this.checked) {
            localStorage.setItem('ui_mode', 'secure');
        } else {
            localStorage.setItem('ui_mode', 'vulnerable');
        }
        syncTheme();
    });
}

// Chạy đồng bộ lúc mới load trang
syncTheme();


// --- XỬ LÝ FORM LOGIN ---
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const rememberMe = document.getElementById('rememberMe').checked;
        
        await executeAuth('http://127.0.0.1:8000/api/auth/login', {
            username: username,
            password: password,
            remember_me: rememberMe
        });
    });
}

// --- XỬ LÝ NÚT LOGIN SSO ---
const ssoBtn = document.getElementById('ssoBtn');
if (ssoBtn) {
    ssoBtn.addEventListener('click', async function() {
        const email = document.getElementById('username').value;
        if(!email.includes('@')) {
            alert("Vui lòng nhập Email!");
            return;
        }

        showMessage("Đang xin cấp Token từ Google ...", "success");
        try {
            // Lấy Token từ "Google"
            const googleRes = await fetch(`http://127.0.0.1:8000/api/auth/mock-google-token/${email}`);
            const googleData = await googleRes.json();
            const token = googleData.google_id_token;

            //  Bắn Token xuống Backend
            await executeAuth('http://127.0.0.1:8000/api/auth/sso/google', {
                email: email, 
                google_id_token: token
            });
        } catch (e) {
            showMessage("Lỗi kết nối SSO!", "error");
        }
    });
}

// --- HÀM GỌI API CHUNG ---
async function executeAuth(url, payload) {
    const messageBox = document.getElementById('messageBox');
    const loginBtn = document.getElementById('loginBtn');
    
    showMessage("Đang xử lý...", "success");
    if(loginBtn) loginBtn.disabled = true;

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (response.ok) {
            showMessage(data.message, "success");
            
            // Xử lý MFA
            if(data.require_mfa) {
                const otp = prompt(`[MFA REQUIRED] Vui lòng nhập mã 6 số cho tài khoản ${data.temp_token}:`);
                if(otp) {
                    await executeAuth('http://127.0.0.1:8000/api/auth/mfa/verify', {
                        username: data.temp_token,
                        otp_token: otp
                    });
                } else { showMessage("Đã hủy nhập MFA", "error"); }
                return;
            }

            // Lưu trữ thông tin
            localStorage.setItem('auth_username', payload.username || payload.email);
            localStorage.setItem('auth_role', data.role);
            
            // Xử lý dữ liệu 
            localStorage.setItem('auth_session', data.session_id || 'HttpOnly Protected');
            
            // Ghi đè chữ để dễ nhìn
            if(data.remember_cookie && data.remember_cookie.includes('Bảo mật')) {
                 localStorage.setItem('auth_remember', '[Bảo mật: Chuỗi ngẫu nhiên]');
            } else {
                 localStorage.setItem('auth_remember', data.remember_cookie || 'null');
            }
            
            if (data.access_token) {
                localStorage.setItem('auth_jwt', data.access_token);
            }

            // Chuyển sang Dashboard
            setTimeout(() => { window.location.href = 'dashboard.html'; }, 800);
            
        } else {
            showMessage(data.detail || 'Lỗi đăng nhập', "error");
        }
    } catch (error) {
        showMessage('Không thể kết nối đến Máy chủ.', "error");
    } finally {
        if(loginBtn) loginBtn.disabled = false;
    }
}

function showMessage(msg, type) {
    const box = document.getElementById('messageBox');
    if(!box) return;
    box.className = `message ${type}`;
    box.textContent = msg;
    box.classList.remove('hidden');
}

// --- LOGIC TRANG DASHBOARD ---
function loadDashboardData() {
    const username = localStorage.getItem('auth_username');
    const role = localStorage.getItem('auth_role');
    
    if (!username) { window.location.href = 'index.html'; return; }

    // Gọi sync theme lại lần nữa để ẩn panel
    syncTheme();

    document.getElementById('welcomeMsg').innerHTML = `Xin chào <b>${username}</b>! Quyền: <b>[ ${role.toUpperCase()} ]</b>`;
    document.getElementById('sessionDisplay').textContent = localStorage.getItem('auth_session') || 'null';
    document.getElementById('rememberDisplay').textContent = localStorage.getItem('auth_remember') || 'null';

    const jwt = localStorage.getItem('auth_jwt');
    if (jwt) {
        document.getElementById('jwtRawDisplay').textContent = jwt;
        try {
            const parts = jwt.split('.');
            if(parts.length === 3) {
                const header = JSON.parse(atob(parts[0]));
                const payload = JSON.parse(atob(parts[1]));
                document.getElementById('jwtDecodedDisplay').textContent = 
                    `[HEADER]\n${JSON.stringify(header, null, 2)}\n\n[PAYLOAD]\n${JSON.stringify(payload, null, 2)}`;
            }
        } catch(e) { document.getElementById('jwtDecodedDisplay').textContent = "Lỗi giải mã JWT."; }
    } else { document.getElementById('jwtRawDisplay').textContent = "Không có JWT."; }
}

// --- TEST ADMIN API ---
const testAdminBtn = document.getElementById('testAdminBtn');
if (testAdminBtn) {
    testAdminBtn.addEventListener('click', async function() {
        const token = localStorage.getItem('auth_jwt');
        const box = document.getElementById('adminDataBox');
        box.classList.remove('hidden');
        box.innerHTML = "Đang gọi API...";

        try {
            const res = await fetch('http://127.0.0.1:8000/api/admin/users', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await res.json();
            
            if(res.ok) {
                box.innerHTML = `<b>Thành công!</b><br><pre>${JSON.stringify(data, null, 2)}</pre>`;
                box.style.borderColor = "var(--accent)";
                box.style.color = "var(--accent)";
            } else {
                box.innerHTML = `<b>Thất bại (HTTP ${res.status}):</b><br>${data.detail}`;
                box.style.borderColor = "var(--error-text)";
                box.style.color = "var(--error-text)";
            }
        } catch(e) { box.innerHTML = "Lỗi kết nối!"; }
    });
}

const logoutBtn = document.getElementById('logoutBtn');
if(logoutBtn) {
    logoutBtn.addEventListener('click', () => {
        localStorage.clear();
        window.location.href = 'index.html';
    });
}