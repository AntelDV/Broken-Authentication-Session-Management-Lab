// Quan ly dong ho dem nguoc
let timerInterval;

// Thay doi mau sac giao dien theo trang thai bao mat
const modeToggle = document.getElementById("modeToggle");
const modeLabel = document.getElementById("modeLabel");
const body = document.body;

function syncTheme() {
  const savedMode = localStorage.getItem("ui_mode") || "vulnerable";
  if (savedMode === "secure") {
    body.classList.add("theme-secure");
    if (modeToggle) modeToggle.checked = true;
    if (modeLabel)
      modeLabel.innerHTML =
        '<i class="fas fa-shield-check"></i> Chế độ an toàn';
    const statusText = document.getElementById("serverStatusText");
    if (statusText) {
      statusText.textContent = "An toàn";
      statusText.style.color = "#059669";
    }
  } else {
    body.classList.remove("theme-secure");
    if (modeToggle) modeToggle.checked = false;
    if (modeLabel)
      modeLabel.innerHTML =
        '<i class="fas fa-exclamation-triangle"></i> Cảnh báo lỗi';
    const statusText = document.getElementById("serverStatusText");
    if (statusText) {
      statusText.textContent = "Nguy hiểm";
      statusText.style.color = "#e53e3e";
    }
  }
}

// Lang nghe su kien gat nut
if (modeToggle) {
  modeToggle.addEventListener("change", async function () {
    const newMode = this.checked ? "secure" : "vulnerable";
    localStorage.setItem("ui_mode", newMode);
    syncTheme();

    try {
      await fetch("/api/system/switch-mode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: newMode }),
      });
    } catch (e) {
      console.error("Khong the ket noi voi may chu");
    }
  });
}
syncTheme();

// Hieu ung an hien cac khung dang nhap
const loginSection = document.getElementById("loginSection");
const mfaSection = document.getElementById("mfaSection");
const forgotSection = document.getElementById("forgotSection");

function switchSection(hideElem, showElem) {
  hideElem.classList.add("hidden");
  showElem.classList.remove("hidden");
  showElem.classList.add("fade-in");
  document.getElementById("messageBox")?.classList.add("hidden");
}

document
  .getElementById("showForgotBtn")
  ?.addEventListener("click", () => switchSection(loginSection, forgotSection));
document
  .getElementById("backToLoginBtn")
  ?.addEventListener("click", () => switchSection(forgotSection, loginSection));
document.getElementById("backToLoginFromMfa")?.addEventListener("click", () => {
  switchSection(mfaSection, loginSection);
  const otpInput = document.getElementById("otpCode");
  if (otpInput) otpInput.value = "";
});

// Xu ly thong bao va luu tru phien lam viec
const messageBox = document.getElementById("messageBox");
let tempMfaToken = ""; // Luu Token MFA tam thoi
let currentAuthUsername = ""; // BIẾN MỚI: Luu ten user chinh xac de hien thi, khong dung JWT

function showMessage(msg, type) {
  if (!messageBox) return;
  messageBox.className = `message ${type} fade-in`;
  messageBox.innerHTML = msg;
  messageBox.classList.remove("hidden");
}

function saveDataAndRedirect(data, username) {
  // Luu ten nguoi dung de hien thi tren Header
  localStorage.setItem("auth_username", username);
  localStorage.setItem("auth_role", data.role || "user");
  const savedMode = localStorage.getItem("ui_mode") || "vulnerable";

  // VÁ LỖI LỘ TOKEN (XSS):
  if (savedMode === "secure") {
    // 1. O che do An toan: Xoa sach Token, buoc he thong chi su dung HttpOnly Cookie ngam!
    localStorage.removeItem("auth_jwt");
  } else {
    // 2. O che do Canh bao: Luu Token ho henh ra ngoai de Hacker co the copy duoc trong F12
    if (data.access_token) {
      localStorage.setItem("auth_jwt", data.access_token);
    }
  }

  setTimeout(() => {
    window.location.href = "dashboard.html";
  }, 800);
}

// API Dang nhap chinh
document
  .getElementById("loginForm")
  ?.addEventListener("submit", async function (e) {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const rememberMe = document.getElementById("rememberMe").checked;

    currentAuthUsername = username; // Luu lai ten vua nhap
    const loginBtn = document.getElementById("loginBtn");
    loginBtn.disabled = true;
    showMessage(
      '<i class="fas fa-spinner fa-spin"></i> Đang xác thực...',
      "success",
    );

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password, remember_me: rememberMe }),
      });
      const data = await response.json();

      if (response.ok) {
        if (data.require_mfa) {
          tempMfaToken = data.temp_token;
          switchSection(loginSection, mfaSection);
          const otpInput = document.getElementById("otpCode");
          if (otpInput) otpInput.value = "";
          showMessage(
            '<i class="fas fa-mobile-alt"></i> Vui lòng nhập mã bảo mật',
            "success",
          );
        } else {
          showMessage(
            '<i class="fas fa-check-circle"></i> Đăng nhập thành công',
            "success",
          );
          saveDataAndRedirect(data, currentAuthUsername);
        }
      } else {
        showMessage(
          '<i class="fas fa-times-circle"></i> Sai tên đăng nhập hoặc mật khẩu',
          "error",
        );
      }
    } catch (error) {
      showMessage('<i class="fas fa-wifi"></i> Lỗi kết nối mạng', "error");
    } finally {
      loginBtn.disabled = false;
    }
  });

// API Dang nhap bang Google
document.getElementById("ssoBtn")?.addEventListener("click", async function () {
  const email = document.getElementById("username").value;
  if (!email.includes("@")) {
    showMessage(
      '<i class="fas fa-exclamation-triangle"></i> Vui lòng nhập Email trước khi tiếp tục',
      "error",
    );
    return;
  }

  currentAuthUsername = email; // Luu lai email vua nhap
  showMessage(
    '<i class="fas fa-spinner fa-spin"></i> Chờ xác nhận từ Google...',
    "success",
  );

  try {
    const googleRes = await fetch(`/api/auth/mock-google-token/${email}`);
    const googleData = await googleRes.json();

    const response = await fetch("/api/auth/sso/google", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        email: email,
        google_id_token: googleData.google_id_token,
      }),
    });

    const data = await response.json();
    if (response.ok) {
      if (data.require_mfa) {
        tempMfaToken = data.temp_token;
        switchSection(loginSection, mfaSection);
        const otpInput = document.getElementById("otpCode");
        if (otpInput) otpInput.value = "";
        showMessage(
          '<i class="fas fa-lock"></i> Yêu cầu xác minh thiết bị',
          "success",
        );
      } else {
        showMessage(
          '<i class="fab fa-google"></i> Xác nhận thành công',
          "success",
        );
        saveDataAndRedirect(data, currentAuthUsername);
      }
    } else {
      showMessage(
        '<i class="fas fa-times-circle"></i> Tài khoản không hợp lệ',
        "error",
      );
    }
  } catch (e) {
    showMessage('<i class="fas fa-wifi"></i> Lỗi kết nối Google', "error");
  }
});

// API Xac thuc ma OTP
document
  .getElementById("mfaForm")
  ?.addEventListener("submit", async function (e) {
    e.preventDefault();
    const otpCode = document.getElementById("otpCode").value;
    showMessage(
      '<i class="fas fa-spinner fa-spin"></i> Đang kiểm tra mã...',
      "success",
    );

    try {
      const response = await fetch("/api/auth/mfa/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username: tempMfaToken, otp_token: otpCode }),
      });
      const data = await response.json();
      if (response.ok) {
        showMessage(
          '<i class="fas fa-shield-check"></i> Xác minh thành công',
          "success",
        );
        // Tra ten nguoi dung dang hoang thay vi token
        saveDataAndRedirect(data, currentAuthUsername);
      } else {
        showMessage(
          `<i class="fas fa-times-circle"></i> ${data.detail || "Mã bảo mật sai"}`,
          "error",
        );
      }
    } catch (error) {
      showMessage('<i class="fas fa-wifi"></i> Lỗi kết nối mạng', "error");
    }
  });

// Tai du lieu khi vao trang chu
async function loadDashboardData() {
  const username = localStorage.getItem("auth_username");
  const role = localStorage.getItem("auth_role");
  const savedMode = localStorage.getItem("ui_mode") || "vulnerable";

  if (!username) {
    window.location.href = "/";
    return;
  }
  syncTheme();
  document.getElementById("welcomeName").textContent = username;

  if (role === "admin") {
    document.getElementById("adminView").classList.remove("hidden");
    document.getElementById("userView").classList.add("hidden");
    fetchAdminData();
  } else {
    document.getElementById("userView").classList.remove("hidden");
    document.getElementById("adminView").classList.add("hidden");

    const mfaElem = document.getElementById("userMfaStatus");
    if (savedMode === "secure") {
      mfaElem.innerHTML = '<i class="fas fa-check"></i> Đang bật';
      mfaElem.className = "badge success";
    } else {
      mfaElem.innerHTML = '<i class="fas fa-times"></i> Đã tắt';
      mfaElem.className = "badge error";
      mfaElem.style.background = "#fee2e2";
      mfaElem.style.color = "#c53030";
    }
  }
}

// Lay danh sach nguoi dung cho bang cua Admin
async function fetchAdminData() {
  const tbody = document.getElementById("adminTableBody");
  try {
    const headers = {};
    const token = localStorage.getItem("auth_jwt");
    if (token) {
      // Chi gui kem Token neu dang o che do Vuln
      headers["Authorization"] = `Bearer ${token}`;
    }

    const res = await fetch("/api/admin/users", {
      headers: headers,
      credentials: "include", // Luon gui kem HttpOnly Cookie neu dang o Secure
    });
    const data = await res.json();
    if (res.ok) {
      tbody.innerHTML = "";
      data.users.slice(0, 10).forEach((u) => {
        const roleBadge =
          u.role === "admin"
            ? '<span class="badge admin">Quản trị</span>'
            : '<span class="badge">Người dùng</span>';
        const mfaBadge = u.is_mfa_enabled
          ? '<i class="fas fa-check-circle" style="color:var(--accent-color)"></i>'
          : "-";
        tbody.innerHTML += `
            <tr>
                <td><strong>${u.username}</strong></td>
                <td>${u.email}</td>
                <td>${roleBadge}</td>
                <td style="text-align:center">${mfaBadge}</td>
                <td>
                    <button class="btn-action"><i class="fas fa-edit"></i> Sửa</button>
                    <button class="btn-action lock"><i class="fas fa-ban"></i> Khóa</button>
                </td>
            </tr>`;
      });
    } else {
      tbody.innerHTML =
        '<tr><td colspan="5">Lỗi phân quyền (Từ chối truy cập).</td></tr>';
    }
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="5">Lỗi kết nối máy chủ.</td></tr>';
  }
}

document
  .getElementById("btnUserAccessAdmin")
  ?.addEventListener("click", function () {
    document.getElementById("userErrorBox").classList.remove("hidden");
  });

document.getElementById("logoutBtn")?.addEventListener("click", async () => {
  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
  } catch (e) {}
  localStorage.clear();
  window.location.href = "/";
});
