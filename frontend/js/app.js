// --- XỬ LÝ NÚT GẠT THEME VÀ ĐỒNG BỘ UI ---
const modeToggle = document.getElementById("modeToggle");
const modeLabel = document.getElementById("modeLabel");
const body = document.body;

function syncTheme() {
  const savedMode = localStorage.getItem("ui_mode") || "vulnerable";
  if (savedMode === "secure") {
    body.classList.add("theme-secure");
    if (modeToggle) modeToggle.checked = true;
    if (modeLabel) modeLabel.textContent = "🛡️ SECURE MODE";

    const dashLabel = document.getElementById("modeLabelDashboard");
    if (dashLabel) dashLabel.textContent = "🛡️ SECURE MODE";

    // Chế độ Secure: Ẩn hết đồ chơi của Hacker, hiện Profile an toàn
    document
      .querySelectorAll(".panel-vuln")
      .forEach((p) => p.classList.add("hidden"));
    document
      .querySelectorAll(".panel-secure-only")
      .forEach((p) => p.classList.remove("hidden"));
  } else {
    body.classList.remove("theme-secure");
    if (modeToggle) modeToggle.checked = false;
    if (modeLabel) modeLabel.textContent = "☠️ VULNERABLE MODE";

    const dashLabel = document.getElementById("modeLabelDashboard");
    if (dashLabel) dashLabel.textContent = "☠️ VULNERABLE MODE";

    // Chế độ Vuln: đưa mọi thứ ra cho Hacker copy
    document
      .querySelectorAll(".panel-vuln")
      .forEach((p) => p.classList.remove("hidden"));
    document
      .querySelectorAll(".panel-secure-only")
      .forEach((p) => p.classList.add("hidden"));
  }
}

if (modeToggle) {
  modeToggle.addEventListener("change", function () {
    localStorage.setItem("ui_mode", this.checked ? "secure" : "vulnerable");
    syncTheme();
  });
}
syncTheme();

// --- XỬ LÝ FORM LOGIN ---
const loginForm = document.getElementById("loginForm");
if (loginForm) {
  loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    await executeAuth("http://127.0.0.1:8000/api/auth/login", {
      username: document.getElementById("username").value,
      password: document.getElementById("password").value,
      remember_me: document.getElementById("rememberMe").checked,
    });
  });
}

// --- XỬ LÝ NÚT LOGIN SSO ---
const ssoBtn = document.getElementById("ssoBtn");
if (ssoBtn) {
  ssoBtn.addEventListener("click", async function () {
    const email = document.getElementById("username").value;
    if (!email.includes("@")) {
      alert("Vui lòng nhập Email!");
      return;
    }
    showMessage("Đang xin cấp Token từ Google ...", "success");
    try {
      const googleRes = await fetch(
        `http://127.0.0.1:8000/api/auth/mock-google-token/${email}`,
      );
      const googleData = await googleRes.json();
      await executeAuth("http://127.0.0.1:8000/api/auth/sso/google", {
        email: email,
        google_id_token: googleData.google_id_token,
      });
    } catch (e) {
      showMessage("Lỗi kết nối SSO!", "error");
    }
  });
}

// --- HÀM GỌI API CHUNG ---
async function executeAuth(url, payload) {
  const loginBtn = document.getElementById("loginBtn");
  showMessage("Đang xử lý...", "success");
  if (loginBtn) loginBtn.disabled = true;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (response.ok) {
      showMessage(data.message, "success");

      if (data.require_mfa) {
        const otp = prompt(
          `[MFA REQUIRED] Vui lòng nhập mã 6 số cho tài khoản ${data.temp_token}:`,
        );
        if (otp) {
          await executeAuth("http://127.0.0.1:8000/api/auth/mfa/verify", {
            username: data.temp_token,
            otp_token: otp,
          });
        } else {
          showMessage("Đã hủy nhập MFA", "error");
        }
        return;
      }

      localStorage.setItem("auth_username", payload.username || payload.email);
      localStorage.setItem("auth_role", data.role);
      localStorage.setItem(
        "auth_session",
        data.session_id || "HttpOnly Protected",
      );

      if (data.remember_cookie && data.remember_cookie.includes("Bảo mật")) {
        localStorage.setItem("auth_remember", "[Bảo mật: Chuỗi ngẫu nhiên]");
      } else {
        localStorage.setItem("auth_remember", data.remember_cookie || "null");
      }

      if (data.access_token) {
        localStorage.setItem("auth_jwt", data.access_token);
      }

      setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 800);
    } else {
      showMessage(data.detail || "Lỗi đăng nhập", "error");
    }
  } catch (error) {
    showMessage("Không thể kết nối đến Máy chủ.", "error");
  } finally {
    if (loginBtn) loginBtn.disabled = false;
  }
}

function showMessage(msg, type) {
  const box = document.getElementById("messageBox");
  if (!box) return;
  box.className = `message ${type}`;
  box.textContent = msg;
  box.classList.remove("hidden");
}

// --- LOGIC TRANG DASHBOARD ---
function loadDashboardData() {
  const username = localStorage.getItem("auth_username");
  if (!username) {
    window.location.href = "/";
    return;
  }

  syncTheme();

  document.getElementById("welcomeMsg").innerHTML =
    `Xin chào <b>${username}</b>! Quyền: <b>[ ${localStorage.getItem("auth_role").toUpperCase()} ]</b>`;
  document.getElementById("secUsername").textContent = username;

  document.getElementById("sessionDisplay").textContent =
    localStorage.getItem("auth_session") || "null";
  document.getElementById("rememberDisplay").textContent =
    localStorage.getItem("auth_remember") || "null";

  const jwt = localStorage.getItem("auth_jwt");
  if (jwt) {
    document.getElementById("jwtRawDisplay").textContent = jwt;
    try {
      const parts = jwt.split(".");
      if (parts.length === 3) {
        document.getElementById("jwtDecodedDisplay").textContent =
          `[HEADER]\n${JSON.stringify(JSON.parse(atob(parts[0])), null, 2)}\n\n[PAYLOAD]\n${JSON.stringify(JSON.parse(atob(parts[1])), null, 2)}`;
      }
    } catch (e) {
      document.getElementById("jwtDecodedDisplay").textContent =
        "Lỗi giải mã JWT.";
    }
  } else {
    document.getElementById("jwtRawDisplay").textContent = "Không có JWT.";
  }
}

// --- TEST ADMIN API ---
const testAdminBtn = document.getElementById("testAdminBtn");
if (testAdminBtn) {
  testAdminBtn.addEventListener("click", async function () {
    const box = document.getElementById("adminDataBox");
    box.classList.remove("hidden");
    box.innerHTML = "Đang gọi API...";

    try {
      const res = await fetch("http://127.0.0.1:8000/api/admin/users", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("auth_jwt")}`,
        },
      });
      const data = await res.json();

      if (res.ok) {
        box.innerHTML = `<b>Thành công!</b><br><pre>${JSON.stringify(data, null, 2)}</pre>`;
        box.style.borderColor = "var(--accent)";
        box.style.color = "var(--accent)";
      } else {
        box.innerHTML = `<b>Thất bại (HTTP ${res.status}):</b><br>${data.detail}`;
        box.style.borderColor = "var(--error-text)";
        box.style.color = "var(--error-text)";
      }
    } catch (e) {
      box.innerHTML = "Lỗi kết nối!";
    }
  });
}

const logoutBtn = document.getElementById("logoutBtn");
if (logoutBtn) {
  logoutBtn.addEventListener("click", () => {
    localStorage.clear();
    window.location.href = "/";
  });
}
