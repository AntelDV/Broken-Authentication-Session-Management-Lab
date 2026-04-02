let timerInterval; // Biến cho đồng hồ

// ==========================================
// 1. XỬ LÝ THEME & ĐỒNG BỘ UI
// ==========================================
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
        '<i class="fas fa-shield-check"></i> Chế Độ An Toàn';
    document
      .querySelectorAll(".panel-vuln")
      .forEach((p) => p.classList.add("hidden"));
    document
      .querySelectorAll(".panel-secure-only")
      .forEach((p) => p.classList.remove("hidden"));
  } else {
    body.classList.remove("theme-secure");
    if (modeToggle) modeToggle.checked = false;
    if (modeLabel)
      modeLabel.innerHTML =
        '<i class="fas fa-exclamation-triangle"></i> Có Thể Bị Tấn Công';
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

// ==========================================
// 2. XỬ LÝ CHUYỂN ĐỔI FORM MƯỢT MÀ
// ==========================================
const loginSection = document.getElementById("loginSection");
const mfaSection = document.getElementById("mfaSection");
const forgotSection = document.getElementById("forgotSection");

function switchSection(hideElem, showElem) {
  hideElem.classList.add("hidden");
  showElem.classList.remove("hidden");
  showElem.classList.add("fade-in");
  document.getElementById("messageBox").classList.add("hidden"); // Xóa thông báo rác
}

document
  .getElementById("showForgotBtn")
  ?.addEventListener("click", () => switchSection(loginSection, forgotSection));
document
  .getElementById("backToLoginBtn")
  ?.addEventListener("click", () => switchSection(forgotSection, loginSection));
document
  .getElementById("backToLoginFromMfa")
  ?.addEventListener("click", () => switchSection(mfaSection, loginSection));

// ==========================================
// 3. KẾT NỐI API THỰC TẾ VỚI BACKEND
// ==========================================
const messageBox = document.getElementById("messageBox");
let tempMfaUsername = ""; // Lưu tạm user để đẩy sang API MFA

function showMessage(msg, type) {
  messageBox.className = `message ${type} fade-in`;
  messageBox.innerHTML = msg;
  messageBox.classList.remove("hidden");
}

function saveDataAndRedirect(data, username) {
  localStorage.setItem("auth_username", username);
  localStorage.setItem("auth_role", data.role || "user");
  localStorage.setItem("auth_session", data.session_id || "HttpOnly Protected");

  if (data.remember_cookie) {
    localStorage.setItem(
      "auth_remember",
      data.remember_cookie.includes("Bảo mật")
        ? "[Chuỗi mã hóa an toàn]"
        : data.remember_cookie,
    );
  } else {
    localStorage.setItem("auth_remember", "null");
  }

  if (data.access_token) {
    localStorage.setItem("auth_jwt", data.access_token);
  }

  setTimeout(() => {
    window.location.href = "dashboard.html";
  }, 800);
}

// GỌI API ĐĂNG NHẬP
document
  .getElementById("loginForm")
  ?.addEventListener("submit", async function (e) {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const rememberMe = document.getElementById("rememberMe").checked;

    const loginBtn = document.getElementById("loginBtn");
    loginBtn.disabled = true;
    showMessage(
      '<i class="fas fa-spinner fa-spin"></i> Đang xác thực...',
      "success",
    );

    try {
      const response = await fetch("http://127.0.0.1:8000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password, remember_me: rememberMe }),
      });
      const data = await response.json();

      if (response.ok) {
        if (data.require_mfa) {
          // TRƯỢT SANG FORM MFA
          tempMfaUsername = data.temp_token;
          switchSection(loginSection, mfaSection);
          showMessage(
            '<i class="fas fa-mobile-alt"></i> Vui lòng nhập mã từ ứng dụng',
            "success",
          );
        } else {
          showMessage(
            '<i class="fas fa-check-circle"></i> Xác thực thành công!',
            "success",
          );
          saveDataAndRedirect(data, username);
        }
      } else {
        showMessage(
          '<i class="fas fa-times-circle"></i> ' +
            (data.detail || "Lỗi đăng nhập"),
          "error",
        );
      }
    } catch (error) {
      showMessage(
        '<i class="fas fa-wifi"></i> Không thể kết nối đến Máy chủ.',
        "error",
      );
    } finally {
      loginBtn.disabled = false;
    }
  });

// GỌI API XÁC THỰC MFA (OTP)
document
  .getElementById("mfaForm")
  ?.addEventListener("submit", async function (e) {
    e.preventDefault();
    const otpCode = document.getElementById("otpCode").value;
    const mfaBtn = document.getElementById("mfaBtn");

    mfaBtn.disabled = true;
    showMessage(
      '<i class="fas fa-spinner fa-spin"></i> Đang kiểm tra mã...',
      "success",
    );

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/api/auth/mfa/verify",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            username: tempMfaUsername,
            otp_token: otpCode,
          }),
        },
      );
      const data = await response.json();

      if (response.ok) {
        showMessage(
          '<i class="fas fa-shield-check"></i> Xác thực 2 lớp thành công!',
          "success",
        );
        saveDataAndRedirect(data, tempMfaUsername);
      } else {
        showMessage(
          '<i class="fas fa-times-circle"></i> ' +
            (data.detail || "Mã OTP không đúng"),
          "error",
        );
      }
    } catch (error) {
      showMessage('<i class="fas fa-wifi"></i> Lỗi kết nối.', "error");
    } finally {
      mfaBtn.disabled = false;
    }
  });

// GỌI API QUÊN MẬT KHẨU
document
  .getElementById("forgotForm")
  ?.addEventListener("submit", async function (e) {
    e.preventDefault();
    const username = document.getElementById("forgotUsername").value;
    const btn = document.getElementById("sendResetBtn");
    btn.disabled = true;
    showMessage(
      '<i class="fas fa-spinner fa-spin"></i> Đang yêu cầu máy chủ...',
      "success",
    );

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/api/auth/password/forgot",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: username }),
        },
      );
      const data = await response.json();

      if (response.ok) {
        const demoLink = data.reset_link_demo
          ? `<br><br><span style="font-size:14px;color:#e53e3e;word-break:break-all">[DỮ LIỆU ĐÁNH CHẶN]: ${data.reset_link_demo}</span>`
          : "";
        showMessage(
          `<i class="fas fa-envelope-open-text"></i> ${data.message} ${demoLink}`,
          "success",
        );
      } else {
        showMessage('<i class="fas fa-times-circle"></i> Thất bại', "error");
      }
    } catch (err) {
      showMessage('<i class="fas fa-wifi"></i> Lỗi mạng.', "error");
    } finally {
      btn.disabled = false;
    }
  });

// GỌI API SSO
document.getElementById("ssoBtn")?.addEventListener("click", async function () {
  const email = document.getElementById("username").value;
  if (!email.includes("@")) {
    showMessage(
      '<i class="fas fa-exclamation-triangle"></i> Vui lòng nhập Email của bạn vào ô Đăng nhập để test SSO!',
      "error",
    );
    return;
  }
  showMessage(
    '<i class="fas fa-spinner fa-spin"></i> Đang yêu cầu Token từ Google...',
    "success",
  );
  try {
    const googleRes = await fetch(
      `http://127.0.0.1:8000/api/auth/mock-google-token/${email}`,
    );
    const googleData = await googleRes.json();
    const token = googleData.google_id_token;

    const response = await fetch("http://127.0.0.1:8000/api/auth/sso/google", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ email: email, google_id_token: token }),
    });
    const data = await response.json();

    if (response.ok) {
      showMessage(
        '<i class="fab fa-google"></i> Ủy quyền SSO thành công!',
        "success",
      );
      saveDataAndRedirect(data, email);
    } else {
      showMessage(
        '<i class="fas fa-times-circle"></i> ' + (data.detail || "Lỗi SSO"),
        "error",
      );
    }
  } catch (e) {
    showMessage('<i class="fas fa-wifi"></i> Lỗi kết nối SSO', "error");
  }
});

// ==========================================
// 4. LOGIC TRANG DASHBOARD & ĐỒNG HỒ
// ==========================================
function loadDashboardData() {
  const username = localStorage.getItem("auth_username");
  const role = localStorage.getItem("auth_role");
  const savedMode = localStorage.getItem("ui_mode") || "vulnerable";

  if (!username) {
    window.location.href = "/";
    return;
  }

  syncTheme();

  document.getElementById("welcomeName").textContent = username;
  const roleElem = document.getElementById("userRole");
  if (roleElem) {
    roleElem.textContent = role.toUpperCase();
    roleElem.className = role === "admin" ? "badge success" : "badge";
  }

  const mfaElem = document.getElementById("mfaStatus");
  if (mfaElem) {
    if (savedMode === "secure") {
      mfaElem.innerHTML = '<i class="fas fa-check"></i> Đang hoạt động';
      mfaElem.className = "badge success";
    } else {
      mfaElem.innerHTML = '<i class="fas fa-times"></i> Vô hiệu hóa';
      mfaElem.className = "badge error";
      mfaElem.style.background = "#fee2e2";
      mfaElem.style.color = "#c53030";
    }
  }

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
        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));
        document.getElementById("jwtDecodedDisplay").textContent =
          `[HEADER]\n${JSON.stringify(header, null, 2)}\n\n[PAYLOAD]\n${JSON.stringify(payload, null, 2)}`;
      }
    } catch (e) {
      document.getElementById("jwtDecodedDisplay").textContent =
        "Không thể giải mã Token.";
    }
  } else {
    document.getElementById("jwtRawDisplay").textContent =
      "Không có JWT Token.";
  }

  if (savedMode === "secure") {
    startCountdown(15 * 60);
  }
}

function startCountdown(durationInSeconds) {
  clearInterval(timerInterval);
  const display = document.getElementById("countdownTimer");
  if (!display) return;

  let timer = durationInSeconds,
    minutes,
    seconds;
  timerInterval = setInterval(function () {
    minutes = parseInt(timer / 60, 10);
    seconds = parseInt(timer % 60, 10);

    minutes = minutes < 10 ? "0" + minutes : minutes;
    seconds = seconds < 10 ? "0" + seconds : seconds;

    display.textContent = minutes + ":" + seconds;

    if (--timer < 0) {
      clearInterval(timerInterval);
      display.textContent = "00:00 (Hết hạn)";
    }
  }, 1000);
}

document
  .getElementById("testAdminBtn")
  ?.addEventListener("click", async function () {
    const box = document.getElementById("adminDataBox");
    box.classList.remove("hidden");
    box.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Đang truy xuất...';

    try {
      const res = await fetch("http://127.0.0.1:8000/api/admin/users", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("auth_jwt")}`,
        },
      });
      const data = await res.json();

      if (res.ok) {
        box.innerHTML = `<i class="fas fa-check-circle" style="color:var(--accent-color)"></i> Truy xuất thành công!<br><pre style="margin-top:15px">${JSON.stringify(data, null, 2)}</pre>`;
        box.style.borderColor = "var(--accent-color)";
      } else {
        box.innerHTML = `<i class="fas fa-ban" style="color:var(--accent-color)"></i> Lỗi (HTTP ${res.status}): ${data.detail}`;
        box.style.borderColor = "var(--accent-color)";
      }
    } catch (e) {
      box.innerHTML = '<i class="fas fa-wifi"></i> Lỗi mạng!';
    }
  });

document.getElementById("logoutBtn")?.addEventListener("click", () => {
  localStorage.clear();
  window.location.href = "/";
});
