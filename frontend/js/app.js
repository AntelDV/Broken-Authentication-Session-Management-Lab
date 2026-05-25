let timerInterval;

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

if (modeToggle) {
  modeToggle.addEventListener("change", async function () {
    const newMode = this.checked ? "secure" : "vulnerable";
    localStorage.setItem("ui_mode", newMode);
    syncTheme();
    try {
      await fetch("/api/admin/switch-mode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: newMode }),
      });
    } catch (e) {}
  });
}
syncTheme();

const loginSection = document.getElementById("loginSection");
const mfaSection = document.getElementById("mfaSection");
const forgotSection = document.getElementById("forgotSection");

function switchSection(hideElem, showElem) {
  if (hideElem) hideElem.classList.add("hidden");
  if (showElem) {
    showElem.classList.remove("hidden");
    showElem.classList.add("fade-in");
  }
  document.getElementById("messageBox")?.classList.add("hidden");
}

document
  .getElementById("showForgotBtn")
  ?.addEventListener("click", function (e) {
    e.preventDefault();
    switchSection(loginSection, forgotSection);
  });

document
  .getElementById("backToLoginBtn")
  ?.addEventListener("click", function (e) {
    e.preventDefault();
    switchSection(forgotSection, loginSection);
  });

document
  .getElementById("backToLoginFromMfa")
  ?.addEventListener("click", function (e) {
    e.preventDefault();
    switchSection(mfaSection, loginSection);
    const otpInput = document.getElementById("otpCode");
    if (otpInput) otpInput.value = "";
  });

const messageBox = document.getElementById("messageBox");
let tempMfaToken = "";
let currentAuthUsername = "";

function showMessage(msg, type) {
  if (!messageBox) return;
  messageBox.className = `message ${type} fade-in`;
  messageBox.innerHTML = msg;
  messageBox.classList.remove("hidden");
}

function saveDataAndRedirect(data, username) {
  localStorage.setItem("auth_username", username);
  localStorage.setItem("auth_role", data.role || "user");
  const savedMode = localStorage.getItem("ui_mode") || "vulnerable";

  if (savedMode === "secure") {
    localStorage.removeItem("auth_jwt");
  } else {
    if (data.access_token) {
      localStorage.setItem("auth_jwt", data.access_token);
    }
  }
  setTimeout(() => {
    window.location.href = "dashboard.html";
  }, 800);
}

document
  .getElementById("loginForm")
  ?.addEventListener("submit", async function (e) {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const rememberMe = document.getElementById("rememberMe").checked;

    currentAuthUsername = username;
    const loginBtn = document.getElementById("loginBtn");
    loginBtn.disabled = true;
    showMessage(
      '<i class="fas fa-spinner fa-spin"></i> Đang xác thực...',
      "success",
    );

    try {
      const urlParams = window.location.search;
      const response = await fetch("/api/auth/login" + urlParams, {
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
      const urlParams = window.location.search;
      const response = await fetch("/api/auth/mfa/verify" + urlParams, {
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

document
  .getElementById("ssoBtn")
  ?.addEventListener("click", async function (e) {
    e.preventDefault();
    const email = document.getElementById("username").value;
    if (!email.includes("@")) {
      showMessage(
        '<i class="fas fa-exclamation-triangle"></i> Vui lòng nhập Email',
        "error",
      );
      return;
    }
    currentAuthUsername = email;
    showMessage(
      '<i class="fas fa-spinner fa-spin"></i> Chờ xác nhận...',
      "success",
    );
    try {
      const googleRes = await fetch(`/api/auth/mock-google-token/${email}`);
      const googleData = await googleRes.json();

      const urlParams = window.location.search;

      const response = await fetch("/api/auth/sso/google" + urlParams, {
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
    } catch (err) {
      showMessage('<i class="fas fa-wifi"></i> Lỗi kết nối Google', "error");
    }
  });

document
  .getElementById("forgotForm")
  ?.addEventListener("submit", async function (e) {
    e.preventDefault();

    const emailInput =
      document.getElementById("forgotEmail") ||
      document.getElementById("forgotUsername") ||
      document.querySelector('#forgotSection input[type="text"]');
    const email = emailInput ? emailInput.value : "";

    if (!email) {
      showMessage(
        '<i class="fas fa-exclamation-triangle"></i> Vui lòng nhập Email',
        "error",
      );
      return;
    }

    showMessage(
      '<i class="fas fa-spinner fa-spin"></i> Đang gửi yêu cầu...',
      "success",
    );

    try {
      const response = await fetch("/api/auth/password/forgot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: email }),
      });
      const data = await response.json();

      if (response.ok) {
        const linkDemo = data.reset_link_demo || "#";
        showMessage(
          `
          <i class="fas fa-envelope"></i> ${data.message}
          <div style="margin-top:12px; padding:10px; background:#f3f4f6; border-left: 4px solid #e53e3e; border-radius:4px; font-size:13px; word-break: break-all; color: #333;">
            <b>[Email gửi tới]:</b><br>
            <i>Hãy nhấp vào đường dẫn bên dưới để đặt lại mật khẩu:</i><br>
            <a href="${linkDemo}" target="_blank" rel="noopener noreferrer" style="color:#d97706; font-weight: bold;">${linkDemo}</a>
          </div>
        `,
          "success",
        );
      } else {
        showMessage(
          `<i class="fas fa-times-circle"></i> ${data.detail || "Không thể gửi yêu cầu"}`,
          "error",
        );
      }
    } catch (error) {
      showMessage('<i class="fas fa-wifi"></i> Lỗi kết nối mạng', "error");
    }
  });

async function loadDashboardData() {
  const tbody = document.getElementById("adminTableBody");
  const welcomeName = document.getElementById("welcomeName");
  const adminView = document.getElementById("adminView");
  const userView = document.getElementById("userView");

  syncTheme();

  try {
    const res = await fetch("/api/admin/users", {
      method: "GET",
      credentials: "include",
    });

    if (res.status === 401) {
      localStorage.clear();
      window.location.href = "/";
      return;
    }

    if (welcomeName) {
      welcomeName.innerText =
        localStorage.getItem("auth_username") || "Người dùng";
    }

    if (res.status === 403) {
      if (adminView) adminView.classList.add("hidden");
      if (userView) userView.classList.remove("hidden");

      const mfaElem = document.getElementById("userMfaStatus");
      const savedMode = localStorage.getItem("ui_mode") || "vulnerable";
      if (mfaElem) {
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
      return;
    }

    if (res.ok) {
      if (userView) userView.classList.add("hidden");
      if (adminView) adminView.classList.remove("hidden");

      const data = await res.json();
      if (tbody) {
        tbody.innerHTML = "";
        data.forEach((u) => {
          const roleBadge =
            u.role === "admin"
              ? '<span class="badge admin">Quản trị</span>'
              : '<span class="badge">Người dùng</span>';
          const mfaBadge = u.is_mfa_enabled
            ? '<i class="fas fa-check-circle" style="color:#059669"></i>'
            : "-";

          tbody.innerHTML += `
            <tr>
              <td><strong>${u.username}</strong></td>
              <td>${u.email}</td>
              <td>${roleBadge}</td>
              <td style="text-align:center">${mfaBadge}</td>
              <td>-</td>
            </tr>`;
        });
      }
    }
  } catch (e) {
    if (tbody) {
      tbody.innerHTML =
        '<tr><td colspan="5" style="color:red;">Lỗi kết nối nghiêm trọng đến Máy chủ API.</td></tr>';
    }
  }
}

document.getElementById("logoutBtn")?.addEventListener("click", async () => {
  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
  } catch (e) {}
  localStorage.clear();
  window.location.href = "/";
});

if (
  window.location.pathname.endsWith("index.html") ||
  window.location.pathname === "/"
) {
  const cookies = document.cookie.split(";");
  for (let i = 0; i < cookies.length; i++) {
    const cookie = cookies[i].trim();
    if (cookie.startsWith("auth_session_id=")) {
      window.location.href = "dashboard.html";
      break;
    }
  }
}

document.addEventListener("click", function (e) {
  const toggleIcon = e.target.closest(".toggle-password");

  if (toggleIcon) {
    const input = toggleIcon.previousElementSibling;

    if (input && input.tagName === "INPUT") {
      if (input.type === "password") {
        input.type = "text";
        toggleIcon.classList.remove("fa-eye");
        toggleIcon.classList.add("fa-eye-slash");
      } else {
        input.type = "password";
        toggleIcon.classList.remove("fa-eye-slash");
        toggleIcon.classList.add("fa-eye");
      }
    }
  }
});
