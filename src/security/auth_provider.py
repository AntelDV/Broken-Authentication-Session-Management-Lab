import pyotp

def generate_mfa_secret() -> str:
    """
    Tạo một khóa bí mật ngẫu nhiên (Base32) cho người dùng.
    Khóa này sẽ được lưu vào cột mfa_secret trong Database.
    """
    return pyotp.random_base32()

def get_provisioning_uri(username: str, secret: str, issuer_name: str = "Auth Lab Security") -> str:
    """
    Tạo đường dẫn URI để sau này Frontend có thể dùng thư viện vẽ ra mã QR Code.
    Khi quét QR, app Google Authenticator sẽ lưu với tên issuer_name.
    """
    totp = pyotp.totp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer_name)

def verify_mfa_token(secret: str, token: str) -> bool:
    """
    Kiểm tra xem mã 6 số (token) người dùng nhập vào có khớp với thời gian thực không.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token)