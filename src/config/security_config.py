# WORKFLOW: Nơi thiết lập các config tĩnh về bảo mật.
# ĐIỂM NEO: Nếu mode = 'vulnerable', CORS mở toàn bộ. Ở mode 'secure', sẽ có cấu hình khắt khe hơn.
from fastapi.middleware.cors import CORSMiddleware

def setup_cors(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], 
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

BCRYPT_ROUNDS = 12 # Work Factor chuẩn để chống crack bằng phần cứng.
