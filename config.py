# config.py
# Flask session密钥
SECRET_KEY = "family_2026_project_session_key"

# JWT配置
JWT_SECRET = "family_2026_jwt_token_secret_key"
JWT_EXPIRE = 7200  # 2小时

# 家庭用户账号
ALLOWED_USERS = {
    "mom": "5630913www",
    "dad": "871816",
    "son": "5630913Www"
}

# 验证码配置
import string
CAPTCHA_CHARS = "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
CAPTCHA_LENGTH = 4
