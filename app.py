from flask import Flask, request, jsonify, session
import random
import jwt
import time
import config
from flask_cors import CORS
from datetime import timedelta

# 初始化Flask应用
app = Flask(__name__)
# 配置session密钥（用于验证码存储）
app.secret_key = config.SECRET_KEY  # 可修改为任意字符串
# 配置Session支持跨域
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # 开发环境设为False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # 可选的Session过期时间

# 允许跨域，并指定前端来源
CORS(app,
     supports_credentials=True,
     origins=["http://localhost:8080", "http://127.0.0.1:8080"],  # 明确指定前端地址
     allow_headers=["Content-Type", "Authorization"],
     expose_headers=["Content-Type"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

"""
    ==================== 简单配置 ====================
"""
# JWT密钥（可修改为任意字符串）
JWT_SECRET = config.JWT_SECRET
# JWT过期时间（2小时）
JWT_EXPIRE = config.JWT_EXPIRE
#家庭用户账号
ALLOWED_USERS = config.ALLOWED_USERS
# 验证码字符集
CAPTCHA_CHARS = config.CAPTCHA_CHARS
# 验证码长度
CAPTCHA_LENGTH = config.CAPTCHA_LENGTH

"""
    ==================== 辅助函数：验证登录 ====================
"""
def check_login(username, password, captcha):
    """验证账号密码和验证码"""
    # 1. 验证验证码
    session_captcha = session.get("captcha", "")
    if not session_captcha or captcha.lower() != session_captcha.lower():
        return False, "验证码错误或已过期"

    # 2. 验证账号密码
    if username not in ALLOWED_USERS:
        return False, "账号或密码错误"

    if ALLOWED_USERS[username] != password:
        return False, "账号或密码错误"

    return True, "验证成功"


"""
    ==================== 接口：生成验证码 ====================
"""
import base64
from io import BytesIO

@app.route("/api/captcha", methods=["GET"])
def get_captcha():
    # 生成随机验证码
    captcha_text = ''.join(random.choices(CAPTCHA_CHARS, k=CAPTCHA_LENGTH))
    session["captcha"] = captcha_text

    # 创建简单的验证码图片（使用纯色背景和文字）
    from PIL import Image, ImageDraw, ImageFont

    # 创建图片
    width, height = 120, 40
    image = Image.new('RGB', (width, height), color=(255, 245, 247))  # 浅粉色背景
    draw = ImageDraw.Draw(image)

    # 尝试使用字体
    try:
        # 优先尝试 Windows 常用字体
        font = ImageFont.truetype("arial.ttf", 30)
    except:
        try:
            # 备选 Mac/Linux 常用字体
            font = ImageFont.truetype("DejaVuSans.ttf", 30)
        except:
            # 实在找不到就用默认字体
            font = ImageFont.load_default()

    # 绘制验证码文字
    draw.text((10, 5), captcha_text, fill=(233, 84, 107), font=font)

    # 添加一些干扰点
    for _ in range(100):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(255, 182, 193))  # 浅粉色干扰点

    # 保存到内存
    buffer = BytesIO()
    image.save(buffer, format='PNG')
    buffer.seek(0)

    # 转换为base64
    img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return jsonify({
        "code": 200,
        "msg": "验证码生成成功",
        "data": {
            "captcha_img": f"data:image/png;base64,{img_base64}"
        }
    })

"""
    ==================== 接口：用户登录 ====================
"""
@app.route("/api/login", methods=["POST"])
def login():
    # 获取请求数据
    data = request.get_json()

    # 检查必要参数
    if not data:
        return jsonify({"code": 400, "msg": "缺少请求数据"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    captcha = data.get("captcha", "").strip()

    # 验证输入
    if not username or not password or not captcha:
        return jsonify({"code": 400, "msg": "账号、密码、验证码不能为空"}), 400

    # 验证登录
    success, message = check_login(username, password, captcha)

    if not success:
        return jsonify({"code": 400, "msg": message}), 400

    # 登录成功，清除验证码
    session.pop("captcha", None)

    # 生成JWT token
    payload = {
        "username": username,
        "exp": time.time() + JWT_EXPIRE
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return jsonify({
        "code": 200,
        "msg": "登录成功",
        "data": {
            "token": token,
            "username": username
        }
    })


"""
    ==================== 接口：用户退出 ====================
"""
@app.route("/api/logout", methods=["POST"])
def logout():
    """用户退出登录，清除session"""
    try:
        # 记录退出日志
        print(f"用户退出登录，Session ID: {session.sid if hasattr(session, 'sid') else 'Unknown'}")

        # 清除所有session数据
        session.clear()

        return jsonify({
            "code": 200,
            "msg": "退出成功",
            "data": None
        })
    except Exception as e:
        print(f"退出登录时发生错误: {str(e)}")
        return jsonify({
            "code": 500,
            "msg": f"退出失败: {str(e)}",
            "data": None
        }), 500

"""
    ==================== 接口：验证token ====================
"""
@app.route("/api/verify", methods=["POST"])
def verify_token():
    """验证token是否有效"""
    data = request.get_json()
    token = data.get("token", "") if data else ""

    if not token:
        return jsonify({"code": 401, "msg": "未提供token"}), 401

    try:
        # 验证token
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        # 检查是否过期
        if payload["exp"] < time.time():
            return jsonify({"code": 401, "msg": "token已过期"}), 401

        return jsonify({
            "code": 200,
            "msg": "token有效",
            "data": {
                "username": payload["username"],
                "valid": True
            }
        })

    except jwt.ExpiredSignatureError:
        return jsonify({"code": 401, "msg": "token已过期"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"code": 401, "msg": "无效的token"}), 401
    except Exception as e:
        return jsonify({"code": 401, "msg": "token验证失败"}), 401


"""
    ==================== 接口：获取用户信息 ====================
"""
@app.route("/api/user/info", methods=["GET"])
def get_user_info():
    """获取用户信息（需要token验证）"""
    # 从请求头获取token
    token = request.headers.get("Authorization", "")

    if not token:
        return jsonify({"code": 401, "msg": "未提供token"}), 401

    try:
        # 验证token
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        # 检查是否过期
        if payload["exp"] < time.time():
            return jsonify({"code": 401, "msg": "token已过期"}), 401

        username = payload["username"]

        # 返回用户信息
        return jsonify({
            "code": 200,
            "msg": "获取成功",
            "data": {
                "username": username,
                "login_time": time.time()
            }
        })

    except jwt.ExpiredSignatureError:
        return jsonify({"code": 401, "msg": "token已过期"}), 401
    except Exception as e:
        return jsonify({"code": 401, "msg": "token验证失败"}), 401


"""
    ==================== 接口：测试连通性 ====================
"""
@app.route("/api/test", methods=["GET"])
def test():
    """测试接口，无需登录"""
    return jsonify({
        "code": 200,
        "msg": "服务正常运行",
        "data": {
            "service": "Family Access System",
            "time": time.time()
        }
    })


"""
    ==================== 启动服务 ====================
"""
if __name__ == "__main__":
    # 打印启动信息
    print("=" * 50)
    print("家庭内部访问系统后端")
    print("=" * 50)
    print("已配置的用户账号：")
    for username in ALLOWED_USERS.keys():
        print(f"  - {username}")
    print("")
    print("接口地址：")
    print(f"  登录接口：POST http://localhost:5000/api/login")
    print(f"  验证码：GET  http://localhost:5000/api/captcha")
    print(f"  验证token：POST http://localhost:5000/api/verify")
    print(f"  用户信息：GET  http://localhost:5000/api/user/info")
    print(f"  测试接口：GET  http://localhost:5000/api/test")
    print("")
    print("账号密码验证码登录，仅供家庭内部成员使用")
    print("=" * 50)

    # 运行服务
    app.run(
        host="0.0.0.0",  # 允许同网络设备访问
        port=5000,
        debug=True
    )
