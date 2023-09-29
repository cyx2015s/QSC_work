# 导入模块
import copy
import datetime
import flask
import sqlite3
import jwt
import pytz

# 初始化

UTC8 = pytz.timezone("Asia/Shanghai")
app = flask.Flask(__name__)
DATABASE = "main.db"
DEFAULT_METHODS = ["GET", "POST"]
KEY = "ZJU"
DEFAULT_RESP = {
    "code": 0,
    "msg": "",
    "data": None,
}


# 获取当前时间
def _get_now():
    local_now = datetime.datetime.now()
    utc_now = local_now.astimezone(UTC8)
    return utc_now


# 获取当前日期
def _get_today():
    now = _get_now()
    return datetime.date(now.year, now.month, now.day)


# 通过jwt生成access_token，过期时间为一个小时
def _calc_token(usr, pwd):
    return jwt.encode(
        payload={
            "username": usr,
            "expire": (_get_now() + datetime.timedelta(hours=1)).timestamp(),
        },
        key=KEY,
        algorithm="HS256",
    )


# 检查输入的用户名和密码
def _valid_check(recv):
    state = {}
    username, password = "", ""
    try:
        username = recv["username"]
    except KeyError:
        state = {
            "code": 3,
            "msg": "Empty Username",
        }
    try:
        password = recv["password"]
    except KeyError:
        state = {
            "code": 4,
            "msg": "Empty Password",
        }

    return state, password, username


# 将响应以json格式返回
@app.after_request
def _add_header(resp: flask.Response):
    resp.headers["Content-Type"] = "application/json"
    return resp

# ping
@app.route("/ping", methods=DEFAULT_METHODS)
def ping():
    resp = copy.deepcopy(DEFAULT_RESP)
    resp["msg"] = "pong!"
    return flask.jsonify(resp)

# 登录
@app.route("/signin", methods=DEFAULT_METHODS)
def signin():
    recv = flask.request.get_json()
    resp = copy.deepcopy(DEFAULT_RESP)

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        state, password, username = _valid_check(recv)
        if not state:
            cur.execute("SELECT username, password FROM users WhERE username = ?;", (username,))
            ret = cur.fetchone()
            if ret:
                if ret[1] == password:
                    state = {
                        "data": {
                            "access_token": _calc_token(username, password)
                        }
                    }
                else:
                    state = {
                        "code": 2,
                        "msg": "Wrong Password",
                    }
            else:
                state = {
                    "code": 1,
                    "msg": "User Does Not Exist",
                }
        cur.close()
    resp.update(state)
    return resp

# 注册
@app.route("/signup", methods=DEFAULT_METHODS)
def signup():
    recv = flask.request.get_json()
    resp = copy.deepcopy(DEFAULT_RESP)

    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        state, password, username = _valid_check(recv)
        if not state:
            cur.execute("SELECT username, password FROM users WhERE username = ? ;", (username,))
            ret = cur.fetchone()
            if not ret:
                state = {
                    "data": {
                        "access_token": _calc_token(username, password)
                    }
                }
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                conn.commit()
            else:
                state = {
                    "code": 5,
                    "msg": "User Already Exists",
                }
        cur.close()
    resp.update(state)
    return resp

# 签到
@app.route("/checkin", methods=DEFAULT_METHODS)
def checkin():
    recv: dict = flask.request.get_json()
    resp = copy.deepcopy(DEFAULT_RESP)
    state = {}
    try:
        recv = jwt.decode(recv.get("access_token", ""), KEY, ["HS256"])
    except jwt.InvalidTokenError:
        state = {
            "code": 6,
            "msg": "Invalid Token",
        }
    if not state:
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            username = recv["username"]
            cur.execute("SELECT last_check, total_points, continuous FROM users WHERE username = ?", (username,))
            ret = cur.fetchone()
            ret = list(ret)
            if ret:
                if _get_now() < datetime.datetime.fromtimestamp(recv["expire"], tz=UTC8):
                    # 更新签到信息
                    state = {
                        "data": {
                            "point": 1,
                        }
                    }
                    delta_date = _get_today() - datetime.date.fromisoformat(ret[0])
                    if delta_date.days == 0:
                        state["data"]["point"] = 0
                    elif delta_date.days == 1:
                        ret[2] += 1
                        state["data"]["point"] += ret[2]
                    else:
                        ret[2] = 0
                    if state["data"]["point"] > 7:
                        state["data"]["point"] = 7

                    ret[0] = _get_today()
                    ret[1] += state["data"]["point"]
                    conn.execute("UPDATE users SET last_check = ?, total_points = ?, continuous = ? WHERE username = ?",
                                 (*ret, username))
                    conn.commit()
                else:
                    state = {
                        "code" : 8,
                        "msg" : "Login Token Expired",
                    }
            else:
                state = {
                    "code": 7,
                    "msg": "User Deleted",
                }

            cur.close()
    resp.update(state)
    return resp

# 主程序
if __name__ == "__main__":
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users ("
                     "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                     "username TEXT NOT NULL,"
                     "password TEXT NOT NULL,"
                     "last_check DATE NOT NULL DEFAULT '1900-01-01',"
                     "total_points INTEGER DEFAULT 0,"
                     "continuous INTEGER DEFAULT 0"
                     ")")
        conn.commit()
        print(conn)
    app.run()
