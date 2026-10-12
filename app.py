#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
权益U赏 多账号权益管理器
- 零第三方依赖（仅 Python 3 标准库），二维码库已内置在 vendor/ 目录
- 本地运行，凭证只保存在你自己的电脑上
启动： python3 app.py   然后浏览器打开 http://127.0.0.1:8787
"""

import json
import os
import base64
import hmac
import re
import sys
import threading
import datetime
import time
import traceback
import uuid
import urllib.request
import urllib.error
import socket
import webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import (urlparse, urlsplit, urlunsplit, unquote,
                          quote, urlencode)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "vendor"))  # 内置 segno

ACCOUNTS_FILE = os.path.join(BASE_DIR, "accounts.json")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")
STATIC_DIR = os.path.join(BASE_DIR, "static")
PORT = int(os.environ.get("PORT") or os.environ.get("UBRP_PORT") or 8787)

API_BASE = "https://benefit.unionpayintl.com/gateway/ubrp/h5"
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1")


# ---------------------------------------------------------------- 设置
DEFAULT_SETTINGS = {"qrMode": "qrserver", "hostedBase": "", "qrApi": "qrserver",
                    "cloudUrl": "", "cloudKey": "", "officialForm": "history",
                    "shareTtl": 0}


def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            s = json.load(f)
        out = dict(DEFAULT_SETTINGS)
        out.update({k: v for k, v in s.items() if k in DEFAULT_SETTINGS})
        # 兼容旧字段
        if not out.get("hostedBase") and s.get("publicBase"):
            out["hostedBase"] = s["publicBase"]
            out["qrMode"] = "hosted"
        return out
    except Exception:
        return dict(DEFAULT_SETTINGS)


def save_settings(s):
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SETTINGS_FILE)


def share_base(req_host=""):
    """按设置的模式，算出 /s/ 链接该用哪个地址前缀"""
    st = load_settings()
    mode, pub = st.get("linkMode", "local"), (st.get("publicBase") or "").strip().rstrip("/")
    if mode == "public":
        return pub                              # 内网穿透 / 公网域名
    # 端口以实际请求的为准（用户可能改了 UBRP_PORT）
    port = PORT
    if req_host and ":" in req_host:
        try:
            port = int(req_host.rsplit(":", 1)[1])
        except Exception:
            pass
    if mode == "lan":
        ip = lan_ip()
        return ("http://%s:%d" % (ip, port)) if ip else ""
    return ("http://" + req_host) if req_host else ("http://127.0.0.1:%d" % port)


# ---------------------------------------------------------------- 凭证智能识别
def _decode_layers(text, rounds=3):
    """逐层 URL 解码：%7B → {，%22 → "，%3A → :"""
    out, cur = [text], text
    for _ in range(rounds):
        nxt = unquote(cur)
        if nxt == cur:
            break
        cur = nxt
        out.append(cur)
    return out


# (说明, 正则, 置信度 high/low)
RE_TOKEN = [
    ("sessionStorage 字段 tokenUbrpH5", r'["\']?tokenUbrpH5["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "high"),
    ("JSON 字段 \"token\"",              r'["\']token["\']\s*:\s*["\']([^"\']{8,})["\']', "high"),
    ("请求头 token:",                    r'^\s*token\s*:\s*([0-9a-zA-Z._\-]{8,})\s*$', "high"),
    ("文本 token=",                      r'(?i)\btoken\s*[:=]\s*["\']?([0-9a-zA-Z._\-]{16,64})', "mid"),
]
RE_DEVICE = [
    ("JSON 字段 \"deviceId\"",           r'["\']deviceId["\']\s*:\s*["\']([^"\']{8,})["\']', "high"),
    ("请求头/文本 deviceId",             r'(?i)\bdeviceId\s*[:=]\s*["\']?([0-9a-zA-Z._\-]{8,64})', "high"),
    ("神策 Cookie 里的 $device_id",      r'\$device_id\s*["\']?\s*[:=]\s*["\']?([0-9a-zA-Z._\-]{8,64})', "low"),
    ("文本 device_id",                   r'(?i)\bdevice_id\s*["\']?\s*[:=]\s*["\']?([0-9a-zA-Z._\-]{8,64})', "low"),
]
RANK = {"high": 3, "mid": 2, "low": 1}


def _scan(patterns, texts):
    """在所有候选文本里按置信度从高到低找第一个命中"""
    best = None
    for desc, pat, conf in patterns:
        rx = re.compile(pat, re.M)
        for t in texts:
            m = rx.search(t)
            if m:
                val = m.group(1).strip().strip('"\'')
                if not val:
                    continue
                if best is None or RANK[conf] > RANK[best[2]]:
                    best = (val, desc, conf)
    return best


def parse_credentials(raw):
    """从任意一段文本（抓包全文 / 单行 header / JSON / URL 编码 Cookie）里摘出 token 与 deviceId"""
    raw = raw or ""
    notes, warns = [], []

    texts = _decode_layers(raw)
    if len(texts) > 1:
        notes.append("检测到 %xx 百分号编码，已自动 URL 解码后再识别")

    token, dev = None, None

    # 先看整段是不是干净 JSON（Console 直接输出的那种）
    for t in texts:
        s = t.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                o = json.loads(s)
                if isinstance(o, dict):
                    if o.get("token"):
                        token = (str(o["token"]).strip(), "JSON 字段 token", "high")
                    if o.get("deviceId"):
                        dev = (str(o["deviceId"]).strip(), "JSON 字段 deviceId", "high")
                    if token or dev:
                        break
            except Exception:
                pass

    if token is None:
        token = _scan(RE_TOKEN, texts)
    if dev is None:
        dev = _scan(RE_DEVICE, texts)

    # 兜底：整段就是一个十六进制串 → 当作 token（实测 token 是 33 位，别写死 32）
    if token is None:
        s = raw.strip()
        if re.fullmatch(r"[0-9a-fA-F]{16,64}", s):
            token = (s, "纯十六进制串（%d 位）" % len(s), "mid")

    out = {"ok": bool(token and dev), "token": "", "deviceId": "",
           "tokenFrom": "", "deviceFrom": "", "deviceConfidence": "",
           "notes": notes, "warns": warns}

    if token:
        out["token"] = token[0]
        out["tokenFrom"] = token[1]
    else:
        warns.append("没找到 token。请确认粘贴的内容里有 token（形如 token: xxxx 或 \"token\":\"xxxx\"）")

    if dev:
        out["deviceId"] = dev[0]
        out["deviceFrom"] = dev[1]
        out["deviceConfidence"] = dev[2]
        if dev[2] == "low":
            warns.append(
                "⚠ deviceId 取自神策统计 Cookie 的 $device_id，它通常**不是**接口需要的那个 deviceId。"
                "接口真正用的是浏览器 sessionStorage 里的 deviceId（32 位十六进制）。"
                "用这个值很可能查询失败，建议按上方代码重新取一次。")
    else:
        warns.append("没找到 deviceId。请确认粘贴的内容里有 deviceId 字段")

    if token and dev and RANK.get(dev[2], 0) >= 3:
        out["ok"] = True
    else:
        out["ok"] = bool(token and dev)   # 能凑齐就先给你，警告照样显示
    return out


# ---------------------------------------------------------------- 账号存储
def seed_from_env():
    """云端部署时，账号可以放在环境变量 UBRP_ACCOUNTS（base64(JSON)）里。

    Render 免费档的文件系统是临时盘：休眠、重启、重新部署都会清空，
    靠 /api/push 写进去的 accounts.json 会丢。写进环境变量则能一直保留。
    """
    raw = os.environ.get("UBRP_ACCOUNTS") or ""
    if not raw or os.path.exists(ACCOUNTS_FILE):
        return
    try:
        data = json.loads(base64.b64decode(raw).decode("utf-8"))
        if data.get("accounts"):
            save_store(data)
    except Exception:
        pass


def load_store():
    if not os.path.exists(ACCOUNTS_FILE):
        seed_from_env()
    if not os.path.exists(ACCOUNTS_FILE):
        return {"accounts": [], "activeId": ""}
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("accounts", [])
        data.setdefault("activeId", "")
        return data
    except Exception:
        return {"accounts": [], "activeId": ""}


def save_store(store):
    tmp = ACCOUNTS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)
    os.replace(tmp, ACCOUNTS_FILE)


def mask(s, keep=4):
    if not s:
        return ""
    s = str(s)
    return s if len(s) <= keep * 2 else s[:keep] + "…" + s[-keep:]


def public_account(a):
    return {
        "id": a["id"], "name": a.get("name", ""), "note": a.get("note", ""),
        "autoName": a.get("autoName", ""), "custom": bool(a.get("custom", False)),
        "tokenMask": mask(a.get("token", "")), "deviceIdMask": mask(a.get("deviceId", "")),
        "createdAt": a.get("createdAt", ""), "lastUsed": a.get("lastUsed", ""),
        "lastEmail": a.get("lastEmail", ""), "lastOk": a.get("lastOk", None),
    }


def find_account(store, aid):
    for a in store["accounts"]:
        if a["id"] == aid:
            return a
    return None


# ---------------------------------------------------------------- 接口调用
def api_post(path, token, device_id, data=None, timeout=25):
    ts = int(time.time() * 1000)
    payload = {
        "origin": {
            "source": 2, "apiVersion": "1.0", "timestamp": ts,
            "msgId": uuid.uuid4().hex, "lang": "zh_CN", "deviceId": device_id,
        },
        "data": data or {},
    }
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        "Origin": "https://benefit.unionpayintl.com",
        "Referer": "https://benefit.unionpayintl.com/mobile/",
        "User-Agent": UA,
        "token": token,
        "t": str(ts),
    }
    req = urllib.request.Request(
        API_BASE + path, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return {"rspInfo": {"code": "HTTP%s" % e.code, "msg": body or str(e)}}
    except Exception as e:
        return {"rspInfo": {"code": "NET_ERR", "msg": "%s: %s" % (type(e).__name__, e)}}


def ok(resp):
    return isinstance(resp, dict) and resp.get("rspInfo", {}).get("code") == "000000"


# ---------------------------------------------------------------- 商户识别
MERCHANTS = [
    ("龙腾出行", ["dragonpass", "机场贵宾", "机场休息室"]),
    ("悦途出行", ["悦途", "高铁贵宾", "高铁休息室"]),
    ("乐牙口腔", ["leya920", "洁牙", "齿科"]),
    ("KLOOK 客路", ["klook"]),
]


def detect_merchant(title, activity_name, mrch_url):
    blob = " ".join([title or "", activity_name or "", mrch_url or ""]).lower()
    for name, keys in MERCHANTS:
        if any(k.lower() in blob for k in keys):
            return name
    if mrch_url:
        host = urlparse(mrch_url).netloc
        if host:
            return host
    return "—"


def is_onsite(title, merchant):
    """是否属于现场扫码核销类（机场贵宾厅 / 高铁贵宾厅）"""
    blob = (title or "") + (merchant or "")
    return ("机场" in blob) or ("高铁" in blob) or ("龙腾" in blob) or ("悦途" in blob)


def _asdict(v):
    """把可能是 None / 非 dict 的值安全转成 dict"""
    return v if isinstance(v, dict) else {}


def classify_code(c):
    """判断券码是静态还是动态。

    不能只看 couponType / 字段名，实测四种情况：
      · KLOOK : couponType=1，有 benefitCode              → 静态
      · 洁牙  : couponType=0，有 dynamicCode，refreshTime=0 → 静态（字段叫 dynamic 但其实永不刷新）
      · 机场  : couponType=0，dynamicCode，refreshTime=60   → 动态
      · 高铁  : couponType=0，dynamicCode，refreshTime=60   → 动态

    真正的判据是「码会不会自己变」= refreshTime 是否 > 0。
    """
    static_code = str(c.get("benefitCode") or "").strip()
    dyn_code = str(c.get("dynamicCode") or "").strip()
    raw_refresh = int(c.get("refreshTime") or 0)

    if static_code:                       # 有固定兑换码 → 静态
        return static_code, "static", 0
    if dyn_code and raw_refresh > 0:      # 会定时变 → 真动态
        return dyn_code, "dynamic", raw_refresh
    if dyn_code:                          # 有码但不刷新 → 实际是固定码
        return dyn_code, "static", 0
    return "", "none", 0


def build_benefit(item, detail, coupon):
    """把 列表项 + 详情 + 券详情 合成前端要的一条"""
    # 注意：后端可能返回 {"data": null}，.get("data", {}) 会拿到 None 而不是 {}，
    # 后面再 .get() 就会崩。这里统一兜底成 dict。
    d = _asdict((detail or {}).get("data"))
    c = _asdict((coupon or {}).get("data"))
    oi = _asdict(d.get("orderInfo"))

    title = d.get("title") or item.get("title") or ""
    activity_name = d.get("activityName") or item.get("activityName") or ""
    mrch_url = c.get("mrchUrl") or ""
    merchant = detect_merchant(title, activity_name, mrch_url)

    code, code_type, refresh = classify_code(c)

    lk = analyze_link(mrch_url)
    return {
        "recordId": item.get("recordId"),
        "couponId": item.get("couponId"),
        "benefitId": item.get("benefitId"),
        "activityId": item.get("activityId"),
        "linkStable": lk["stable"],
        "linkExpire": lk.get("expire", ""),
        "linkNote": lk.get("note", ""),
        "linkTtl": lk.get("ttl", 0),
        "title": title,
        "activityName": activity_name,
        "highlight": d.get("highlight") or "",
        "bankName": d.get("bankName") or "",
        "cardNo": d.get("cardNo") or item.get("cardNo") or "",
        "expireTime": oi.get("expireTime") or "",
        "receiveTime": oi.get("receiveCouponTime") or oi.get("createTime") or "",
        "merchant": merchant,
        "onsite": is_onsite(title, merchant),
        "code": code,
        "codeType": code_type,
        "refreshTime": refresh,
        "mrchUrl": mrch_url,
        # 动态码一律只编裸券码（官方 mrchUrl 实测外部浏览器打不开，编进去等于废码）；
        # 静态码保持原样（编官方兑换链接，本地弹窗，不上公网）
        "qrTarget": code if code_type == "dynamic" else (mrch_url or code),
        "status": c.get("status", 1),
        "statusText": {1: "待使用", 2: "已使用", 3: "已过期"}.get(c.get("status", 1), "未知"),
        "imgUrl": item.get("imgUrl") or d.get("thumbnailUrl") or "",
        "orderNo": item.get("orderNo") or "",
        "bankName": d.get("bankName") or "",
        "useDirections": (c.get("useDirections") or d.get("useDirections") or "").strip(),
        "content": (d.get("content") or "").strip(),
    }


def fetch_benefits(token, device_id, only_type=2):
    """拉取权益：type=1 进行中(报名未达标) / type=2 待使用 / type=3 已使用已过期"""
    user = api_post("/user/queryUserInfo", token, device_id, {})
    if not ok(user):
        return {"ok": False, "err": user.get("rspInfo", {}), "list": [], "user": None}

    udata = user.get("data", {}) or {}
    email = udata.get("email") or ""

    types = [only_type] if only_type else [1, 2, 3]
    raw = []
    for t in types:
        r = api_post("/user/queryBenefitList", token, device_id,
                     {"type": t, "pageNo": 1, "pageSize": 50})
        if ok(r):
            for it in (r.get("data", {}) or {}).get("list", []) or []:
                it = dict(it)
                it["_type"] = t
                raw.append(it)

    # 同一张券可能出现在多个 type 里，按 couponId 去重
    seen, items = set(), []
    for it in raw:
        key = it.get("couponId") or it.get("recordId")
        if key in seen:
            continue
        seen.add(key)
        items.append(it)

    out = []
    for it in items:
        det = api_post("/user/queryBenefitDetail", token, device_id,
                       {"recordId": it.get("recordId"), "orderStatus": it.get("orderStatus", 4)})
        cp = api_post("/coupon/queryUserCouponDetail", token, device_id,
                      {"couponId": it.get("couponId")})
        b = build_benefit(it, det, cp)
        b["listType"] = it.get("_type")
        out.append(b)

    out.sort(key=lambda x: (x["expireTime"] or "9999", x["title"]))
    return {
        "ok": True,
        "user": {
            "email": email,
            "userId": udata.get("userId"),
            "cardCount": (udata.get("userBenefitStatInfo") or {}).get("cardCount"),
            "pendingUseCount": (udata.get("userBenefitStatInfo") or {}).get("pendingUseCount"),
        },
        "list": out,
    }


def suggest_name(token, device_id):
    """联网取 邮箱/发卡行/卡号后4位，拼成默认备注名"""
    u = api_post("/user/queryUserInfo", token, device_id, {})
    if not ok(u):
        return None, (u.get("rspInfo", {}) or {}).get("msg", "凭证无效")
    ud = u.get("data", {}) or {}
    email = ud.get("email") or ""

    card_no, bank = "", ""
    for t in (2, 1):
        r = api_post("/user/queryBenefitList", token, device_id,
                     {"type": t, "pageNo": 1, "pageSize": 10})
        if not ok(r):
            continue
        lst = (r.get("data", {}) or {}).get("list", []) or []
        if not lst:
            continue
        it = lst[0]
        card_no = it.get("cardNo") or ""
        d = api_post("/user/queryBenefitDetail", token, device_id,
                     {"recordId": it.get("recordId"), "orderStatus": it.get("orderStatus", 4)})
        if ok(d):
            bank = (d.get("data", {}) or {}).get("bankName") or ""
        break

    parts = []
    if email:
        parts.append(email)
    if bank:
        parts.append(bank)
    if card_no:
        parts.append(card_no[-4:] if len(card_no) >= 4 else card_no)
    return (" · ".join(parts) if parts else None), None


def refresh_coupon(token, device_id, coupon_id, record_id=None, order_status=4):
    cp = api_post("/coupon/queryUserCouponDetail", token, device_id, {"couponId": coupon_id})
    if not ok(cp):
        return {"ok": False, "err": cp.get("rspInfo", {})}
    c = _asdict(cp.get("data"))
    title = c.get("title") or ""
    mrch_url = c.get("mrchUrl") or ""
    code, code_type, refresh = classify_code(c)
    lk = analyze_link(mrch_url)
    mrch_url_use = official_url(mrch_url)
    return {
        "ok": True,
        "code": code, "codeType": code_type,
        "refreshTime": refresh,
        "mrchUrl": mrch_url_use, "mrchUrlRaw": mrch_url,
        "qrTarget": code if code_type == "dynamic" else (mrch_url_use or code),
        "linkStable": lk["stable"], "linkExpire": lk.get("expire", ""),
        "linkNote": lk.get("note", ""), "linkTtl": lk.get("ttl", 0),
        "status": c.get("status", 1),
        "fetchedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def to_history_url(u):
    """把官方给的 hash 路由链接换成真实路径。

    实测（探测器的四个变体）：
      带 #/verification/station  → 86271B「引导/说明页」  与访问域名根完全一致
      去掉 # 改成 /verification/station → 1312B「核销/验证页」
    原因：URL 里 # 之后的内容浏览器不会发给服务器，服务端只收到根路径，
    于是返回首页。去掉 # 后服务端才认得这个路由。
    """
    if not u:
        return ""
    m = re.match(r"^(https?://[^/]+)/#/(.*)$", u)
    if not m:
        return u
    return m.group(1) + "/" + m.group(2)


def official_url(u, form=None):
    """按设置决定官方链接用 hash 形式还是 history 形式"""
    if not u:
        return ""
    if form is None:
        form = load_settings().get("officialForm", "history")
    return u if form == "hash" else to_history_url(u)


def analyze_link(mrch_url):
    """解析官方核销链接里的签名载荷，判断这个链接本身能活多久。

    实测三类：
      · 乐牙洁牙  : expiryTime 距今约 28 天 → 稳定，可直接分享
      · KLOOK     : 根本没有 expiryTime     → 长期有效
      · 龙腾机场  : expiryTime = 签发+60秒  → 必须用活页面续期
    """
    if not mrch_url:
        return {"stable": False, "expire": "", "ttl": 0, "note": "官方未返回核销链接"}
    m = re.search(r"benefit_request_data=([^&]+)", mrch_url)
    if not m:
        return {"stable": True, "expire": "", "ttl": 0, "note": "无签名参数，链接长期有效"}
    try:
        payload = json.loads(unquote(m.group(1)))
        if not isinstance(payload, dict):
            raise ValueError("payload 不是对象")
        trx = payload.get("trxInfo")
        if not isinstance(trx, dict):
            trx = {}
        exp = str(trx.get("expiryTime") or "").strip()
    except Exception:
        return {"stable": True, "expire": "", "ttl": 0, "note": "签名无法解析，按长期有效处理"}
    if not exp:
        return {"stable": True, "expire": "", "ttl": 0, "note": "签名未设过期时间，长期有效"}
    try:
        dt = datetime.datetime.strptime(exp, "%Y%m%d%H%M%S")
    except Exception:
        return {"stable": True, "expire": exp, "ttl": 0, "note": "过期时间格式未知，按长期有效处理"}
    ttl = int((dt - datetime.datetime.now()).total_seconds())
    stable = ttl > 3600          # 还能活 1 小时以上就算稳定
    return {
        "stable": stable, "expire": dt.strftime("%Y-%m-%d %H:%M"),
        "ttl": ttl, "signed": True,
        "note": ("链接有效期至 %s（约 %d 天）" % (dt.strftime("%Y-%m-%d %H:%M"), ttl // 86400))
                if stable else ("链接仅 %d 秒有效" % max(ttl, 0)),
    }


# ---------------------------------------------------------------- 二维码
def make_qr_svg(text, scale=8, border=4):
    """画【标准】二维码（实心方块），不是 Micro QR。

    踩过两个坑，都记在这里：
      1. segno.make() 默认会自动选 Micro QR（短券码 → 15x15 / 17x17）。
         Micro QR 很多扫码器根本不认（微信、老旧扫码枪、机场核销设备），
         用户反馈"生成的不是标准二维码"就是这个原因。必须 micro=False 强制 21x21 起。
      2. segno.svg_inline() 默认输出 stroke 描边路径（class="qrline"），
         缩小后线条细、有间隙，识别率低。这里按 matrix 自己画实心方块。
    """
    try:
        import segno
        q = segno.make(text, error="m", micro=False)     # 关键：强制标准 QR
        m = q.matrix
        n = len(m)
        total = n + border * 2
        px = total * scale
        out = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
               'viewBox="0 0 %d %d" shape-rendering="crispEdges">' % (px, px, total, total)]
        out.append('<rect width="%d" height="%d" fill="#fff"/>' % (total, total))
        for y in range(n):
            run = 0
            for x in range(n + 1):
                on = x < n and bool(m[y][x])
                if on:
                    run += 1
                elif run:
                    out.append('<rect x="%d" y="%d" width="%d" height="1" fill="#000"/>'
                               % (x - run + border, y + border, run))
                    run = 0
        out.append('</svg>')
        return "".join(out)
    except Exception:
        return None


# ---------------------------------------------------------------- 分享核销会话
# 设计要点：按需续期（懒刷新）。只有当有人正在看二维码页时才会去拉新码，
# 没人看就零请求；超过 SHARE_IDLE 无人访问自动失效；点「停止」立即销毁。
SHARES = {}
SHARE_LOCK = threading.Lock()
SHARE_IDLE = 30 * 60            # 无 KV（本地内存）：30 分钟无人访问自动失效
SHARE_IDLE_PERSIST = 7 * 86400  # 有 KV（云端持久）：7 天无人访问才回收，日常只受"停用"控制
HOST = os.environ.get("UBRP_HOST") or ("0.0.0.0" if os.environ.get("UBRP_CLOUD") else "127.0.0.1")
CLOUD = bool(os.environ.get("UBRP_CLOUD"))            # 云端部署模式
PUSH_KEY = os.environ.get("UBRP_PUSH_KEY") or ""      # 本地推送凭证用的共享密钥


# 银联侧判定凭证失效的关键词/返回码（抓包未见真实样本，按常见形态保守匹配）
AUTH_EXPIRED_CODES = re.compile(
    r"900001|900002|token|登录|未授权|失效|过期|unauthor|unlogin|invalid.*token", re.I)


def guess_profile(merchant="", title=""):
    """按服务商判定机场 / 高铁两套样式"""
    t = (merchant or "") + (title or "")
    if "高铁" in t or "悦途" in t or "rail" in t.lower():
        return "RAIL"
    if "机场" in t or "龙腾" in t or "airport" in t.lower():
        return "AIRPORT"
    return "GENERIC"


def share_fill(s):
    """拉一次券码 + 重画二维码

    mode=official：官方链接本身就长期有效（实测洁牙 28 天、KLOOK 无过期），
                   一次生成即可直接分享，任何网络都能打开，不需要本机在线。
    mode=live    ：动态码 60 秒就换，只能由本机活页面持续续期。
    """
    r = refresh_coupon(s["token"], s["deviceId"], s["couponId"])
    now = time.time()
    if not r.get("ok"):
        e = r.get("err") or {}
        code = str(e.get("code", ""))
        msg = str(e.get("msg", ""))
        s["err"] = ("%s %s" % (code, msg)).strip() or "刷新失败"
        # token 失效是终态，重试一万次也没用——明确告诉用户去重推凭证
        if AUTH_EXPIRED_CODES.search(code + " " + msg):
            s["authExpired"] = True
            s["err"] = "凭证已过期，请让分享人在本机重新推送一次凭证到云端。"
        s["expireAt"] = now + 60          # 出错 60 秒后重试
        return s

    s["authExpired"] = False
    s["fetchCount"] = s.get("fetchCount", 0) + 1
    s["lastFetch"] = time.strftime("%H:%M:%S")
    s["code"] = r["code"]
    s["codeType"] = r["codeType"]
    s["mrchUrl"] = r.get("mrchUrl", "")
    s["fetchedAt"] = r.get("fetchedAt", "")
    s["linkStable"] = r.get("linkStable", False)
    s["linkExpire"] = r.get("linkExpire", "")
    s["linkNote"] = r.get("linkNote", "")
    s["err"] = ""

    if r.get("linkStable"):
        # 官方链接长期有效 → 直接把它当分享链接，不续期、不依赖本机
        s["mode"] = "official"
        s["refreshTime"] = 0
        s["qrTarget"] = r["mrchUrl"]
        s["expireAt"] = 0
    else:
        s["mode"] = "live"
        s["refreshTime"] = r["refreshTime"]
        s["qrTarget"] = r["qrTarget"]
        s["expireAt"] = now + (r["refreshTime"] or 0)
        s["bornAt"] = now

    s["svg"] = make_qr_svg(s["qrTarget"] or s["code"], scale=8) or ""
    return s


def share_poll(sid, real_view=False):
    """有人访问时才调用；到期就续，没人访问就啥也不干"""
    s = SHARES.get(sid)
    if not s:
        return None
    now = time.time()
    idle = SHARE_IDLE_PERSIST if s.get("persistent") else SHARE_IDLE
    if now - s["lastPoll"] > idle:
        SHARES.pop(sid, None)
        return None
    # 硬上限：活链接最多活这么久，到点自动作废，避免"谁拿到谁永远能看"
    ttl = int(load_settings().get("shareTtl", 0) or 0)
    if ttl and s.get("mode") == "live" and now - s.get("bornAt", now) > ttl:
        SHARES.pop(sid, None)
        return None
    s["lastPoll"] = now
    if real_view:
        s["views"] = s.get("views", 0) + 1
    # 凭证已过期：给明确终态，别让前端每 15 秒傻等
    if s.get("authExpired"):
        return s
    if s.get("mode") == "live" and s["refreshTime"] > 0 and now >= s["expireAt"]:
        with SHARE_LOCK:                      # 双检加锁：多端同时看也只拉一次
            if time.time() >= s["expireAt"]:
                share_fill(s)
    return s


def share_restore(sid):
    """按 sid 恢复会话，优先内存，其次 KV。

    返回 (state, msg)：
      ok      已就位（内存或已从 KV 恢复）
      stopped 被人主动停用
      missing 真的没有这个链接
      error   KV 暂时不可用（网络/5xx），【不能】当成 missing
    """
    if not sid:
        return "missing", "链接地址不完整。"
    if sid in SHARES:
        return "ok", ""
    if not kv_enabled():
        return "missing", "这个链接已失效或已被停止，请回到管理页面重新启用。"

    state, val = kv_get(sid)
    if state == "error":
        return "error", "服务暂时不可用，请稍后重试（若持续出现，请让分享人检查云端配置）。"
    if state == "missing" or not isinstance(val, dict):
        return "missing", "这个链接不存在或已被停止。"
    if val.get("status") == "stopped":
        return "stopped", "分享人已停用这个链接。如需继续使用，请让他重新生成。"

    # 恢复到内存：凭证优先从账号库取（云端靠 UBRP_ACCOUNTS 恢复），
    # 取不到就留空，等 share_fill 时报"凭证已过期"而不是干等。
    acc = None
    store = load_store()
    aid = val.get("accountId")
    if aid:
        acc = next((a for a in store["accounts"] if a.get("id") == aid), None)
    now = time.time()
    s = {"id": sid, "accountId": aid,
         "token": (acc or {}).get("token", ""), "deviceId": (acc or {}).get("deviceId", ""),
         "couponId": val.get("couponId", ""),
         "title": val.get("title", ""), "merchant": val.get("merchant", ""),
         "expireTime": val.get("expireTime", ""), "cardNo": val.get("cardNo", ""),
         "imgUrl": val.get("imgUrl", ""), "orderNo": val.get("orderNo", ""),
         "bankName": val.get("bankName", ""), "profile": val.get("profile", ""),
         "activityId": val.get("activityId", ""), "useDirections": val.get("useDirections", ""),
         "code": "", "svg": "", "refreshTime": 0, "expireAt": 0,
         "mode": "live", "fetchedAt": "", "err": "", "lastPoll": now,
         "bornAt": val.get("bornAt", now), "views": val.get("views", 0),
         "fetchCount": 0, "lastFetch": "", "authExpired": False,
         "persistent": True}
    if not s["token"]:
        s["authExpired"] = True
        s["err"] = "凭证已过期，请让分享人在本机重新推送一次凭证到云端。"
    SHARES[sid] = s
    return "ok", ""


def share_promote(s, cloud, push_key="", acc=None, extra=None):
    """把本机会话推到云端，让云端写 KV，从而产出公网可开的 /union/<sid>。

    返回 True/False。失败不影响本机内存态，只是链接仍然只能本机打开。
    """
    payload = {
        "id": s["id"],
        "key": push_key or "",
        "session": {"couponId": s.get("couponId", ""), "accountId": s.get("accountId"),
                    "title": s.get("title", ""), "merchant": s.get("merchant", ""),
                    "expireTime": s.get("expireTime", ""), "cardNo": s.get("cardNo", ""),
                    "imgUrl": s.get("imgUrl", ""), "orderNo": s.get("orderNo", ""),
                    "bankName": s.get("bankName", ""), "profile": s.get("profile", ""),
                    "activityId": s.get("activityId", ""),
                    "useDirections": s.get("useDirections", ""),
                    "bornAt": s.get("bornAt", time.time()), "views": 0,
                    "status": "active", "updatedAt": time.time()},
        # 凭证一并带过去，否则云端没凭证取码会直接进"凭证已过期"终态
        "accounts": [acc] if acc else [],
    }
    try:
        req = urllib.request.Request(cloud + "/api/share/promote",
                                     data=json.dumps(payload).encode("utf-8"),
                                     method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read().decode("utf-8"))
        return bool(d.get("ok"))
    except Exception:
        return False


def share_persist(s):
    """把会话写进 KV（只存元数据，绝不存凭证）"""
    if not kv_enabled():
        return False
    val = {"couponId": s.get("couponId", ""), "accountId": s.get("accountId"),
           "title": s.get("title", ""), "merchant": s.get("merchant", ""),
           "expireTime": s.get("expireTime", ""), "cardNo": s.get("cardNo", ""),
           "imgUrl": s.get("imgUrl", ""), "orderNo": s.get("orderNo", ""),
           "bankName": s.get("bankName", ""), "profile": s.get("profile", ""),
           "activityId": s.get("activityId", ""), "useDirections": s.get("useDirections", ""),
           "bornAt": s.get("bornAt", time.time()), "views": s.get("views", 0),
           "status": "active", "updatedAt": time.time()}
    return kv_put(s["id"], val)


def lan_ip():
    """本机在局域网里的地址，用于给手机 / 同行的人拼链接"""
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.connect(("223.5.5.5", 80))
        ip = sk.getsockname()[0]
        sk.close()
        return ip
    except Exception:
        return ""


# 可用的免费二维码 API（都能 URL 外拼券码，都只出图、没有标题）
QR_APIS = {
    "qrserver": {"name": "qrserver（国外，你实测最快）",
                 "tpl": "https://api.qrserver.com/v1/create-qr-code/?data={data}"},
    "cliim":    {"name": "草料二维码（国内）",
                 "tpl": "https://cli.im/api/qrcode/code?text={data}"},
    "qrtool":   {"name": "qrtool.cn（国内）",
                 "tpl": "https://api.qrtool.cn/?text={data}"},
    "isoyu":    {"name": "isoyu（国内）",
                 "tpl": "https://api.isoyu.com/qr/?m=1&e=M&p=10&url={data}"},
}


def qrserver_url(text, api=None):
    """拼免费二维码 API 的公网链接（对方打开就是一张二维码图）。

    只用于动态码：静态码长期有效，不上公网 API，本地画即可。
    不再带 size 参数——链接越短越好，默认尺寸足够扫。
    """
    if not text:
        return ""
    key = api or load_settings().get("qrApi", "qrserver")
    tpl = (QR_APIS.get(key) or QR_APIS["qrserver"])["tpl"]
    return tpl.format(data=quote(text, safe=""))


def hosted_url(s):
    """拼自建托管页链接。

    刻意只带 code + ts 两个参数：标题、服务商、说明文字、有效期全部写死在
    网页里（网页能按券码前缀自动识别机场/高铁），链接因此短很多。

    文件名自适应：填的地址若以 .html 结尾就用它，否则走根路径
    （帽子云默认文档是 index.html，把文件改名成 index.html 后要访问根路径）。
    """
    base = (load_settings().get("hostedBase") or "").strip().rstrip("/")
    if not base:
        return ""
    q = {"code": s.get("code", ""),
         "ts": time.strftime("%Y%m%d%H%M%S", time.localtime(s.get("bornAt", 0) or time.time()))}
    return (base + "?" if base.lower().endswith(".html") else base + "/?") + urlencode(q)


def host_check(base=""):
    """自检托管页是否真的能打开：拼一个测试链接去请求，看返回什么"""
    base = (base or load_settings().get("hostedBase") or "").strip().rstrip("/")
    if not base:
        return {"ok": False, "err": "还没填托管地址"}
    test = (base + "?" if base.lower().endswith(".html") else base + "/?") + urlencode(
        {"code": "TEST1234", "ts": time.strftime("%Y%m%d%H%M%S", time.localtime())})
    try:
        r = http_get(test, timeout=15)
        low = r["body"].lower()
        has_encoder = "makematrix" in low
        is_html = "<html" in low or "<!doctype" in low
        notfound = ("not_found" in low or "does not exist" in low
                    or ("404" in low and not is_html))
        ok = r["status"] == 200 and is_html and has_encoder and not notfound
        hint = ""
        if r["status"] == 404 or notfound:
            hint = "这个路径上没有这个文件——若已改名成 index.html，地址里就不要带 /qrshow.html"
        elif r["status"] == 200 and not is_html:
            hint = "返回的不是网页（%s）——多半是托管平台的报错 JSON" % (r["type"] or "未知类型")
        elif r["status"] == 200 and is_html and not has_encoder:
            hint = "打开的像是别的页面，没找到二维码编码器"
        return {"ok": ok, "status": r["status"], "type": r["type"],
                "bytes": r["bytes"], "ms": r["ms"], "test": test,
                "hasEncoder": has_encoder, "hint": hint,
                "head": r["body"][:180].replace("\n", " ")}
    except Exception as e:
        return {"ok": False, "err": "%s: %s" % (type(e).__name__, e), "test": test}


def share_public(s, base=""):
    lan = lan_ip()
    official = s.get("mode") == "official"
    st = load_settings()
    cloud = (st.get("cloudUrl") or "").strip().rstrip("/")
    # 只有会变的码才需要拼公网链接；静态码 url 留空，前端走本地二维码
    if s.get("codeType") == "dynamic":
        # 优先级：已同步到云端 → 用云端 /union/ 链接（公网可开、长期有效）
        #         自建托管页   → 用托管页
        #         否则         → qrserver 兜底
        if s.get("cloudPromoted") and cloud:
            url = "%s/union/%s" % (cloud, s["id"])
        elif CLOUD:
            # 云端自身：请求 Host 就是公网地址，拼完整 URL（否则前端复制到的是半截）
            host = (base or "").replace("http://", "").replace("https://", "").rstrip("/")
            if host and "." in host:
                url = "https://%s/union/%s" % (host, s["id"])
            else:
                url = "/union/%s" % s["id"]
        else:
            url = hosted_url(s) if st.get("qrMode") == "hosted" else ""
            if not url:
                url = qrserver_url(s.get("qrTarget") or s.get("code", ""))
    else:
        url = s.get("mrchUrl") or ""
    return {
        "id": s["id"], "title": s.get("title", ""), "merchant": s.get("merchant", ""),
        "couponId": s.get("couponId", ""),
        "fetchCount": s.get("fetchCount", 0), "lastFetch": s.get("lastFetch", ""),
        "views": s.get("views", 0), "authExpired": bool(s.get("authExpired", False)),
        "imgUrl": s.get("imgUrl", ""), "orderNo": s.get("orderNo", ""),
        "bankName": s.get("bankName", ""), "profile": s.get("profile", ""),
        "activityId": s.get("activityId", ""), "useDirections": s.get("useDirections", ""),
        "persistent": bool(s.get("persistent", kv_enabled())),
        "cloudPromoted": bool(s.get("cloudPromoted", False)),
        "ttl": int(load_settings().get("shareTtl", 0) or 0),
        "deadAt": (s.get("bornAt", 0) + int(load_settings().get("shareTtl", 0) or 0))
                  if (int(load_settings().get("shareTtl", 0) or 0) and s.get("mode") == "live") else 0,
        "expireTime": s.get("expireTime", ""), "cardNo": s.get("cardNo", ""),
        "code": s.get("code", ""), "codeType": s.get("codeType", "dynamic"),
        "refreshTime": s.get("refreshTime", 0), "svg": s.get("svg", ""),
        "mrchUrl": s.get("mrchUrl", ""),
        "expireAt": s.get("expireAt", 0), "now": time.time(),
        "fetchedAt": s.get("fetchedAt", ""), "err": s.get("err", ""),
        "mode": "official" if official else "live",
        "linkStable": s.get("linkStable", False),
        "linkExpire": s.get("linkExpire", ""), "linkNote": s.get("linkNote", ""),
        "anyNetwork": official and s.get("codeType") == "dynamic",
        "url": url,
        "lanUrl": ("http://%s:%d/s/%s" % (lan, PORT, s["id"])) if lan else "",
        "lanReachable": HOST not in ("127.0.0.1", "localhost"),
    }



# ---------------------------------------------------------------- 官方链接探测
SPA_MARKS = ["<div id=app", '<div id="app"', "__vue", "app.js", "manifest.js",
             "__POWERED_BY_QIANKUN__", "qiankun", "single-spa",
             "chunk-vendors", "window.__", "bundle.js"]
PAGE_MARKS = {
    "核销/验证页": ["verification", "核销", "verify", "请工作人员", "扫描上方二维码"],
    "网点查询页": ["可用网点", "网点", "station", "服务网点", "查询服务网点"],
    "引导/说明页": ["使用说明", "使用指引", "guide", "help", "说明"],
}


def http_get(url, timeout=12):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
    })
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
        return {"status": r.status, "type": (r.headers.get("Content-Type") or "")[:40],
                "bytes": len(body), "ms": int((time.time() - t0) * 1000),
                "body": body.decode("utf-8", "replace")}


def probe_official(token, device_id, coupon_id, do_open=False):
    """拉一次新鲜券（60 秒内的签名），再逐个试 URL 变体，报告每种的实际返回"""
    r = refresh_coupon(token, device_id, coupon_id)
    # 用【原始】链接构造变体：refresh_coupon 返回的已按设置转换过，
    # 拿它去探测就生成不出"去掉 #"这个变体了。
    mrch = (r.get("mrchUrlRaw") or r.get("mrchUrl") or "") if r.get("ok") else ""
    out = {"ok": bool(mrch), "code": r.get("code", ""), "mrchUrl": mrch,
           "mrchUrlUse": (r.get("mrchUrl") or ""),
           "err": r.get("err") if not r.get("ok") else None, "variants": []}
    if not mrch:
        out["err"] = out["err"] or "这条权益官方没有返回核销链接"
        return out
    if do_open:
        try:
            webbrowser.open(official_url(mrch))   # 用转换后的，原始带 # 的打不开
            out["opened"] = True
            out["openedUrl"] = official_url(mrch)
        except Exception as e:
            out["opened"] = False
            out["openErr"] = str(e)
        return out

    sp = urlsplit(mrch)
    frag = sp.fragment or ""
    cand = [("① 原始链接（含 # 路由）", mrch)]
    raw_bytes = None
    if frag:
        p = frag if frag.startswith("/") else "/" + frag
        cand.append(("② 去掉 # 改 history 路径", urlunsplit((sp.scheme, sp.netloc, p, "", ""))))
        q2 = urlsplit(cand[1][1]).query
        if "hideWebviewNavBar" in q2:
            from urllib.parse import parse_qsl, urlencode
            pairs = [(k, v) for k, v in parse_qsl(q2) if k != "hideWebviewNavBar"]
            cand.append(("③ history 路径 + 去掉 hideWebviewNavBar",
                         urlunsplit((sp.scheme, sp.netloc, p.split("?")[0], urlencode(pairs), ""))))
    cand.append(("④ 只取域名根（作对照）", urlunsplit((sp.scheme, sp.netloc, "/", "", ""))))

    for name, u in cand:
        try:
            g = http_get(u)
            low = g["body"].lower()
            marks = [k for k, ws in PAGE_MARKS.items() if any(w.lower() in low for w in ws)]
            spa = [m for m in SPA_MARKS if m.lower() in low]
            out["variants"].append({"name": name, "url": u[:110], "status": g["status"],
                                    "type": g["type"], "bytes": g["bytes"], "ms": g["ms"],
                                    "pageMarks": marks, "spaMarks": spa,
                                    "head": g["body"][:160].replace("\n", " ")})
        except Exception as e:
            out["variants"].append({"name": name, "url": u[:110], "status": "ERR",
                                    "type": "", "bytes": 0, "ms": 0, "pageMarks": [],
                                    "spaMarks": [], "head": "%s: %s" % (type(e).__name__, e)})
    # 判定哪个变体最可能是真核销页：
    # 与"域名根"返回的字节数不同 = 服务端确实按这个路径路由了
    root = next((v for v in out["variants"] if v["name"].startswith("④")), None)
    root_bytes = (root or {}).get("bytes")
    for v in out["variants"]:
        v["routed"] = bool(root_bytes is not None and v["bytes"] != root_bytes
                           and v["status"] == 200)
        v["verification"] = "核销" in "".join(v["pageMarks"])
    best = next((v for v in out["variants"]
                 if v["routed"] and v["verification"] and v["status"] == 200), None)
    if best:
        out["recommend"] = best["name"]
        out["recommendWhy"] = ("这个变体返回的内容与访问域名根时不同（%dB vs %dB），"
                               "说明服务端按这条路径路由到了核销页"
                               % (best["bytes"], root_bytes or 0))
        mk = [m for m in best["spaMarks"] if "qiankun" in m.lower()
              or "POWERED_BY" in m or "single-spa" in m.lower()]
        if mk:
            out["micro"] = True
            out["microWhy"] = ("页面里有微前端标记（%s）。这类页面是给 App 内嵌用的子应用，"
                               "必须由宿主容器把它挂载上去才会渲染；直接用浏览器打开就是白屏、"
                               "也不报错——这跟你看到的现象一致。"
                               % ",".join(mk))
            out["advice"] = ("别再折腾官方链接了：它独立打不开。"
                             "机场权益照旧编【裸券码】即可，工作人员扫的是码不是链接。")
        else:
            out["micro"] = False
            out["microWhy"] = ""
            out["advice"] = "可以用浏览器直接打开这个变体验证"
    else:
        out["recommend"] = ""
        out["recommendWhy"] = "所有变体返回的内容都一样，服务端没有按路径区分"
    return out


# ---------------------------------------------------------------- Cloudflare KV
# 三态设计（用户要求，勿简化成二态）：
#   found   命中，value 是 dict
#   missing KV 明确说没有这个 key → 链接真的不存在
#   error   网络超时 / 5xx / 未配置 → KV 暂时不可用
# 把 error 当成 missing 会误杀还在生效的链接，这是这套架构最容易翻车的地方。
KV_FIND_ACCOUNT = True          # 是否已尝试过拉取 account id
KV_ACCOUNT_ID = os.environ.get("UBRP_KV_ACCOUNT") or ""

def kv_conf():
    """返回 (account, token, namespace)；任一缺失返回空串"""
    ns = os.environ.get("UBRP_KV_NAMESPACE") or ""
    tk = os.environ.get("UBRP_KV_TOKEN") or ""
    return (KV_ACCOUNT_ID or "", tk, ns)


def kv_enabled():
    a, t, n = kv_conf()
    return bool(a and t and n)


def kv_find_account(token):
    """首次调用时用 API token 反查 account id 并缓存（只查一次）"""
    global KV_ACCOUNT_ID, KV_FIND_ACCOUNT
    if KV_ACCOUNT_ID or not KV_FIND_ACCOUNT:
        return KV_ACCOUNT_ID
    KV_FIND_ACCOUNT = False
    try:
        req = urllib.request.Request("https://api.cloudflare.com/client/v4/accounts",
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8"))
        for acc in (data.get("result") or []):
            if acc.get("id"):
                KV_ACCOUNT_ID = acc["id"]
                return KV_ACCOUNT_ID
    except Exception:
        pass
    return ""


def _kv_url(key=""):
    a, t, n = kv_conf()
    if not a:
        a = kv_find_account(t)
    if not (a and t and n):
        return "", ""
    base = ("https://api.cloudflare.com/client/v4/accounts/%s/storage/kv/namespaces/%s"
            % (a, n))
    return (base + "/values/" + urllib.parse.quote(key, safe="")) if key else base, t


def kv_get(key):
    """→ (state, value_dict)   state ∈ found / missing / error"""
    if not kv_enabled() and not os.environ.get("UBRP_KV_TOKEN"):
        return "error", None
    url, tk = _kv_url(key)
    if not url:
        return "error", None
    try:
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tk})
        with urllib.request.urlopen(req, timeout=8) as r:
            raw = r.read().decode("utf-8")
        try:
            return "found", json.loads(raw)
        except Exception:
            return "found", None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "missing", None      # KV 明确没有这个 key
        return "error", None            # 5xx / 429 / 403 都算暂时不可用
    except Exception:
        return "error", None            # 超时、DNS、连接失败


def kv_put(key, value):
    """→ True/False。失败不抛，调用方按'未持久化'处理但不影响本次内存态"""
    url, tk = _kv_url(key)
    if not url:
        return False
    try:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, method="PUT", data=body,
                                     headers={"Authorization": "Bearer " + tk,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
        return True
    except Exception:
        return False


def kv_del(key):
    url, tk = _kv_url(key)
    if not url:
        return False
    try:
        req = urllib.request.Request(url, method="DELETE",
                                     headers={"Authorization": "Bearer " + tk})
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- 云端鉴权
# fail-closed：CLOUD 模式没设密码就直接拒绝启动，绝不裸奔。
ADMIN_PASSWORD = os.environ.get("UBRP_ADMIN_PASSWORD") or ""
ADMIN_SESSIONS = {}                      # token -> 过期时间戳（内存，重启即失效）
ADMIN_SESSION_TTL = 12 * 3600

# 这些路径云端必须免密：访客页、访客轮询、本机推送凭证、登录页、静态资源
PUBLIC_PATHS = ("/s/", "/union/", "/api/share/", "/api/push", "/api/share/promote",
                "/login", "/login.html", "/api/login", "/api/logout",
                "/static/", "/favicon")


def is_public(path):
    if path.startswith(PUBLIC_PATHS):
        return True
    if path.endswith((".html", ".css", ".js", ".svg", ".png", ".ico")):
        return True
    return False


def need_login_redirect(h):
    """未登录时怎么回应，取决于谁在问：

    浏览器导航（Accept 里有 text/html）→ 302 跳登录页，
      否则用户只会看到一行 JSON 文本 "需要管理员登录"，压根没地方输密码
      （这正是之前踩的坑，用户以为部署坏了）。
    程序调用（fetch / XHR）→ 401 JSON，让前端自己处理。
    """
    accept = (h.headers.get("Accept") or "")
    return "text/html" in accept and "application/json" not in accept.split(",")[0]


def send_login_or_401(h):
    if need_login_redirect(h):
        h.send_response(302)
        h.send_header("Location", "/login")
        h.send_header("Content-Length", "0")
        h.send_header("Cache-Control", "no-store")
        h.end_headers()
        return
    h._send(401, {"ok": False, "err": "需要管理员登录", "needLogin": True})


def admin_ok(headers):
    """校验 X-Admin-Token 头或 cookie"""
    if not CLOUD:
        return True
    if not ADMIN_PASSWORD:
        return False                     # fail-closed
    tok = headers.get("X-Admin-Token") or ""
    if not tok:
        cookie = headers.get("Cookie") or ""
        m = re.search(r"ubrp_admin=([0-9a-f]+)", cookie)
        tok = m.group(1) if m else ""
    if not tok:
        return False
    exp = ADMIN_SESSIONS.get(tok)
    return bool(exp and exp > time.time())


def new_admin_session():
    tok = uuid.uuid4().hex + uuid.uuid4().hex
    ADMIN_SESSIONS[tok] = time.time() + ADMIN_SESSION_TTL
    return tok


UNION_TERM_HTML = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>__TITLE__</title><style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
     font-family:arial,"PingFang SC","Microsoft YaHei",sans-serif;background:#f5f7fa;color:#0f172a}
.box{background:#fff;border-radius:14px;padding:30px 26px;max-width:340px;text-align:center;
     box-shadow:0 8px 28px rgba(15,23,42,.09)}
h1{font-size:17px;margin:0 0 10px}
p{font-size:13.5px;color:#64748b;line-height:1.75;margin:0}
.ic{font-size:38px;margin-bottom:10px}
</style></head><body><div class="box">
<div class="ic">__ICON__</div><h1>__TITLE__</h1><p>__MSG__</p></div></body></html>"""


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "UBRPManager/1.0"

    def log_message(self, fmt, *args):
        pass  # 安静一点

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    # ---- GET
    def do_GET(self):
        try:
            self._do_GET()
        except Exception as e:
            self._fail("GET", e)

    def _do_GET(self):
        path = urlparse(self.path).path

        # 云端鉴权门：白名单之外一律要管理员会话。
        # 顺序很关键——访客页 /s/ /union/ 和轮询接口 /api/share/ 必须放行，
        # 否则朋友打不开链接。登录页本身也要放行，不然死锁。
        if not is_public(path) and not admin_ok(self.headers):
            send_login_or_401(self)
            return

        # 访客核销页：/union/<sid>（新）与 /s/<sid>（旧链接兼容）
        if path.startswith("/union/"):
            sid = path[len("/union/"):].strip("/")
            self._serve_union(sid)
            return
        if path.startswith("/s/"):
            sid = path[3:].strip("/")
            self._serve_union(sid)
            return

        # 访客页轮询数据
        if path.startswith("/api/share/"):
            sid = path.split("/")[3]
            s = share_poll(sid, real_view=True)
            if not s:
                self._send(200, {"ok": False, "err": "链接已失效，请重新启用"})
                return
            base = share_base(self.headers.get("Host") or "")
            self._send(200, {"ok": True, "share": share_public(s, base)})
            return

        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(STATIC_DIR, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, "index.html 读取失败: %s" % e, "text/plain; charset=utf-8")
            return
        if path == "/login" or path == "/login.html":
            try:
                with open(os.path.join(STATIC_DIR, "login.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, "login.html 读取失败: %s" % e, "text/plain; charset=utf-8")
            return

        # 刷新页面后靠它恢复"监控中"状态和停止按钮
        if path == "/api/shares":
            base = share_base(self.headers.get("Host") or "")
            out = []
            for sid, sh in list(SHARES.items()):
                try:
                    out.append(share_public(sh, base))
                except Exception:
                    continue
            self._send(200, {"ok": True, "shares": out})
            return

        if path == "/api/accounts":
            store = load_store()
            self._send(200, {
                "ok": True,
                "accounts": [public_account(a) for a in store["accounts"]],
                "activeId": store.get("activeId", ""),
            })
            return
        self._send(404, {"ok": False, "err": "not found"})

# ------------------------------------------------ 访客页
    def _serve_union(self, sid):
        """出访客页。会话恢复失败时区分三种原因，给不同文案。"""
        st, err = share_restore(sid)
        if st == "ok":
            try:
                with open(os.path.join(STATIC_DIR, "union.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, "union.html 读取失败: %s" % e, "text/plain; charset=utf-8")
            return
        # 非 ok：直接返回一张终态页，不再加载 union.html 的轮询逻辑
        title = {"stopped": "链接已停用",
                 "missing": "链接不存在",
                 "error": "服务暂时不可用"}.get(st, "链接不可用")
        icon = {"stopped": "🛑", "missing": "🔗", "error": "⚠️"}.get(st, "🔗")
        body = (UNION_TERM_HTML.replace("__TITLE__", title)
                               .replace("__MSG__", err or "")
                               .replace("__ICON__", icon))
        self._send(200, body, "text/html; charset=utf-8")

    # ---- POST
    def do_POST(self):
        try:
            self._do_POST()
        except Exception as e:
            self._fail("POST", e)

    def _do_POST(self):
        path = urlparse(self.path).path
        if not is_public(path) and not admin_ok(self.headers):
            self._send(401, {"ok": False, "err": "需要管理员登录", "needLogin": True})
            return
        b = self._body()

        def cred():
            """从 accountId 或临时凭证里取出 token/deviceId"""
            aid = b.get("accountId")
            if aid:
                a = find_account(load_store(), aid)
                if a:
                    return a.get("token", ""), a.get("deviceId", ""), a
            return b.get("token", ""), b.get("deviceId", ""), None

        if path == "/api/accounts":
            token = (b.get("token") or "").strip()
            dev = (b.get("deviceId") or "").strip()
            if not token or not dev:
                self._send(200, {"ok": False, "err": "token 和 deviceId 都不能为空"})
                return
            store = load_store()
            custom = bool((b.get("name") or "").strip())
            # 同 token 视为同一账号，覆盖更新
            target = None
            for a in store["accounts"]:
                if a.get("token") == token:
                    target = a
                    break
            if target is None:
                target = {"id": uuid.uuid4().hex[:10],
                          "createdAt": time.strftime("%Y-%m-%d %H:%M:%S")}
                store["accounts"].append(target)
            target.update({"token": token, "deviceId": dev,
                           "note": b.get("note", target.get("note", "")),
                           "lastUsed": time.strftime("%Y-%m-%d %H:%M:%S")})
            if custom:
                target["name"] = b["name"].strip()
                target["custom"] = True
            elif not target.get("custom"):
                target["name"] = "账号%d" % (store["accounts"].index(target) + 1)

            # 联网取「邮箱 · 发卡行 · 卡号后4位」作为默认名
            auto, err = suggest_name(token, dev)
            if auto:
                target["autoName"] = auto
                target["lastEmail"] = auto.split(" · ")[0]
                target["lastOk"] = True
                if not target.get("custom"):
                    target["name"] = auto
            else:
                target["lastOk"] = False
            store["activeId"] = target["id"]
            save_store(store)
            self._send(200, {"ok": True, "account": public_account(target),
                             "autoName": auto, "autoNameErr": err,
                             "accounts": [public_account(a) for a in store["accounts"]]})
            return

        if path.startswith("/api/accounts/") and path.endswith("/check"):
            aid = path.split("/")[3]
            a = find_account(load_store(), aid)
            if not a:
                self._send(200, {"ok": False, "err": "账号不存在"})
                return
            r = api_post("/user/queryUserInfo", a["token"], a["deviceId"], {})
            good = ok(r)
            store = load_store()
            ta = find_account(store, aid)
            if ta is not None:
                ta["lastOk"] = good
                ta["lastEmail"] = (r.get("data", {}) or {}).get("email", "") if good else ""
                save_store(store)
            self._send(200, {"ok": good,
                             "email": (r.get("data", {}) or {}).get("email", "") if good else "",
                             "err": r.get("rspInfo", {}) if not good else None})
            return

        if path.startswith("/api/accounts/") and path.endswith("/autoname"):
            aid = path.split("/")[3]
            a = find_account(load_store(), aid)
            if not a:
                self._send(200, {"ok": False, "err": "账号不存在"})
                return
            name, err = suggest_name(a["token"], a["deviceId"])
            if not name:
                self._send(200, {"ok": False, "err": err or "没能取到账号信息"})
                return
            store = load_store()
            ta = find_account(store, aid)
            if ta is not None:
                ta["autoName"] = name
                ta["lastEmail"] = name.split(" · ")[0]
                ta["lastOk"] = True
                save_store(store)
            self._send(200, {"ok": True, "name": name,
                             "accounts": [public_account(x) for x in store["accounts"]]})
            return

        if path == "/api/accounts/rename":
            store = load_store()
            a = find_account(store, b.get("id"))
            if a is None:
                self._send(200, {"ok": False, "err": "账号不存在"})
                return
            a["name"] = (b.get("name") or "").strip() or a["name"]
            save_store(store)
            self._send(200, {"ok": True,
                             "accounts": [public_account(x) for x in store["accounts"]]})
            return

        if path == "/api/benefits":
            token, dev, acc = cred()
            if not token or not dev:
                self._send(200, {"ok": False, "err": "缺少凭证"})
                return
            res = fetch_benefits(token, dev, only_type=b.get("type", 2))
            if acc is not None:
                store = load_store()
                ta = find_account(store, acc["id"])
                if ta is not None:
                    ta["lastUsed"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    ta["lastOk"] = res.get("ok")
                    ta["lastEmail"] = (res.get("user") or {}).get("email", "") if res.get("ok") else ""
                    save_store(store)
            res["accountName"] = acc.get("name") if acc else ""
            res["accountId"] = acc["id"] if acc else None
            self._send(200, res)
            return

        if path == "/api/coupon/refresh":
            token, dev, _ = cred()
            cid = b.get("couponId")
            if not token or not dev or not cid:
                self._send(200, {"ok": False, "err": "参数不全"})
                return
            self._send(200, refresh_coupon(token, dev, cid,
                                           b.get("recordId"), b.get("orderStatus", 4)))
            return

        if path == "/api/qrcode":
            text = b.get("text") or ""
            if not text:
                self._send(200, {"ok": False, "err": "空内容"})
                return
            svg = make_qr_svg(text, scale=int(b.get("scale", 7)), border=int(b.get("border", 2)))
            if svg is None:
                self._send(200, {"ok": False, "err": "二维码生成失败"})
                return
            self._send(200, {"ok": True, "svg": svg, "text": text})
            return

        if path == "/api/parse-cred":
            self._send(200, parse_credentials(b.get("raw") or ""))
            return

        if path == "/api/login":
            if not CLOUD:
                self._send(200, {"ok": True, "token": ""})
                return
            if not ADMIN_PASSWORD:
                self._send(500, {"ok": False, "err": "云端未设置 UBRP_ADMIN_PASSWORD"})
                return
            pwd = b.get("password") or ""
            if not hmac.compare_digest(pwd, ADMIN_PASSWORD):
                self._send(401, {"ok": False, "err": "密码不对"})
                return
            tok = new_admin_session()
            # 注意：headers 必须用关键字传。之前写成第三个位置参数，
            # 实际被当成 ctype 吃掉了 → Set-Cookie 根本没发出去，
            # 于是登录后跳回首页又 401 跳回登录页，看起来像"密码对但进不去"。
            self._send(200, {"ok": True, "token": tok},
                       headers={"Set-Cookie":
                                "ubrp_admin=%s; Path=/; HttpOnly; SameSite=Lax" % tok})
            return

        if path == "/api/logout":
            tok = self.headers.get("X-Admin-Token") or ""
            ADMIN_SESSIONS.pop(tok, None)
            self._send(200, {"ok": True})
            return

        # ---- 本地：把凭证推送到云端 ----
        if path == "/api/pushcloud":
            st = load_settings()
            url = (st.get("cloudUrl") or "").strip().rstrip("/")
            if not url:
                self._send(200, {"ok": False, "err": "还没填云端地址"})
                return
            store = load_store()
            payload = {"key": st.get("cloudKey", ""),
                       "accounts": [{"id": a["id"], "token": a.get("token", ""),
                                     "deviceId": a.get("deviceId", ""),
                                     "name": a.get("name", "") or a.get("autoName", "")}
                                    for a in store["accounts"]]}
            try:
                req = urllib.request.Request(url + "/api/push",
                                             data=json.dumps(payload).encode(),
                                             method="POST",
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    res = json.loads(r.read().decode())
                self._send(200, {"ok": res.get("ok", False), "count": res.get("count", 0),
                                 "err": res.get("err", ""), "url": url})
            except Exception as e:
                self._send(200, {"ok": False, "err": "%s: %s" % (type(e).__name__, e), "url": url})
            return

        # ---- 云端：接收本地推送的凭证 ----
        # 本机把会话推上来，云端写入 KV → 变成持久的 /union/<sid> 链接
        if path == "/api/share/promote":
            if PUSH_KEY and b.get("key") != PUSH_KEY:
                self._send(401, {"ok": False, "err": "密钥不对"})
                return
            sid = b.get("id") or ""
            if not sid:
                self._send(200, {"ok": False, "err": "缺少 sid"})
                return
            if not kv_enabled():
                self._send(200, {"ok": False,
                                 "err": "云端未配置 KV，无法生成持久链接"})
                return
            accs = b.get("accounts") or []
            if accs:                       # 顺带把凭证一起带过来，确保能取码
                try:
                    store = load_store()
                    keep = {a.get("id") for a in accs}
                    store["accounts"] = [a for a in store["accounts"]
                                         if a.get("id") in keep]
                    for a in accs:
                        if not a.get("id"):
                            continue
                        hit = next((x for x in store["accounts"]
                                    if x.get("id") == a["id"]), None)
                        if hit:
                            hit["token"] = a.get("token", "")
                            hit["deviceId"] = a.get("deviceId", "")
                        else:
                            store["accounts"].append(a)
                    save_store(store)
                except Exception:
                    pass
            okp = kv_put(sid, b.get("session") or {})
            self._send(200, {"ok": bool(okp),
                             "err": "" if okp else "KV 写入失败"})
            return

        if path == "/api/push":
            if PUSH_KEY and b.get("key") != PUSH_KEY:
                self._send(401, {"ok": False, "err": "密钥不对"})
                return
            accs = b.get("accounts") or []
            if not accs:
                self._send(200, {"ok": False, "err": "没有账号"})
                return
            try:
                store = load_store()
                keep = {a.get("id") for a in accs}
                store["accounts"] = [a for a in store["accounts"] if a.get("id") in keep]
                for a in accs:
                    if not a.get("id"):
                        continue
                    hit = next((x for x in store["accounts"] if x.get("id") == a["id"]), None)
                    if hit:
                        hit["token"], hit["deviceId"] = a.get("token", ""), a.get("deviceId", "")
                        if a.get("name"):
                            hit["name"] = a["name"]
                    else:
                        store["accounts"].append(a)
                if not store.get("activeId"):
                    store["activeId"] = store["accounts"][0]["id"] if store["accounts"] else ""
                save_store(store)
                self._send(200, {"ok": True, "count": len(store["accounts"]), "cloud": CLOUD})
            except Exception as e:
                self._send(200, {"ok": False, "err": "%s: %s" % (type(e).__name__, e)})
            return

        if path == "/api/hostcheck":
            self._send(200, host_check(b.get("base") or ""))
            return

        # ---- 官方链接探测 ----
        if path == "/api/probe":
            token, dev, _acc = cred()
            cid = b.get("couponId")
            if not token or not dev or not cid:
                self._send(200, {"ok": False, "err": "参数不全"})
                return
            self._send(200, probe_official(token, dev, cid, do_open=bool(b.get("open"))))
            return

        # ---- 链接生成方式 ----
        if path == "/api/settings":
            s = load_settings()
            if any(k in b for k in ("qrMode", "hostedBase", "qrApi", "cloudUrl",
                                    "cloudKey", "officialForm", "shareTtl")):
                s["qrMode"] = b.get("qrMode", s["qrMode"])
                s["hostedBase"] = (b.get("hostedBase") or "").strip()
                s["qrApi"] = b.get("qrApi", s["qrApi"])
                s["cloudUrl"] = (b.get("cloudUrl") or "").strip().rstrip("/")
                s["cloudKey"] = (b.get("cloudKey") or "").strip()
                s["officialForm"] = b.get("officialForm", s["officialForm"])
                try:
                    s["shareTtl"] = int(b.get("shareTtl", s["shareTtl"]))
                except Exception:
                    pass
                save_settings(s)
            self._send(200, {"ok": True, "settings": s, "lanIp": lan_ip(),
                             "host": HOST, "qrApis": QR_APIS,
                             "publicReady": HOST not in ("127.0.0.1", "localhost")})
            return

        # ---- 自检：一步步试接口，报告每一步耗时和结果 ----
        if path == "/api/diag":
            token, dev, _ = cred()
            if not token or not dev:
                self._send(200, {"ok": False, "steps": [], "err": "缺少凭证"})
                return
            steps = []
            def step(name, fn):
                t0 = time.time()
                try:
                    r = fn()
                    good = ok(r)
                    info = r.get("rspInfo", {}) or {}
                    steps.append({"step": name, "ok": good,
                                  "code": info.get("code", ""), "msg": info.get("msg", ""),
                                  "ms": int((time.time() - t0) * 1000)})
                    return r
                except Exception as e:
                    steps.append({"step": name, "ok": False, "code": "EXC",
                                  "msg": "%s: %s" % (type(e).__name__, e),
                                  "ms": int((time.time() - t0) * 1000)})
                    return {}

            step("1 网络连通 getConfig", lambda: api_post("/common/getConfig", token, dev, {}))
            u = step("2 账号信息 queryUserInfo",
                     lambda: api_post("/user/queryUserInfo", token, dev, {}))
            lst = step("3 权益列表 type=2",
                       lambda: api_post("/user/queryBenefitList", token, dev,
                                        {"type": 2, "pageNo": 1, "pageSize": 10}))
            items = (lst.get("data") or {}).get("list") or [] if isinstance(lst.get("data"), dict) else []
            if items:
                it = items[0]
                step("4 权益详情 queryBenefitDetail",
                     lambda: api_post("/user/queryBenefitDetail", token, dev,
                                      {"recordId": it.get("recordId"), "orderStatus": it.get("orderStatus", 4)}))
                step("5 券码 queryUserCouponDetail",
                     lambda: api_post("/coupon/queryUserCouponDetail", token, dev,
                                      {"couponId": it.get("couponId")}))
            self._send(200, {"ok": all(s["ok"] for s in steps), "steps": steps,
                             "count": len(items),
                             "email": (u.get("data") or {}).get("email", "")})
            return

        # ---- 分享核销会话 ----
        if path == "/api/share/create":
            token, dev, acc = cred()
            cid = b.get("couponId")
            if not token or not dev or not cid:
                self._send(200, {"ok": False, "err": "参数不全"})
                return
            # 幂等：同一张券已有活动会话就直接复用，不生成第二个链接
            # （否则刷新页面后再点「生成链接」会越积越多，旧链接还没人停）
            for old in SHARES.values():
                if (old.get("couponId") == cid and old.get("mode") == "live"
                        and not old.get("authExpired")):
                    base = share_base(self.headers.get("Host") or "")
                    self._send(200, {"ok": True, "share": share_public(old, base),
                                     "reused": True})
                    return
            sid = uuid.uuid4().hex[:12]
            s = {"id": sid, "accountId": acc["id"] if acc else None, "bornAt": time.time(),
                 "token": token, "deviceId": dev, "couponId": cid,
                 "title": b.get("title", ""), "merchant": b.get("merchant", ""),
                 "expireTime": b.get("expireTime", ""), "cardNo": b.get("cardNo", ""),
                 "imgUrl": b.get("imgUrl", ""), "orderNo": b.get("orderNo", ""),
                 "bankName": b.get("bankName", ""),
                 "activityId": b.get("activityId", ""),
                 "useDirections": b.get("useDirections", ""),
                 "profile": guess_profile(b.get("merchant", ""), b.get("title", "")),
                 "code": "", "svg": "", "refreshTime": 0, "expireAt": 0,
                 "fetchCount": 0, "lastFetch": "", "views": 0,
                 "mode": "live", "fetchedAt": "", "err": "", "lastPoll": time.time()}
            SHARES[sid] = s
            share_fill(s)
            # 配置了云端 → 把会话推到云端写 KV，成功后本地直接发 /union/ 公网链接
            cloud = (load_settings().get("cloudUrl") or "").strip().rstrip("/")
            if cloud and not CLOUD:
                # 凭证一并带过去（云端账号库可能还没有这个账号）
                acc_push = None
                if acc:
                    acc_push = {"id": acc["id"], "token": acc.get("token", ""),
                                "deviceId": acc.get("deviceId", ""), "name": acc.get("name", "")}
                if share_promote(s, cloud, load_settings().get("cloudKey", ""), acc_push):
                    s["cloudPromoted"] = True
            base = share_base(self.headers.get("Host") or "")
            self._send(200, {"ok": True, "share": share_public(s, base)})
            return

        if path == "/api/share/stop":
            sid = b.get("id")
            here = SHARES.pop(sid, None) is not None
            if kv_enabled() and sid:
                # 写 stopped 而不是删除：删了会被当成"从未存在"，
                # 停用必须是可区分的终态
                st2, val = kv_get(sid)
                if st2 == "found" and isinstance(val, dict):
                    val["status"] = "stopped"
                    val["stoppedAt"] = time.time()
                    kv_put(sid, val)
            # 在哪启用就要在哪停用；若配了云端地址，顺手把云端那份也停掉
            st = load_settings()
            cloud = (st.get("cloudUrl") or "").strip().rstrip("/")
            cloud_ok = None
            if cloud and sid:
                try:
                    req = urllib.request.Request(cloud + "/api/share/stop",
                                                 data=json.dumps({"id": sid}).encode(),
                                                 method="POST",
                                                 headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=15) as r:
                        cloud_ok = json.loads(r.read().decode()).get("ok")
                except Exception as e:
                    cloud_ok = "ERR: %s" % e
            self._send(200, {"ok": True, "stoppedHere": here, "cloudStopped": cloud_ok})
            return

        self._send(404, {"ok": False, "err": "not found"})

    def _fail(self, where, e):
        """兜底：任何未捕获异常都要回一个 JSON，否则浏览器会一直转圈"""
        try:
            self._send(500, {"ok": False, "err": "服务端异常：%s: %s" % (type(e).__name__, e),
                             "where": where, "trace": traceback.format_exc()[-1200:]})
        except Exception:
            pass

    def do_DELETE(self):
        try:
            self._do_DELETE()
        except Exception as e:
            self._fail("DELETE", e)

    def _do_DELETE(self):
        path = urlparse(self.path).path
        if path.startswith("/api/accounts/"):
            aid = path.split("/")[3]
            store = load_store()
            store["accounts"] = [a for a in store["accounts"] if a["id"] != aid]
            if store.get("activeId") == aid:
                store["activeId"] = store["accounts"][0]["id"] if store["accounts"] else ""
            save_store(store)
            self._send(200, {"ok": True,
                             "accounts": [public_account(a) for a in store["accounts"]],
                             "activeId": store.get("activeId", "")})
            return
        self._send(404, {"ok": False, "err": "not found"})


def main():
    # fail-closed：云端模式没设管理员密码就直接拒绝启动，绝不裸奔
    if CLOUD and not ADMIN_PASSWORD:
        print("=" * 58)
        print(" 拒绝启动：云端模式必须设置 UBRP_ADMIN_PASSWORD")
        print("=" * 58)
        print(" 云端部署后任何人拿到地址都能看到你的权益列表和券码，")
        print(" 所以必须先设一个管理员密码。")
        print()
        print(" Render 控制台 → Environment → 新增：")
        print("   UBRP_ADMIN_PASSWORD = 你自己起一串")
        print("=" * 58)
        sys.exit(2)
    url = "http://127.0.0.1:%d" % PORT
    print("=" * 58)
    print(" 权益U赏 · 多账号权益管理器")
    print("=" * 58)
    print(" 已启动：%s" % url)
    print(" 凭证保存位置：%s" % ACCOUNTS_FILE)
    if HOST != "127.0.0.1":
        print(" 监听地址：%s（局域网内其他设备可打开生成的二维码链接）" % HOST)
    print(" 关闭窗口或按 Ctrl+C 即可停止")
    if CLOUD:
        print(" 云端模式：管理页需要密码登录（访客链接免密）")
        print(" 凭据持久化：%s" % ("KV" if kv_enabled() else "未配置 KV，重启后链接会失效"))
    print("=" * 58)
    if not os.environ.get("UBRP_NO_BROWSER"):
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    except OSError as e:
        print("启动失败：%s（端口 %d 可能被占用，可设环境变量 UBRP_PORT 换端口）" % (e, PORT))


if __name__ == "__main__":
    main()
