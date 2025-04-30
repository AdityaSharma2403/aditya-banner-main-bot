import logging
import requests
import asyncio
import time
import httpx
import json
from io import BytesIO
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from cachetools import TTLCache
from PIL import Image, ImageDraw, ImageFont
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB48"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Pre-downloaded assets ===
FONT_URL             = "https://raw.githubusercontent.com/Thong-ihealth/arial-unicode/main/Arial-Unicode-Bold.ttf"
CELEBRITY_ICON_URL   = "https://i.ibb.co/YBrt0j0m/icon.png"
try:
    # Download font
    resp = requests.get(FONT_URL); resp.raise_for_status()
    FONT_DATA = resp.content
    logging.info("Custom font downloaded successfully")
except Exception as e:
    logging.error("Could not download custom font, will use default: %s", e)
    FONT_DATA = None

try:
    # Download celebrity badge once
    resp = requests.get(CELEBRITY_ICON_URL); resp.raise_for_status()
    BADGE_DATA = resp.content
    logging.info("Celebrity badge downloaded successfully")
except Exception as e:
    logging.error("Could not download celebrity badge: %s", e)
    BADGE_DATA = None

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.DEBUG)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

def get_custom_font(size):
    if FONT_DATA:
        try:
            return ImageFont.truetype(BytesIO(FONT_DATA), int(size))
        except Exception as e:
            logging.error("Error loading truetype from FONT_DATA: %s", e)
    return ImageFont.load_default()

def fetch_image(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return Image.open(BytesIO(resp.content)).convert("RGBA")
    except Exception as e:
        logging.error("Image fetch error from %s: %s", url, e)
        return None

def get_banner_url(banner_id):
    return f"https://raw.githubusercontent.com/AdityaSharma2403/OUTFIT-S/main/BANNERS/{banner_id}.png"

def get_avatar_url(avatar_id):
    return f"https://raw.githubusercontent.com/AdityaSharma2403/OUTFIT-S/main/AVATARS/{avatar_id}.png"

# Text positions & sizes
ACCOUNT_NAME_POSITION   = {"x": 62,  "y": 0,  "font_size": 12.5}
ACCOUNT_LEVEL_POSITION  = {"x": 180, "y": 45, "font_size": 12.5}
GUILD_NAME_POSITION     = {"x": 62,  "y": 40, "font_size": 12.5}
AVATAR_POSITION         = {"x": 0,   "y": 0,  "width": 60, "height": 60}
PIN_POSITION            = {"x": 0,   "y": 40, "width": 20, "height": 20}
BADGE_POSITION          = {"x": 40,  "y": 0,  "width": 20, "height": 20}

SCALE = 4
FALLBACK_BANNER_ID = "900000014"
FALLBACK_AVATAR_ID = "900000013"

# === Crypto & Protobuf Helpers ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# === Account Credentials & Token Management ===
def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3128851125&password=A2E0175866917124D431D93C8F0179502108F92B9E22B84F855730F2E70ABEA4"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3301387397&password=BAC03CCF677F8772473A09870B6228ADFBC1F503BF59C8D05746DE451AD67128"
    else:
        return "uid=3301239795&password=DD40EE772FCBD61409BB15033E3DE1B1C54EDA83B75DF0CDD24C34C7C8798475"

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(
            decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
        ))
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def get_token_info(region: str):
    info = cached_tokens.get(region.upper())
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(server+endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(
            decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        ))

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for all regions.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

@app.route('/banner-image', methods=['GET'])
def generate_image():
    uid    = request.args.get('uid')
    region = request.args.get('region')
    if not uid or not region:
        return jsonify({"error": "Missing uid or region"}), 400

    try:
        data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
    except Exception as e:
        logging.error("Player info fetch error: %s", e)
        return jsonify({"error": str(e)}), 500

    basic_info = data.get('basicInfo', {})
    guild_info = data.get('clanBasicInfo', {})
    if not basic_info:
        return jsonify({"error": "No valid API response received"}), 500

    banner_id = basic_info.get('bannerId') or FALLBACK_BANNER_ID
    if banner_id == 'Default':
        banner_id = FALLBACK_BANNER_ID
    avatar_id = basic_info.get('headPic') or FALLBACK_AVATAR_ID
    if avatar_id == 'Default':
        avatar_id = FALLBACK_AVATAR_ID

    account_name  = basic_info.get('nickname', '')
    account_level = basic_info.get('level', '')
    guild_name    = guild_info.get('clanName', '')

    try:
        role_value = int(basic_info.get('role', 0))
    except (ValueError, TypeError):
        role_value = 0
    is_celebrity = role_value in (64, 68)

    # Fetch and compose images
    bg = fetch_image(get_banner_url(banner_id)) or fetch_image(get_banner_url(FALLBACK_BANNER_ID))
    av = fetch_image(get_avatar_url(avatar_id)) or fetch_image(get_avatar_url(FALLBACK_AVATAR_ID))
    bw, bh = bg.size
    hr_bg = bg.resize((bw * SCALE, bh * SCALE), Image.LANCZOS)
    aw, ah = av.size
    new_h = bh * SCALE
    new_w = int((aw / ah) * new_h)
    hr_av = av.resize((new_w, new_h), Image.LANCZOS)
    hr_bg.paste(hr_av, (AVATAR_POSITION['x']*SCALE, AVATAR_POSITION['y']*SCALE), hr_av)

    draw = ImageDraw.Draw(hr_bg)
    fn = get_custom_font(ACCOUNT_NAME_POSITION['font_size'] * SCALE)
    draw.text((ACCOUNT_NAME_POSITION['x']*SCALE, ACCOUNT_NAME_POSITION['y']*SCALE),
              account_name, font=fn, fill='white')
    fl = get_custom_font(ACCOUNT_LEVEL_POSITION['font_size'] * SCALE)
    draw.text((ACCOUNT_LEVEL_POSITION['x']*SCALE, ACCOUNT_LEVEL_POSITION['y']*SCALE),
              f"Lvl. {account_level}", font=fl, fill='white')
    fg = get_custom_font(GUILD_NAME_POSITION['font_size'] * SCALE)
    draw.text((GUILD_NAME_POSITION['x']*SCALE, GUILD_NAME_POSITION['y']*SCALE),
              guild_name, font=fg, fill='white')

    pin_id = basic_info.get('pinId')
    if pin_id:
        pin_img = fetch_image(f"https://freefireinfo.vercel.app/icon?id={pin_id}")
        if pin_img:
            pr = PIN_POSITION
            hr_pin = pin_img.resize((pr['width']*SCALE, pr['height']*SCALE), Image.LANCZOS)
            hr_bg.paste(hr_pin, (pr['x']*SCALE, pr['y']*SCALE), hr_pin)

    # Paste celebrity badge from pre-downloaded data
    if is_celebrity and BADGE_DATA:
        badge_img = Image.open(BytesIO(BADGE_DATA)).convert("RGBA")
        bp = BADGE_POSITION
        hr_badge = badge_img.resize((bp['width']*SCALE, bp['height']*SCALE), Image.LANCZOS)
        hr_bg.paste(hr_badge, (bp['x']*SCALE, bp['y']*SCALE), hr_badge)

    final = hr_bg.resize((bw, bh), Image.LANCZOS)
    buf = BytesIO()
    final.save(buf, 'PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
