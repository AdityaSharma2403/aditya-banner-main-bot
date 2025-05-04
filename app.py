import logging
import os
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
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB48"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === GitHub Repo Paths ===
GITHUB_API_BASE = "https://api.github.com/repos/AdityaSharma2403/OUTFIT-S/contents"
FOLDERS = {"BANNERS": "BANNERS", "AVATARS": "AVATARS", "PINS": "PINS"}

# === Pre-loaded assets caches ===
ASSET_CACHE = {"BANNERS": {}, "AVATARS": {}, "PINS": {}}
BADGE_DATA = None
FONT_DATA = None

# === Image Layout Constants ===
SCALE = 4
ACCOUNT_NAME_POSITION = {"x": 62,  "y": 0,  "font_size": 12.5}
ACCOUNT_LEVEL_POSITION= {"x":180, "y":45, "font_size":12.5}
GUILD_NAME_POSITION  = {"x": 62,  "y":40, "font_size":12.5}
AVATAR_POSITION      = {"x": 0,   "y": 0,  "width":60, "height":60}
PIN_POSITION         = {"x": 0,   "y":40, "width":20, "height":20}
BADGE_POSITION       = {"x":40,  "y": 0,  "width":20, "height":20}
FALLBACK_BANNER_ID   = "900000014"
FALLBACK_AVATAR_ID   = "900000013"

# Configure logging
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Asset Preloading ===
def load_font():
    global FONT_DATA
    FONT_URL = "https://raw.githubusercontent.com/Thong-ihealth/arial-unicode/main/Arial-Unicode-Bold.ttf"
    try:
        resp = requests.get(FONT_URL);
        resp.raise_for_status()
        FONT_DATA = resp.content
        logging.info("Custom font downloaded successfully")
    except Exception as e:
        logging.error("Could not download custom font, will use default: %s", e)


def load_badge():
    global BADGE_DATA
    CELEB_URL = "https://i.ibb.co/YBrt0j0m/icon.png"
    try:
        resp = requests.get(CELEB_URL);
        resp.raise_for_status()
        BADGE_DATA = resp.content
        logging.info("Celebrity badge downloaded successfully")
    except Exception as e:
        logging.error("Could not download celebrity badge: %s", e)


def fetch_folder(folder_name):
    api_url = f"{GITHUB_API_BASE}/{folder_name}"
    token = "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"  # Replace with your actual token

    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'token {token}'
    }

    try:
        resp = requests.get(api_url, headers=headers, timeout=10)
        resp.raise_for_status()
        items = resp.json()
        logging.info("Downloading %d assets from %s...", len(items), folder_name)

        def download(item):
            name = item.get('name', '')
            if not name.lower().endswith(('.png', '.jpg')):
                return None, None
            key = name.rsplit('.', 1)[0]
            raw = item.get('download_url')
            try:
                r = requests.get(raw, timeout=10)
                r.raise_for_status()
                img = Image.open(BytesIO(r.content)).convert('RGBA')
                return key, img
            except Exception as e:
                logging.error("Error downloading %s: %s", raw, e)
                return None, None

        with ThreadPoolExecutor(max_workers=500) as executor:  # 500 is too high, use ~50
            futures = [executor.submit(download, it) for it in items]
            for fut in tqdm(as_completed(futures), total=len(futures), desc=folder_name):
                k, img = fut.result()
                if k and img:
                    ASSET_CACHE[folder_name][k] = img

        logging.info("Loaded %d assets for %s", len(ASSET_CACHE[folder_name]), folder_name)

    except Exception as e:
        logging.error("Error loading folder %s: %s", folder_name, e)


def preload_assets():
    load_font()
    load_badge()
    for folder in FOLDERS.values():
        fetch_folder(folder)

# Ensure preload runs only once (avoid Flask reloader)
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not os.environ.get('WERKZEUG_RUN_MAIN'):
    preload_assets()

# === Utility for fonts & assets ===
def get_custom_font(size):
    if FONT_DATA:
        try:
            return ImageFont.truetype(BytesIO(FONT_DATA), int(size))
        except Exception as e:
            logging.error("Error loading truetype from FONT_DATA: %s", e)
    return ImageFont.load_default()


def get_asset_image(folder, asset_id, fallback_id):
    cache_map = ASSET_CACHE.get(folder, {})
    img = cache_map.get(asset_id)
    if img is None:
        img = cache_map.get(fallback_id)
    return img.copy() if img else None

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

def cached_endpoint(ttl=300):  
    def decorator(fn):  
        @wraps(fn)  
        def wrapper(*a, **k):  
            key = (request.path, tuple(request.args.items()))  
            if key in cache:  
                data = cache[key]  
                return send_file(BytesIO(data), mimetype='image/png')  
            result = fn(*a, **k)  
            # fn returns Response or tuple(bytes, status)  
            if isinstance(result, tuple) and isinstance(result[0], bytes):  
                data, status = result  
            elif isinstance(result, bytes):  
                data, status = result, 200  
            else:  
                return result  
            cache[key] = data  
            return send_file(BytesIO(data), mimetype='image/png'), status  
        return wrapper  
    return decorator  

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for all regions.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

# === Flask Route ===
@app.route('/banner-image', methods=['GET'])
@cached_endpoint(ttl=300)
def generate_image():
    uid    = request.args.get('uid')
    region = request.args.get('region')
    if not uid or not region:
        return jsonify({"error":"Missing uid or region"}), 400
    try:
        data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
    except Exception as e:
        logging.error("Player info fetch error: %s", e)
        return jsonify({"error":str(e)}), 500
    basic_info = data.get('basicInfo', {})
    guild_info = data.get('clanBasicInfo', {})
    if not basic_info:
        return jsonify({"error":"No valid API response received"}), 500
    banner_id = str(basic_info.get('bannerId') or FALLBACK_BANNER_ID)
    avatar_id = str(basic_info.get('headPic') or FALLBACK_AVATAR_ID)
    account_name  = basic_info.get('nickname','')
    account_level = basic_info.get('level','')
    guild_name    = guild_info.get('clanName','')
    try:
        role_value = int(basic_info.get('role', 0))
    except:
        role_value = 0
    is_celebrity = role_value in (64, 68)
    bg = get_asset_image('BANNERS', banner_id, FALLBACK_BANNER_ID)
    av = get_asset_image('AVATARS', avatar_id, FALLBACK_AVATAR_ID)
    if not bg or not av:
        return jsonify({"error":"Asset not found"}), 500
    bw, bh = bg.size
    hr_bg = bg.resize((bw*SCALE, bh*SCALE), Image.LANCZOS)
    aw, ah = av.size
    new_h = bh*SCALE
    new_w = int((aw/ah)*new_h)
    hr_av = av.resize((new_w, new_h), Image.LANCZOS)
    hr_bg.paste(hr_av, (AVATAR_POSITION['x']*SCALE, AVATAR_POSITION['y']*SCALE), hr_av)
    draw = ImageDraw.Draw(hr_bg)
    fn = get_custom_font(ACCOUNT_NAME_POSITION['font_size']*SCALE)
    draw.text((ACCOUNT_NAME_POSITION['x']*SCALE, ACCOUNT_NAME_POSITION['y']*SCALE), account_name, font=fn, fill='white')
    fl = get_custom_font(ACCOUNT_LEVEL_POSITION['font_size']*SCALE)
    draw.text((ACCOUNT_LEVEL_POSITION['x']*SCALE, ACCOUNT_LEVEL_POSITION['y']*SCALE), f"Lvl. {account_level}", font=fl, fill='white')
    fg = get_custom_font(GUILD_NAME_POSITION['font_size']*SCALE)
    draw.text((GUILD_NAME_POSITION['x']*SCALE, GUILD_NAME_POSITION['y']*SCALE), guild_name, font=fg, fill='white')

    pin_id = str(basic_info.get('pinId',''))
    if pin_id:
        pin_img = get_asset_image('PINS', pin_id, None)
        if pin_img:
            hr_pin = pin_img.resize((PIN_POSITION['width']*SCALE, PIN_POSITION['height']*SCALE), Image.LANCZOS)
            hr_bg.paste(hr_pin, (PIN_POSITION['x']*SCALE, PIN_POSITION['y']*SCALE), hr_pin)

    if is_celebrity and BADGE_DATA:
        badge = Image.open(BytesIO(BADGE_DATA)).convert('RGBA')
        hr_badge = badge.resize((BADGE_POSITION['width']*SCALE, BADGE_POSITION['height']*SCALE), Image.LANCZOS)
        hr_bg.paste(hr_badge, (BADGE_POSITION['x']*SCALE, BADGE_POSITION['y']*SCALE), hr_badge)

    final = hr_bg.resize((bw, bh), Image.LANCZOS)
    buf = BytesIO()
    final.save(buf,'PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

# === Main ===
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
