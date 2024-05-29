import asyncio
import json
import requests
import urllib
import time
import aiocron
import random
import ssl
import psutil
from telethon.sync import TelegramClient, functions, types, events
from threading import Thread

# Load configuration from config.json
with open('config.json') as f:
    data = json.load(f)
    api_id = data['api_id']
    api_hash = data['api_hash']
    admin = data['admin']
    auto_upgrade = data['auto_upgrade']
    max_charge_level = data['max_charge_level']
    max_energy_level = data['max_energy_level']
    max_tap_level = data['max_tap_level']

# Initialize the bot database and version
db = {'click': 'on'}
VERSION = "1.5"
START_TIME = time.time()

# Setup the Telegram client
client = TelegramClient('bot', api_id, api_hash, device_model=f"TapSwap Clicker V{VERSION}")
client.start()
client_id = client.get_me(True).user_id

# Print startup information
print(r'''
  _____           _______          _
 / ____|         |__   __|        | |
| |     ___  _ __  _| | ___ _ __ | |_
| |    / _ \| '_ \| | |/ _ \ '_ \| __|
| |___| (_) | | | | | |  __/ | | | |_
 \_____\___/|_| |_| |_|\___|_| |_|\__|

''')
print("Client is Ready - Enjoy")
print("➤VorTex Network™")
print("----------------------------------------")
print("Join Telegram for more: t.me/RexxCheat")

client.send_message('tapswap_bot', f'/start r_{admin}')

class BypassTLSv1_3(requests.adapters.HTTPAdapter):
    SUPPORTED_CIPHERS = [
        "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256", "AES256-GCM-SHA384", "AES128-SHA", "AES256-SHA", "DES-CBC3-SHA",
        "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256", "TLS_AES_256_CCM_8_SHA256"
    ]

    def __init__(self, *args, **kwargs):
        self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.ssl_context.set_ciphers(':'.join(BypassTLSv1_3.SUPPORTED_CIPHERS))
        self.ssl_context.set_ecdh_curve("prime256v1")
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        kwargs["source_address"] = None
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        kwargs["source_address"] = None
        return super().proxy_manager_for(*args, **kwargs)

async def getUrl():
    return await client(
        functions.messages.RequestWebViewRequest(
            peer='tapswap_bot',
            bot='tapswap_bot',
            platform='ios',
            from_bot_menu=False,
            url='https://app.tapswap.ai/',
        )
    )

def x_cv_version(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    }

    s = requests.Session()
    s.headers = headers

    r = requests.get(url, headers=headers)

    f_name = "main"+r.text.split('src="/assets/main')[1].split('"')[0]
    
    try:
        r = requests.get(f'https://app.tapswap.club/assets/{f_name}')
        x_cv = r.text.split('api.headers.set("x-cv","')[1].split('"')[0]
        print('[+] X-CV:  ', x_cv)
    except Exception as e:
        print("[!] Error in X-CV:  ", e)
        x_cv = 1
    return x_cv

async def authToken(url):
    global balance, x_cv  # Define x_cv as a global variable
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "x-cv": x_cv,  # Use x_cv here
        "X-App": "tapswap_server"
    }
    payload = {
        "init_data": urllib.parse.unquote(url).split('tgWebAppData=')[1].split('&tgWebAppVersion')[0],
        "referrer":""
    }
    while True:
        try:
            response = requests.post('https://api.tapswap.ai/api/account/login', headers=headers, data=json.dumps(payload)).json()
            balance = response['player']['shares']
            break
        except Exception as e:
            print("[!] Error in auth:  ", e)
            # time.sleep(3)
    
    if auto_upgrade:
        try:
            Thread(target=complete_missions, args=(response, response['access_token'],)).start()
        except:
            pass
        try:
            check_update(response, response['access_token'])
        except Exception as e:
            print(e)
    
    return response['access_token']

def complete_missions(response, auth: str):
    missions = response['conf']['missions']
    try:
        completed_missions = response['account']['missions']['completed']
    except:
        completed_missions = []
    xmissions = []
    mission_items = []

    for i, mission in enumerate(missions):
        if f"M{i}" in completed_missions:
            continue
        xmissions.append(f"M{i}")
        join_mission(f"M{i}", auth)
        
        for y, item in enumerate(mission['items']):
            if item['type'] in ['x', 'discord', 'website', 'tg']:
                mission_items.append([f"M{i}", y])
                finish_mission_item(f"M{i}", y, auth)
        
    time.sleep(random.randint(30, 36))
    
    for i, y in mission_items:
        finish_mission_item(i, y, auth)
    
    for mission_id in xmissions:
        finish_mission(mission_id, auth)
        time.sleep(2)
        claim_reward(auth, mission_id)
            
def join_mission(mission:str, auth:str):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "Authorization": f"Bearer {auth}",
        "x-cv": x_cv,
        "X-App": "tapswap_server"
    }
    
    payload = {"id":mission}
    response = requests.post('https://api.tapswap.ai/api/missions/join_mission', headers=headers, json=payload).json()
    return response

def finish_mission(mission:str, auth:str):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "Authorization": f"Bearer {auth}",
        "x-cv": x_cv,
        "X-App": "tapswap_server"
    }
    
    payload = {"id":mission}
    response = requests.post('https://api.tapswap.ai/api/missions/finish_mission', headers=headers, json=payload).json()
    return response

def finish_mission_item(mission:str, item:int, auth:str):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "Authorization": f"Bearer {auth}",
        "x-cv": x_cv,
        "X-App": "tapswap_server"
    }
    
    payload = {"id":mission,"item":item}
    response = requests.post('https://api.tapswap.ai/api/missions/finish_mission_item', headers=headers, json=payload).json()
    return response

def claim_reward(auth:str, mission_id:str):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "Authorization": f"Bearer {auth}",
        "x-cv": x_cv,
        "X-App": "tapswap_server"
    }
    
    payload = {"id":mission_id}
    response = requests.post('https://api.tapswap.ai/api/missions/claim_mission_reward', headers=headers, json=payload).json()
    return response

def check_update(response, auth: str):
    acc_data = response['player']
    if acc_data['energy_level'] < max_energy_level:
        for i in range(acc_data['energy_level'], max_energy_level):
            upgrade(auth, 'energy')

    if acc_data['tap_level'] < max_tap_level:
        for i in range(acc_data['tap_level'], max_tap_level):
            upgrade(auth, 'tap')

    if acc_data['charge_level'] < max_charge_level:
        for i in range(acc_data['charge_level'], max_charge_level):
            upgrade(auth, 'charge')

def upgrade(auth:str, type_:str):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "Authorization": f"Bearer {auth}",
        "x-cv": x_cv,
        "X-App": "tapswap_server"
    }
    
    payload = {"type":type_}
    response = requests.post('https://api.tapswap.ai/api/player/upgrade', headers=headers, json=payload).json()
    return response

def submitTaps(auth:str, url:str):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "Authorization": f"Bearer {auth}",
        "x-cv": x_cv,
        "X-App": "tapswap_server"
    }
    
    while db['click'] == 'on':
        try:
            payload = {
                "taps": [{"i": 0, "t": int(time.time() * 1000)} for _ in range(random.randint(85, 93))]
            }
            response = requests.post('https://api.tapswap.ai/api/player/send_taps', headers=headers, data=json.dumps(payload))
            response = response.json()
            balance = response['shares']
            sys.stdout.write(f'\r [>] Tap Sent | Earned: {balance}')
            sys.stdout.flush()
        except Exception as e:
            print("[!] Error in Submit Taps:  ", e)
        time.sleep(30)

@client.on(events.NewMessage(from_users=admin))
async def admin_handler(event):
    text = event.raw_text
    if text == "/start":
        await event.reply("Client is Up and Running.\nUse /stop to halt.")
    elif text == "/stop":
        db['click'] = 'off'
        await event.reply("Client is stopped.")
    elif text == "/run":
        db['click'] = 'on'
        await event.reply("Client is running.")
    elif text == "/main":
        url = await getUrl()
        await event.reply(url.url)
    elif text == "/auth":
        url = await getUrl()
        await event.reply("Auth token is: " + authToken(url.url))
    elif text == "/status":
        elapsed_time = time.time() - START_TIME
        uptime = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
        memory = psutil.virtual_memory().percent
        cpu = psutil.cpu_percent()
        await event.reply(f"Status Report:\nUptime: {uptime}\nMemory Usage: {memory}%\nCPU Usage: {cpu}%")
    elif text == "/upgrade":
        url = await getUrl()
        response = json.loads(authToken(url.url))
        check_update(response, authToken(url.url))
        await event.reply("Upgraded as per configuration.")
    elif text.startswith("/"):
        await event.reply("Unknown command.")

# Cron job to submit taps every 15 minutes
@aiocron.crontab('*/15 * * * *')
async def cron_taps():
    url = await getUrl()
    auth = authToken(url.url)
    submitTaps(auth, url.url)

# Start the client and keep it running
print("Bot is now running...")
client.run_until_disconnected()
