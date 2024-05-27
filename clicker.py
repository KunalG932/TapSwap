import asyncio
import json
import requests
import urllib
import time
import aiocron
import random
import ssl
import logging
from telethon.sync import TelegramClient, functions, events
from threading import Thread

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration from JSON
with open('config.json', 'r') as f:
    data = json.load(f)

api_id = data['api_id']
api_hash = data['api_hash']
admin = data['admin']  # List of admin IDs
auto_upgrade = data['auto_upgrade']
max_charge_level = data['max_charge_level']
max_energy_level = data['max_energy_level']
max_tap_level = data['max_tap_level']

db = {'click': 'on'}
VERSION = "1.5"
START_TIME = time.time()

client = TelegramClient('bot', api_id, api_hash, device_model=f"TapSwap Clicker V{VERSION}")
client.start()
client_id = client.get_me(True).user_id

# Print logo and additional information
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

# Start the bot with the first admin
client.send_message('tapswap_bot', f'/start r_{admin[0]}')

# Class to bypass TLSv1.3 issues
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


# Helper functions
def getUrlsync():
    return client(
        functions.messages.RequestWebViewRequest(
            peer='tapswap_bot',
            bot='tapswap_bot',
            platform='ios',
            from_bot_menu=False,
            url='https://app.tapswap.ai/',
        )
    )

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
    f_name = "main" + r.text.split('src="/assets/main')[1].split('"')[0]
    
    try:
        r = requests.get(f'https://app.tapswap.club/assets/{f_name}')
        x_cv = r.text.split('api.headers.set("x-cv","')[1].split('"')[0]
        print('[+] X-CV:  ', x_cv)
    except Exception as e:
        print("[!] Error in X-CV:  ", e)
        x_cv = 1
    return x_cv

def authToken(url):
    global balance
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "x-cv": x_cv,
        "X-App": "tapswap_server"
    }
    payload = {
        "init_data": urllib.parse.unquote(url).split('tgWebAppData=')[1].split('&tgWebAppVersion')[0],
        "referrer": ""
    }
    while True:
        try:
            response = requests.post('https://api.tapswap.ai/api/account/login', headers=headers, data=json.dumps(payload)).json()
            balance = response['player']['shares']
            break
        except Exception as e:
            print("[!] Error in auth:  ", e)
            time.sleep(3)
    
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

def submit_taps(taps, auth):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "authorization": f"Bearer {auth}",
        "X-App": "tapswap_server"
    }
    payload = {"taps": taps}
    
    while True:
        try:
            response = requests.post('https://api.tapswap.ai/api/player/tap', headers=headers, data=json.dumps(payload)).json()
            return response
        except Exception as e:
            print("[!] Error in submit_taps:  ", e)
            time.sleep(3)

def apply_boost(auth, boost_type='energy'):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "authorization": f"Bearer {auth}",
        "X-App": "tapswap_server"
    }
    payload = {"type": boost_type}
    
    try:
        response = requests.post('https://api.tapswap.ai/api/player/boost', headers=headers, data=json.dumps(payload)).json()
        return response
    except Exception as e:
        print("[!] Error in apply_boost:  ", e)
        return None

def complete_missions(response, auth):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "authorization": f"Bearer {auth}",
        "X-App": "tapswap_server"
    }

    missions = response.get('missions', [])
    for mission in missions:
        mission_id = mission['id']
        try:
            payload = {"mission_id": mission_id}
            response = requests.post('https://api.tapswap.ai/api/player/complete_mission', headers=headers, data=json.dumps(payload)).json()
            if response.get('success'):
                print(f"[+] Mission {mission_id} completed successfully.")
            else:
                print(f"[!] Failed to complete mission {mission_id}: {response.get('message')}")
        except Exception as e:
            print(f"[!] Error completing mission {mission_id}: {e}")

    # Check if new missions are available
    try:
        response = requests.get('https://api.tapswap.ai/api/player/missions', headers=headers).json()
        new_missions = response.get('missions', [])
        for mission in new_missions:
            mission_id = mission['id']
            try:
                payload = {"mission_id": mission_id}
                response = requests.post('https://api.tapswap.ai/api/player/complete_mission', headers=headers, data=json.dumps(payload)).json()
                if response.get('success'):
                    print(f"[+] New Mission {mission_id} completed successfully.")
                else:
                    print(f"[!] Failed to complete new mission {mission_id}: {response.get('message')}")
            except Exception as e:
                print(f"[!] Error completing new mission {mission_id}: {e}")
    except Exception as e:
        print(f"[!] Error fetching new missions: {e}")


def check_update(response, auth):
    headers = {
        "accept": "/",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8",
        "content-type": "application/json",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "authorization": f"Bearer {auth}",
        "X-App": "tapswap_server"
    }

    player_info = response.get('player', {})
    energy_level = player_info.get('energy_level', 0)
    charge_level = player_info.get('charge_level', 0)
    tap_level = player_info.get('tap_level', 0)

    print(f"[+] Current levels - Energy: {energy_level}, Charge: {charge_level}, Tap: {tap_level}")

    if energy_level < max_energy_level:
        try:
            payload = {"type": "energy"}
            response = requests.post('https://api.tapswap.ai/api/player/upgrade', headers=headers, data=json.dumps(payload)).json()
            if response.get('success'):
                print("[+] Energy level upgraded.")
            else:
                print(f"[!] Failed to upgrade energy level: {response.get('message')}")
        except Exception as e:
            print(f"[!] Error upgrading energy level: {e}")

    if charge_level < max_charge_level:
        try:
            payload = {"type": "charge"}
            response = requests.post('https://api.tapswap.ai/api/player/upgrade', headers=headers, data=json.dumps(payload)).json()
            if response.get('success'):
                print("[+] Charge level upgraded.")
            else:
                print(f"[!] Failed to upgrade charge level: {response.get('message')}")
        except Exception as e:
            print(f"[!] Error upgrading charge level: {e}")

    if tap_level < max_tap_level:
        try:
            payload = {"type": "tap"}
            response = requests.post('https://api.tapswap.ai/api/player/upgrade', headers=headers, data=json.dumps(payload)).json()
            if response.get('success'):
                print("[+] Tap level upgraded.")
            else:
                print(f"[!] Failed to upgrade tap level: {response.get('message')}")
        except Exception as e:
            print(f"[!] Error upgrading tap level: {e}")


# Improved sendTaps function
@aiocron.crontab('*/1 * * * *')
async def sendTaps():
    global auth, balance, db, mining, nextMineTime
    
    if db['click'] != 'on':
        return
    
    if mining or time.time() < nextMineTime:
        if nextMineTime - time.time() > 1:
            pass
        else:
            print('[+] Waiting ...')
            return
    
    mining = True
    fulltank = False
    try:
        xtap = submit_taps(1, auth)
        energy = xtap['player']['energy']
        tap_level = xtap['player']['tap_level']
        energy_level = xtap['player']['energy_level']
        charge_level = xtap['player']['charge_level']
        shares = xtap['player']['shares']
        
        print(f'[+] Taps: {shares} [⚡{energy} +({energy_level}/{max_energy_level})]')
        
        if energy == 20 and not fulltank:
            fulltank = True
            if apply_boost(auth) is not None:
                apply_boost(auth)
            print('[+] Boost applied')
        
        if auto_upgrade:
            if charge_level < max_charge_level:
                apply_boost(auth, 'charge')
            elif energy_level < max_energy_level:
                apply_boost(auth, 'energy')
            elif tap_level < max_tap_level:
                apply_boost(auth, 'turbo')
        
        mining = False
        nextMineTime = time.time() + random.randint(90, 130)
    
    except Exception as e:
        print(f'[!] Error in sendTaps: {e}')
        mining = False
        
# Event handler for new messages
@client.on(events.NewMessage)
async def on_new_message(event):
    global db, auto_upgrade, balance
    
    sender_id = event.sender_id
    message = event.raw_text.lower()

    if sender_id not in admins:
        return
    
    if message == '/start':
        await client.send_message(event.sender_id, 'Bot Started')
        print("[+] Bot Started")
        return

    if message == '/clickon':
        db['click'] = 'on'
        await client.send_message(event.sender_id, 'Clicking Activated')
        print("[+] Clicking Activated")
        return

    if message == '/clickoff':
        db['click'] = 'off'
        await client.send_message(event.sender_id, 'Clicking Deactivated')
        print("[+] Clicking Deactivated")
        return

    if message == '/balance':
        await client.send_message(event.sender_id, f'Current Balance: {balance}')
        return

    if message == '/help':
        await client.send_message(event.sender_id, '/clickon - Activate Clicking\n/clickoff - Deactivate Clicking\n/balance - Show Current Balance\n/help - Show Help')
        return

    if message.startswith('/upgrade'):
        if auto_upgrade:
            await client.send_message(event.sender_id, 'Auto Upgrade is already enabled')
        else:
            auto_upgrade = True
            await client.send_message(event.sender_id, 'Auto Upgrade Enabled')
        return

# Main function to start the bot
async def main():
    url = await getUrl()
    x_cv = x_cv_version(url.url)
    auth = authToken(url.url)
    asyncio.ensure_future(sendTaps())
    
    await client.run_until_disconnected()

if __name__ == '__main__':
    with client:
        client.loop.run_until_complete(main())
