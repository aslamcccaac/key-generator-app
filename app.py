import os
import json
from flask import Flask, jsonify, render_template, request
from datetime import date, timedelta

app = Flask(__name__)

# --- Configuration ---
KEYS_FILE = "generated_keys.json"
BANNED_IPS_FILE = "banned_ips.json"
BAN_THRESHOLD = 10 

# --- Your Developer IP Allowlist ---
IP_ALLOWLIST = [
    "127.0.0.1",
    "45.37.169.105"  # Your IP address
]

# --- NEW: Robust IP Detection Function ---
def get_user_ip():
    """
    Gets the real user IP address by correctly parsing proxy headers.
    """
    # The 'X-Forwarded-For' header can be a comma-separated list of IPs.
    # The client's IP is the first one in the list.
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Get the first IP in the list and remove any whitespace
        return forwarded_for.split(',')[0].strip()
    
    # If the header is not present, fall back to the direct address
    # (this is mainly for local testing)
    return request.remote_addr

# --- Helper Functions (Unchanged) ---
def load_json(filename):
    if not os.path.exists(filename) or os.path.getsize(filename) == 0:
        return []
    with open(filename, 'r') as f:
        return json.load(f)

def save_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

# --- NEW: Secret Debug Route ---
@app.route("/debug-info")
def debug_info():
    """A secret page to show us exactly what the server is seeing."""
    headers = dict(request.headers)
    ip_info = {
        "calcuated_user_ip": get_user_ip(),
        "remote_addr": request.remote_addr,
        "all_headers": headers
    }
    return jsonify(ip_info)


# --- Main Route ---
@app.route("/")
def index():
    user_ip = get_user_ip() # Use our new robust function
    is_developer = user_ip in IP_ALLOWLIST
    return render_template("index.html", is_developer=is_developer)

# --- API Endpoints ---
@app.route("/api/get-client-key")
def get_client_key():
    user_ip = get_user_ip() # Use our new robust function
    today = str(date.today())
    
    banned_ips = load_json(BANNED_IPS_FILE)
    if user_ip in banned_ips:
        return jsonify(error=True, message="Your IP is banned."), 403

    all_keys = load_json(KEYS_FILE)
    requests_today = 0
    for key_info in all_keys:
        if key_info.get("generated_by_ip") == user_ip and key_info.get("generated_on") == today:
            requests_today += 1
            if "key" in key_info:
                if requests_today >= BAN_THRESHOLD:
                    if user_ip not in banned_ips:
                        banned_ips.append(user_ip)
                        save_json(banned_ips, BANNED_IPS_FILE)
                    return jsonify(error=True, message="Your IP is now banned for excessive requests."), 403
                return jsonify(daily_key=key_info["key"], message="You already have a key for today. Come back tomorrow.")
    
    new_key = os.urandom(16).hex()
    key_data = { "key": new_key, "generated_by_ip": user_ip, "generated_on": today, "valid_for_days": 1, "expires_on": str(date.today() + timedelta(days=1)) }
    all_keys.append(key_data)
    save_json(all_keys, KEYS_FILE)
    
    return jsonify(daily_key=new_key, message="Here is your new key for today.")

@app.route("/api/generate-developer-key")
def generate_developer_key():
    user_ip = get_user_ip() # Use our new robust function
    
    if user_ip not in IP_ALLOWLIST:
        return jsonify(error=True, message="Unauthorized access."), 403

    try:
        days = int(request.args.get('days'))
        if days not in [3, 7, 14, 30, 60, 90]: raise ValueError("Invalid number of days.")
    except (TypeError, ValueError):
        return jsonify(error=True, message="Invalid 'days' parameter. Use 3, 7, 14, 30, 60, or 90."), 400

    new_key = f"dev_{os.urandom(24).hex()}"
    today = date.today()
    expires = today + timedelta(days=days)
    key_info = { "key": new_key, "generated_by_ip": user_ip, "generated_on": str(today), "valid_for_days": days, "expires_on": str(expires) }
    all_keys = load_json(KEYS_FILE)
    all_keys.append(key_info)
    save_json(all_keys, KEYS_FILE)
    return jsonify(key_info=key_info)

if __name__ == "__main__":
    app.run(debug=True)