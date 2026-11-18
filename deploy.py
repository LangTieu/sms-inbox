#!/usr/bin/env python3
"""Deploy telnyx-sms-relay to Cloudflare Workers via the API (no wrangler).

Credential reaches api.cloudflare.com only through the registered
connection's surrogate exchange (see cf_api.py). Never print secret values:
the `secret` subcommand reads the value from stdin and only reports ok/fail.
"""
import json
import sys
import urllib.request
import uuid

sys.path.insert(0, "/opt/muse/skills/custom-connector-setup/bin")
from dynamic_credentials import add_surrogate_to_request, read_json_response

BASE = "https://api.cloudflare.com/client/v4"
CONNECTION = "custom.cloudflare-vnstockai"
ALLOWED_HOSTS = ["api.cloudflare.com"]
ACCOUNT_ID = "e6e3dca05591f48f9bc8a58767c3ee01"
SCRIPT_NAME = "telnyx-sms-relay"
WORKER_FILE = "/home/hatch/workspace/sms-inbox/worker.js"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError("redirect refused, verify the endpoint")


def opener():
    return urllib.request.build_opener(NoRedirect())


def call_json(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    add_surrogate_to_request(req, CONNECTION, allowed_hosts=ALLOWED_HOSTS)
    with opener().open(req, timeout=60) as resp:
        return read_json_response(resp)


def deploy():
    with open(WORKER_FILE, "rb") as f:
        script = f.read()
    metadata = json.dumps({
        "main_module": "worker.js",
        "compatibility_date": "2026-11-09",
        "bindings": [{"type": "d1", "name": "DB", "database_id": "a0af3f0e-bcf5-4098-9905-e86efc3a0ba1"}],
    }).encode()
    boundary = "----telnyxrelay" + uuid.uuid4().hex
    body = b""
    body += ("--" + boundary + "\r\n").encode()
    body += b'Content-Disposition: form-data; name="metadata"\r\n'
    body += b"Content-Type: application/json\r\n\r\n" + metadata + b"\r\n"
    body += ("--" + boundary + "\r\n").encode()
    body += b'Content-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
    body += b"Content-Type: application/javascript+module\r\n\r\n" + script + b"\r\n"
    body += ("--" + boundary + "--\r\n").encode()
    req = urllib.request.Request(
        f"{BASE}/accounts/{ACCOUNT_ID}/workers/scripts/{SCRIPT_NAME}",
        data=body, method="PUT")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    add_surrogate_to_request(req, CONNECTION, allowed_hosts=ALLOWED_HOSTS)
    with opener().open(req, timeout=60) as resp:
        result = read_json_response(resp)
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1


def subdomain_enable():
    result = call_json("POST",
        f"/accounts/{ACCOUNT_ID}/workers/scripts/{SCRIPT_NAME}/subdomain",
        {"enabled": True})
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1


def subdomain():
    result = call_json("GET", f"/accounts/{ACCOUNT_ID}/workers/subdomain")
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1


def set_secret(name):
    value = sys.stdin.read()
    if not value:
        print("secret: empty value on stdin", file=sys.stderr)
        return 2
    result = call_json("PUT",
        f"/accounts/{ACCOUNT_ID}/workers/scripts/{SCRIPT_NAME}/secrets",
        {"name": name, "text": value, "type": "secret_text"})
    ok = bool(result.get("success"))
    print(f"secret {name}: {'OK' if ok else 'FAILED'}")
    if not ok:
        print(json.dumps(result, indent=2))
    return 0 if ok else 1


def main():
    if len(sys.argv) < 2:
        print("usage: deploy.py {deploy|subdomain|secret <NAME>}", file=sys.stderr)
        return 2
    cmd = sys.argv[1]
    if cmd == "deploy":
        return deploy()
    if cmd == "subdomain":
        return subdomain()
    if cmd == "subdomain-enable":
        return subdomain_enable()
    if cmd == "secret" and len(sys.argv) == 3:
        return set_secret(sys.argv[2])
    print("usage: deploy.py {deploy|subdomain|secret <NAME>}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
