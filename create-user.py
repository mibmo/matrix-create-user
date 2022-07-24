#!/bin/env python3

import argparse, hmac, hashlib, requests, json, sys

def generate_mac(nonce, shared_secret, user, password, admin=False, user_type=None):
    mac = hmac.new(
      key=str.encode(shared_secret),
      digestmod=hashlib.sha1,
    )

    mac.update(nonce.encode('utf8'))
    mac.update(b"\x00")
    mac.update(user.encode('utf8'))
    mac.update(b"\x00")
    mac.update(password.encode('utf8'))
    mac.update(b"\x00")
    mac.update(b"admin" if admin else b"notadmin")
    if user_type:
        mac.update(b"\x00")
        mac.update(user_type.encode('utf8'))

    return mac.hexdigest()

def get_url(homeserver, insecure):
    scheme = "http" if insecure else "https"
    return f"{scheme}://{homeserver}/_synapse/admin/v1/register"

def get_nonce(url):
    res = requests.get(url)
    if res.status_code == 200:
        nonce = json.loads(res.content)["nonce"]
        return nonce
    else:
        print(f"failed to get nonce. status_code={res.status_code} url={url}")
        sys.exit(1)

def create_user(url,  secret, username, password=None, admin=False):
    nonce = get_nonce(url)
    mac = generate_mac(nonce, secret, username, password, admin)
    payload = {
        "nonce": nonce,
        "mac": mac,
        "admin": admin,
        "username": username,
    }
    if password != None:
        payload["password"] = password
    res = requests.post(url, json = payload)
    return res.status_code == 200

def cli():
    parser = argparse.ArgumentParser(description = "Dendrite user creator")

    parser.add_argument("homeserver", type = str, help = "Homeserver address")
    parser.add_argument("username", type = str, help = "Username of the user")
    parser.add_argument("secret", type = str, help = "Registration secret")
    parser.add_argument("-a", "--admin", help = "Is the user an administrator?", action="store_true")
    parser.add_argument("-p", "--password", help = "Password of the user")
    parser.add_argument("--insecure", help = "Use HTTP for requests (use only if hosted locally!)")

    return parser.parse_args()

if __name__ == "__main__":
    args = cli()
    url = get_url("localhost:3030", True)
    ok = create_user(url, args.secret, args.username, password=args.password, admin=args.admin)
    print("Create user: " + "success" if ok else "error")
