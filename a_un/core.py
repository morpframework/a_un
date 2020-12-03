import base64
import hashlib
import json
import os
import textwrap
import time
import typing

from Crypto.PublicKey import RSA

__all__ = [
    "encode",
    "decode",
    "gen_license",
    "gen_keypair",
    "validate_license",
    "load_license",
]

sep = "|||"


def encode(d: dict) -> str:
    s = json.dumps(d)
    txt = base64.b64encode(s.encode("utf8")).decode("utf8")
    return "\n".join(textwrap.wrap(txt, width=60)) + "\n"


def decode(s: str) -> dict:
    ns = ""
    for l in s.split("\n"):
        ll = l.strip()
        if not ll:
            continue
        if not ll.startswith("#"):
            ns += ll

    j = base64.b64decode(ns.encode("utf8")).decode("utf8")
    return json.loads(j)


def hash(message: str):
    message = message.encode("utf8")
    return int.from_bytes(hashlib.sha512(message).digest(), byteorder="big")


def encrypt(message, d, n):
    return hex(pow(message, d, n))


def decrypt(message, e, n):
    message = int(message, 16)
    return pow(message, e, n)


def gen_license(key: str, start: int, end: int, **extra_opts):
    privkey = decode(key)
    privkey["d"] = int(privkey["d"], 16)
    privkey["n"] = int(privkey["n"], 16)

    data = {"start": start, "end": end}

    data.update(extra_opts)
    message = json.dumps(data)
    messagehash = hash(message)
    signature = encrypt(messagehash, privkey["d"], privkey["n"])
    payload = "%s%s%s" % (message, sep, signature)
    return encode(payload)


def gen_keypair(size=4096):
    keypair = RSA.generate(size)
    key = {"d": hex(keypair.d), "n": hex(keypair.n)}
    crt = {"e": hex(keypair.e), "n": hex(keypair.n)}
    return {"key": encode(key), "crt": encode(crt)}


def load_license(license_key: str) -> dict:
    payload = decode(license_key)
    try:
        message, signature = payload.split(sep)
    except ValueError:
        return None

    return json.loads(message)


def validate_license(crt: str, license_key: str) -> typing.Optional[dict]:
    if not license_key:
        return None

    pubkey = decode(crt)
    pubkey["n"] = int(pubkey["n"], 16)
    pubkey["e"] = int(pubkey["e"], 16)

    payload = decode(license_key)
    try:
        message, signature = payload.split(sep)
    except ValueError:
        return None

    messagehash = hash(message)
    sighash = decrypt(signature, pubkey["e"], pubkey["n"])
    if messagehash != sighash:
        return None

    license_data = json.loads(message)
    if license_data["start"] < time.time() < license_data["end"]:
        return license_data
    return None
