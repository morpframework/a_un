import base64
import hashlib
import json
import os
import textwrap
import time

from Crypto.PublicKey import RSA

sep = "|||"


def encode(d: dict) -> str:
    s = json.dumps(d)
    txt = base64.b64encode(s.encode("utf8")).decode("utf8")
    return "\n".join(textwrap.wrap(txt, width=60))


def decode(s: str) -> dict:
    ns = ""
    for l in s.split("\n"):
        if not l.startswith("#"):
            ns += l

    j = base64.b64decode(ns.encode("utf8")).decode("utf8")
    return json.loads(j)


def gen_license(key: str, start: int, days: int):
    privkey = decode(key)
    privkey["d"] = int(privkey["d"], 16)
    privkey["n"] = int(privkey["n"], 16)

    end = start + (days * 24 * 60 * 60)
    message = json.dumps({"start": start, "end": end}).encode("utf8")
    hash = int.from_bytes(hashlib.sha512(message).digest(), byteorder="big")
    signature = pow(hash, privkey["d"], privkey["n"])
    payload = "%s%s%s" % (message, sep, signature)
    return encode(payload)


def gen_keypair(size=4096):
    keypair = RSA.generate(size)
    key = json.dumps({"d": hex(keypair.d), "n": hex(keypair.n)})
    crt = json.dumps({"e": hex(keypair.e), "n": hex(keypair.n)})
    return {"key": encode(key), "crt": encode(crt)}


def validate_license(crt: str, license_key: str) -> bool:
    if not license_key:
        return False

    pubkey = decode(crt)
    pubkey["n"] = int(pubkey["n"], 16)
    pubkey["e"] = int(pubkey["e"], 16)

    payload = decode(license_key)
    try:
        message, signature = payload.split(sep)
    except ValueError:
        return False
    hash = int.from_bytes(
        hashlib.sha512(message.encode("utf8")).digest(), byteorder="big"
    )
    signature = int(signature, 16)
    sighash = pow(signature, pubkey["e"], pubkey["n"])
    if hash != sighash:
        return False

    license_data = json.loads(message)
    if license_data["start"] < time.time() < license_data["end"]:
        return True
    return False
