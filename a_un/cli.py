import argparse
import sys
import time
from datetime import timedelta

import pytz

from dateutil.parser import parse as parse_date

from .core import gen_keypair, gen_license, validate_license


def main():
    parser = argparse.ArgumentParser(description="Simple license key generator")
    subs = parser.add_subparsers()

    keypair_parser = subs.add_parser("gen-keypair", description="Generate keypair")
    keypair_parser.add_argument(
        "-s", "--key-size", help="Key size", default=4096, type=int
    )
    keypair_parser.add_argument("keypair_name", help="Key name")

    license_parser = subs.add_parser("gen-license", description="Generate license")
    license_parser.add_argument("-k", "--key-file", help="Key File", required=True)
    license_parser.add_argument(
        "-s", "--start-date", help="Start date (UTC)", required=True
    )
    license_parser.add_argument(
        "-d", "--days", help="License length in days", default=365, type=int
    )
    license_parser.add_argument("-c", "--comment", help="Comment", default=None)
    license_parser.add_argument("license_name", help="License filename")

    validate_parser = subs.add_parser(
        "validate-license", description="Validate license"
    )
    validate_parser.add_argument(
        "-c", "--cert-file", help="Certificate file", required=True
    )

    validate_parser.add_argument("license_file", help="License file")

    args = parser.parse_args()

    if getattr(args, "keypair_name", None):
        return generate_keypair(args)

    if getattr(args, "license_name", None):
        return generate_license(args)

    if getattr(args, "license_file", None):
        return validate(args)

    sys.exit(9)


def generate_keypair(args):

    pair = gen_keypair(args.key_size)
    name = args.keypair_name
    with open("%s.key" % name, "w") as f:
        f.write("# RSA private key \n")
        f.write(pair["key"])
    with open("%s.crt" % name, "w") as f:
        f.write("# RSA public key \n")
        f.write(pair["crt"])
    print("Written: %s.key and %s.crt" % (name, name))


def generate_license(args):

    start_date = parse_date(args.start_date).astimezone(pytz.UTC)
    end_date = start_date + timedelta(days=args.days)

    with open(args.key_file, "r") as f:
        key = f.read()

    extra_opts = {"created": int(time.time())}
    if args.comment:
        extra_opts["comment"] = args.comment
    license = gen_license(
        key, start_date.timestamp(), end_date.timestamp(), **extra_opts
    )

    with open("%s.license" % args.license_name, "w") as f:
        f.write("# License key \n")
        if args.comment:
            f.write("# %s\n" % args.comment)
        f.write(license)


def validate(args):

    with open(args.cert_file, "r") as f:
        crt = f.read()

    with open(args.license_file, "r") as f:
        license = f.read()

    license = validate_license(crt, license)
    if license:
        print("License is valid and active")
        print(license)
    else:
        print("License is invalid or expired")
