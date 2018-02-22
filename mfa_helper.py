import argparse
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path

import boto3

AWS_PATH = Path.home().joinpath(".aws")
DEFAULT_SERIAL_NUMBER_CACHE = str(AWS_PATH.joinpath("serial_numbers"))
DEFAULT_CREDENTIALS_PATH = str(AWS_PATH.joinpath("credentials"))


def get_logger(level=logging.INFO):
    log = logging.getLogger("aws-cli-mfa")
    log.setLevel(level)
    log.propagate = False
    ch = logging.StreamHandler()
    ch.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    ch.setFormatter(formatter)
    log.addHandler(ch)
    return log


logger = get_logger()


def get_cached_serial_number(cache_path, profile):
    return read_cache(cache_path).get(profile)


def read_cache(cache_path):
    p = Path(cache_path)
    if not p.exists():
        return {}
    with p.open() as f:
        try:
            cached_values = json.load(f)
        except json.JSONDecodeError:
            cached_values = {}
    return cached_values


def write_cache(cache_path, cache):
    p = Path(cache_path)
    with p.open(mode='w') as f:
        json.dump(cache, f)


def cache_serial_number(cache_path, profile, serial_number):
    cache = read_cache(cache_path)
    cache[profile] = serial_number
    write_cache(cache_path, cache)
    logger.info("Cached serial number '{}' for '{}' to '{}'"
                .format(serial_number, profile, cache_path))


def load_credentials(credentials_path):
    p = Path(credentials_path)
    if not p.exists():
        raise RuntimeError(
            "Could not locate credentials file {}".format(credentials_path))
    with p.open() as f:
        credentials = f.read().splitlines()
    return [c.strip() for c in credentials]


def save_credentials(credentials_path, creds):
    backup_path = "{}.{}".format(credentials_path, datetime.now().timestamp())
    shutil.copy(credentials_path, backup_path)
    logger.info("Previous credentials backed up to '{}'".format(backup_path))
    p = Path(credentials_path)
    with p.open(mode='w') as f:
        f.write("\n".join(creds))


def credential_indices(credentials, credentials_profile):
    profile_string = "[{}]".format(credentials_profile)
    if profile_string not in credentials:
        return len(credentials), len(credentials)
    start_index = credentials.index(profile_string)
    end_index = len(credentials)
    for i in range(start_index + 1, len(credentials)):
        if credentials[i].startswith("[") and credentials[i].startswith("]"):
            end_index = i
            break
    return start_index, end_index


def update_mfa_credentials(credentials_path, mfa_profile_name, access_key,
                           secret_access_key, session_token):
    current_credentials = load_credentials(credentials_path)
    mfa_start, mfa_end = credential_indices(current_credentials,
                                            mfa_profile_name)
    first = current_credentials[:mfa_start]
    last = current_credentials[mfa_end:]
    middle = [
        "[{}]".format(mfa_profile_name),
        "aws_access_key_id = {}".format(access_key),
        "aws_secret_access_key = {}".format(secret_access_key),
        "aws_session_token = {}".format(session_token),
        "",
    ]
    new_credentials = first + middle + last
    save_credentials(credentials_path, new_credentials)
    logger.info(
        "MFA credentials stored in profile '{}'".format(mfa_profile_name))


def export_variable(name, value):
    print("export {}={}".format(name.upper(), value))


def main():
    p = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("-c", "--code", help="Authentication code from mfa device.",
                   required=True)
    p.add_argument("-p", "--profile", help="AWS profile to get a session for.",
                   required=True)
    p.add_argument("-r", "--region", help="AWS region to use.",
                   default="eu-west-1")
    p.add_argument("-d", "--duration",
                   help="Duration in seconds to keep the STS token valid for.",
                   default=43200, type=int)
    p.add_argument("-s", "--serial-number",
                   help="Serial number for your MFA device. "
                        "ARN in the case of a virtual device. Falls back to a "
                        "cached value in {}."
                   .format(DEFAULT_SERIAL_NUMBER_CACHE))
    p.add_argument("--cache-path", help="Path to the serial number cache.",
                   default=DEFAULT_SERIAL_NUMBER_CACHE)
    p.add_argument("--credentials-path",
                   help="Path to the AWS credentials file.",
                   default=DEFAULT_CREDENTIALS_PATH)
    args = p.parse_args()
    if args.serial_number is None:
        serial_number = get_cached_serial_number(args.cache_path, args.profile)
        logger.info("Retrieved cached serial number '{}' for '{}'"
                    .format(serial_number, args.profile))
        if serial_number is None:
            raise RuntimeError(
                "No serial number provided for your mfa device and no serial "
                "number present in cache at '{}'. "
                "Please provide a serial number or ARN for your mfa device "
                "with the '-s' option.".format(args.cache_path))
    else:
        serial_number = args.serial_number
        cache_serial_number(args.cache_path, args.profile, serial_number)

    sts = boto3.session.Session(region_name=args.region,
                                profile_name=args.profile).client("sts")
    response = sts.get_session_token(DurationSeconds=args.duration,
                                     SerialNumber=serial_number,
                                     TokenCode=args.code)
    if "Credentials" not in response:
        raise RuntimeError(
            "Received invalid response '{}' from STS".format(response))

    access_key = response["Credentials"]["AccessKeyId"]
    secret_access_key = response["Credentials"]["SecretAccessKey"]
    session_token = response["Credentials"]["SessionToken"]

    mfa_profile_name = "mfa-{}".format(args.profile)
    update_mfa_credentials(args.credentials_path, mfa_profile_name, access_key,
                           secret_access_key, session_token)
    export_variable("AWS_ACCESS_KEY_ID", access_key)
    export_variable("AWS_SECRET_ACCESS_KEY", secret_access_key)
    export_variable("AWS_SESSION_TOKEN", session_token)


if __name__ == "__main__":
    main()
