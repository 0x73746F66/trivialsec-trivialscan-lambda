import logging
import json
import re
import hmac
import hashlib
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from os import getenv, path
from typing import Union
from enum import Enum

import boto3
import validators
from pydantic import EmailStr, IPvAnyAddress
from retry.api import retry
from botocore.exceptions import (
    CapacityNotAvailableError,
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    ReadTimeoutError,
)
import requests
from sendgrid import SendGridAPIClient

import models

JITTER_SECONDS = int(getenv("JITTER_SECONDS", "30"))
APP_ENV = getenv("APP_ENV", "Dev")
APP_NAME = getenv("APP_NAME", "trivialscan-lambda")
STORE_BUCKET = getenv("STORE_BUCKET", "trivialscan-dashboard-store")
GENERIC_SECURITY_MESSAGE = "Your malformed request has been logged for investigation"
ALLOWED_ORIGINS = [
    "https://www.trivialsec.com",
    "https://scanner.trivialsec.com",
    "http://jager:5173",
    "http://localhost:5173",
]
DASHBOARD_URL = "https://scanner.trivialsec.com"
logger = logging.getLogger()
ssm_client = boto3.client(service_name="ssm")
s3_client = boto3.client(service_name="s3")

class StorageClass(str, Enum):
    STANDARD = "STANDARD"
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY"
    STANDARD_IA = "STANDARD_IA"
    ONEZONE_IA = "ONEZONE_IA"
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    GLACIER = "GLACIER"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"
    OUTPOSTS = "OUTPOSTS"
    GLACIER_IR = "GLACIER_IR"

class HMAC:
    auth_param_re = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
    auth_param_re = re.compile(r"^\s*" + auth_param_re + r"\s*$")
    unesc_quote_re = re.compile(r'(^")|([^\\]")')
    default_algorithm = 'sha512'
    supported_algorithms = {
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_384': hashlib.sha3_384,
        'sha3_512': hashlib.sha3_512,
        'blake2b512': hashlib.blake2b,
    }
    server_mac: str
    parsed_header: dict = dict()
    _not_before_seconds: int = JITTER_SECONDS
    _expire_after_seconds: int = JITTER_SECONDS

    @property
    def scheme(self):
        return self.parsed_header.get('scheme')

    @property
    def id(self):
        return self.parsed_header.get('id')

    @property
    def sesh(self):
        return self.parsed_header.get('sesh')

    @property
    def ts(self):
        return int(self.parsed_header.get('ts'))

    @property
    def mac(self):
        return self.parsed_header.get('mac')

    @property
    def canonical_string(self) -> str:
        parsed_url = urlparse(self.request_url)
        port = 443 if parsed_url.port is None else parsed_url.port
        bits = []
        bits.append(self.request_method.upper())
        bits.append(parsed_url.hostname.lower())
        bits.append(str(port))
        bits.append(parsed_url.path)
        bits.append(str(self.ts))
        if self.raw:
            bits.append(b64encode(self.raw.encode('utf8')).decode('utf8'))
        return "\n".join(bits)

    def __init__(self,
            authorization_header: str,
            request_url: str,
            method: str = "GET",
            raw_body: str = None,
            algorithm: str = None,
            not_before_seconds: int = JITTER_SECONDS,
            expire_after_seconds: int = JITTER_SECONDS,
        ):
        self.authorization_header = authorization_header
        self.raw = raw_body
        self.request_method = method
        self.request_url = request_url
        if not self.supported_algorithms.get(algorithm):
            algorithm = self.default_algorithm
        self.algorithm = algorithm
        self._expire_after_seconds = expire_after_seconds
        self._not_before_seconds = not_before_seconds
        self._parse_auth_header()

    def _parse_auth_header(self) -> None:
        scheme, pairs_str = self.authorization_header.split(None, 1)
        self.parsed_header = {"scheme": scheme}
        pairs = []
        if pairs_str:
            for pair in pairs_str.split(","):
                if not pairs or self.auth_param_re.match(pairs[-1]):
                    pairs.append(pair)
                else:
                    pairs[-1] = pairs[-1] + "," + pair
            if not self.auth_param_re.match(pairs[-1]):
                raise ValueError('Malformed auth parameters')
        for pair in pairs:
            (key, value) = pair.strip().split("=", 1)
            # For quoted strings, remove quotes and backslash-escapes.
            if value.startswith('"'):
                value = value[1:-1]
                if self.unesc_quote_re.search(value):
                    raise ValueError("Unescaped quote in quoted-string")
                value = re.compile(r"\\.").sub(lambda m: m.group(0)[1], value)
            self.parsed_header[key] = value

    def is_valid_scheme(self) -> bool:
        return self.authorization_header.startswith('HMAC')

    def is_valid_timestamp(self) -> bool:
        # not_before prevents replay attacks
        compare_date = datetime.fromtimestamp(self.ts, tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        not_before = now - timedelta(seconds=self._not_before_seconds)
        expire_after = now + timedelta(seconds=self._expire_after_seconds)
        # expire_after can assist with support for offline/aeroplane mode
        if compare_date < not_before or compare_date > expire_after:
            logger.info(f'now {now} compare_date {compare_date} not_before {not_before} expire_after {expire_after}')
            logger.info(f'compare_date < not_before {compare_date < not_before} compare_date > expire_after {compare_date > expire_after}')
            return False
        return True

    @staticmethod
    def _compare(*values):
        """
        _compare() takes two or more str or byte-like inputs and compares
        each to return True if they match or False if there is any mismatch
        """
        # In Python 3, if we have a bytes object, iterating it will already get the integer value
        def chk_bytes(val):
            return ord(val if isinstance(val, (bytes, bytearray)) else val.encode('utf8'))
        result = 0
        for index, this in enumerate(values):
            if index == 0:  # first index has nothing to compare
                continue
            # use the index variable i to locate prev
            prev = values[index-1]
            # Constant time string comparision, mitigates side channel attacks.
            if len(prev) != len(this):
                return False
            for _x, _y in zip(chk_bytes(prev), chk_bytes(this)):
                result |= _x ^ _y
        return result == 0

    def validate(self, secret_key: str):
        if not self.is_valid_scheme():
            logger.error(
                'incompatible authorization scheme, expected "Authorization: HMAC ..."')
            return False
        if not self.is_valid_timestamp():
            logger.error(f'jitter detected {self.ts}')
            return False
        if not self.supported_algorithms.get(self.algorithm):
            logger.error(f'algorithm {self.algorithm} is not supported')
            return False

        digestmod = self.supported_algorithms.get(self.algorithm)
        # Sign HMAC using server-side secret (not provided by client)
        digest = hmac.new(secret_key.encode(
            'utf8'), self.canonical_string.encode('utf8'), digestmod).hexdigest()
        self.server_mac = digest
        # Compare server-side HMAC with client provided HMAC
        if invalid := not hmac.compare_digest(digest, self.mac):
            logger.error(f'server_mac {self.server_mac} canonical_string {self.canonical_string}')
        return not invalid

class Authorization:
    def __init__(self,
        authorization_header: str,
        request_url: str,
        user_agent: Union[str, None] = None,
        ip_addr: Union[IPvAnyAddress, None] = None,
        account_name: Union[str, None] = None,
        method: str = "GET",
        raw_body: str = None,
        algorithm: str = None,
        not_before_seconds: int = JITTER_SECONDS,
        expire_after_seconds: int = JITTER_SECONDS
    ):
        self._hmac = HMAC(
            authorization_header,
            str(request_url),
            method,
            raw_body,
            algorithm,
            not_before_seconds,
            expire_after_seconds
        )
        self.ip_addr = ip_addr
        self.user_agent = user_agent
        self.is_valid: bool = False
        self.account: Union[models.MemberAccount, None] = None
        self.session: Union[models.MemberSession, None] = None
        self.client: Union[models.Client, None] = None
        self.member: Union[models.MemberProfile, None] = None
        logger.info(f"Authorization validation id {self._hmac.id}")
        if validators.email(self._hmac.id) is True:
            self.member = load_member(self._hmac.id)
            session_token = hashlib.sha224(bytes(f'{self.member.email}{ip_addr}{user_agent}', 'ascii')).hexdigest()
            logger.info(f"Session HMAC-based Authorization: session_token {session_token}")
            self.session = load_session(self.member.account.name, self.member.email, session_token)
            self.is_valid = self._hmac.validate(self.session.access_token)
        elif account_name is None or self._hmac.id == account_name:
            logger.info(f"Secret Key HMAC-based Authorization: account_name {account_name}")
            self.account = load_member_account(self._hmac.id)
            self.is_valid = self._hmac.validate(self.account.api_key)
        elif account_name:
            logger.info(f"Client Token HMAC-based Authorization: client_name {self._hmac.id}")
            self.account = load_member_account(account_name)
            self.client = load_client(self.account.name, self._hmac.id)
            if self.client:
                self.is_valid = self._hmac.validate(self.client.access_token)
        else:
            logger.error("Unhandled validation")


def object_exists(bucket_name: str, file_path: str, **kwargs):
    try:
        content = s3_client.head_object(Bucket=bucket_name, Key=file_path, **kwargs)
        return content.get("ResponseMetadata", None) is not None
    except ClientError as err:
        logger.debug(err, exc_info=True)
    return False

@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def get_ssm(parameter: str, default=None, **kwargs) -> str:
    logger.info(f"requesting secret {parameter}")
    try:
        response = ssm_client.get_parameter(Name=parameter, **kwargs)
        return (
            default
            if not isinstance(response, dict)
            else response.get("Parameter", {}).get("Value", default)
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.warning(f"The requested secret {parameter} was not found")
        elif err.response["Error"]["Code"] == "InvalidRequestException":
            logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "InvalidParameterException":
            logger.warning(f"The request had invalid params: {err}")
        else:
            logger.exception(err)
    return default

@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def store_ssm(parameter: str, value:str, **kwargs) -> bool:
    logger.info(f"storing secret {parameter}")
    try:
        response = ssm_client.put_parameter(Name=parameter, Value=value, **kwargs)
        return (
            False
            if not isinstance(response, dict)
            else response.get("Version") is not None
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "ParameterAlreadyExists":
            logger.warning(f"The secret {parameter} already exists")
        elif err.response["Error"]["Code"] == "InternalServerError":
            logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "TooManyUpdates":
            logger.warning(err, exc_info=True)
            raise RuntimeError("Please throttle your requests to continue using this service") from err
        elif err.response["Error"]["Code"] == "ParameterLimitExceeded":
            logger.warning(err, exc_info=True)
            raise RuntimeError("Platform is exhausted and unable to respond, please try again soon") from err
        else:
            logger.exception(err)
    return False

@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def list_s3(bucket_name: str, prefix_key: str, **kwargs) -> list[str]:
    """
    params:
    - bucket_name: s3 bucket with target contents
    - prefix_key: pattern to match in s3
    """
    logger.info(f"requesting bucket {bucket_name} key prefix {prefix_key}")
    keys = []
    next_token = ''
    base_kwargs = {
        'Bucket': bucket_name,
        'Prefix': prefix_key,
    }
    base_kwargs.update(kwargs)
    while next_token is not None:
        args = base_kwargs.copy()
        if next_token != '':
            args.update({'ContinuationToken': next_token})
        try:
            results = s3_client.list_objects_v2(**args)

        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchBucket":
                logger.error(f"The requested bucket {bucket_name} was not found")
            elif err.response["Error"]["Code"] == "InvalidObjectState":
                logger.error(f"The request was invalid due to: {err}")
            elif err.response["Error"]["Code"] == "InvalidParameterException":
                logger.error(f"The request had invalid params: {err}")
            else:
                logger.exception(err)
            return
        for item in results.get('Contents', []):
            k = item.get('Key')
            if k[-1] != '/':
                keys.append(k)
        next_token = results.get('NextContinuationToken')

    return keys

@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def get_s3(bucket_name: str, path_key: str, default=None, **kwargs) -> str:
    logger.info(f"requesting bucket {bucket_name} object key {path_key}")
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=path_key, **kwargs)
        return response["Body"].read().decode("utf8")

    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchKey":
            logger.warning(f"The requested bucket {bucket_name} object key {path_key} was not found")
        elif err.response["Error"]["Code"] == "InvalidObjectState":
            logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "InvalidParameterException":
            logger.warning(f"The request had invalid params: {err}")
        else:
            logger.exception(err)
    return default

@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def store_s3(bucket_name: str, path_key: str, value: str, storage_class: StorageClass = StorageClass.STANDARD_IA, **kwargs) -> bool:
    logger.debug(value)
    try:
        response = s3_client.put_object(
            Bucket=bucket_name,
            Key=path_key,
            Body=value,
            StorageClass=storage_class.name,
            **kwargs
        )
        return (
            False
            if not isinstance(response, dict)
            else response.get("ETag") is not None
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "ParameterAlreadyExists":
            logger.warning(f"The object bucket {bucket_name} key {path_key} already exists")
        elif err.response["Error"]["Code"] == "InternalServerError":
            logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "TooManyUpdates":
            logger.warning(err, exc_info=True)
            raise RuntimeError("Please throttle your requests to continue using this service") from err
        elif err.response["Error"]["Code"] == "ParameterLimitExceeded":
            logger.warning(err, exc_info=True)
            raise RuntimeError("Platform is exhausted and unable to respond, please try again soon") from err
        else:
            logger.exception(err)
    return False

def member_exists(member_email: str, account_name: Union[str, None] = None) -> bool:
    suffix = f"/members/{member_email}/profile.json"
    if account_name:
        return object_exists(STORE_BUCKET, f"{APP_ENV}/accounts/{account_name}{suffix}")
    prefix_matches = list_s3(bucket_name=STORE_BUCKET, prefix_key=f"{APP_ENV}/accounts")
    return len([k for k in prefix_matches if k.endswith(suffix)]) >= 1

def load_member_account(account_name: str) -> Union[models.MemberAccount, None]:
    object_key = f"{APP_ENV}/accounts/{account_name}/registration.json"
    return models.MemberAccount(**json.loads(get_s3(STORE_BUCKET, object_key)))

def load_member(member_email: str) -> Union[models.MemberProfile, None]:
    suffix = f"/members/{member_email}/profile.json"
    prefix_matches = list_s3(bucket_name=STORE_BUCKET, prefix_key=f"{APP_ENV}/accounts")
    matches = [k for k in prefix_matches if k.endswith(suffix)]
    if len(matches) > 1:
        logger.critical("load_member found too many matches, this is a data taint, likely manual data edits")
        logger.info(matches)
    if len(matches) == 0:
        return
    return models.MemberProfile(**json.loads(get_s3(STORE_BUCKET, matches[0])))

def save_account(account: models.MemberAccount) -> bool:
    object_key = f"{APP_ENV}/accounts/{account.name}/registration.json"
    return store_s3(
        STORE_BUCKET,
        object_key,
        json.dumps(account.dict(), default=str),
        storage_class=StorageClass.STANDARD
    )

def save_magic_link(link: models.MagicLink) -> bool:
    object_key = f"{APP_ENV}/magic-links/{link.magic_token}.json"
    return store_s3(
        STORE_BUCKET,
        object_key,
        json.dumps(link.dict(), default=str),
        storage_class=StorageClass.STANDARD_IA
    )

def save_member(member: models.MemberProfile) -> bool:
    object_key = f"{APP_ENV}/accounts/{member.account.name}/members/{member.email}/profile.json"
    return store_s3(
        STORE_BUCKET,
        object_key,
        json.dumps(member.dict(), default=str),
        storage_class=StorageClass.STANDARD
    )

def save_member_session(session: models.MemberSession) -> bool:
    object_key = f"{APP_ENV}/accounts/{session.member.account.name}/members/{session.member.email}/sessions/{session.session_token}.json"
    return store_s3(
        STORE_BUCKET,
        object_key,
        json.dumps(session.dict(), default=str),
        storage_class=StorageClass.ONEZONE_IA
    )

def load_session(account_name: str, client_email: EmailStr, session_token: str) -> Union[models.MemberSession, None]:
    if validators.email(client_email) is False:
        return
    object_key = f"{APP_ENV}/accounts/{account_name}/members/{client_email}/sessions/{session_token}.json"
    raw = get_s3(
        bucket_name=STORE_BUCKET,
        path_key=object_key,
    )
    if not raw:
        logger.warning(f"Missing session object: {object_key}")
        return
    try:
        data = json.loads(raw)
    except json.decoder.JSONDecodeError as err:
        logger.debug(err, exc_info=True)
        return
    if not isinstance(data, dict):
        logger.warning(f"Missing session data for object: {object_key}")
        return
    return models.MemberSession(**data)

def load_sessions(account_name: str, client_email: EmailStr) -> list[models.MemberSession]:
    prefix_key = f"{APP_ENV}/accounts/{account_name}/members/{client_email}/sessions/"
    ret = []
    prefix_matches = list_s3(bucket_name=STORE_BUCKET, prefix_key=prefix_key)
    if len(prefix_matches) == 0:
        return []
    for object_path in prefix_matches:
        raw = get_s3(STORE_BUCKET, object_path)
        if raw:
            ret.append(models.MemberSession(**json.loads(raw)))
    return ret

def load_client(account_name: str, client_name: str) -> Union[models.Client, None]:
    if validators.email(client_name) is True:
        return
    object_key = f"{APP_ENV}/accounts/{account_name}/client-tokens/{client_name}.json"
    raw = get_s3(
        bucket_name=STORE_BUCKET,
        path_key=object_key,
    )
    if not raw:
        logger.warning(f"Missing client object: {object_key}")
        return
    try:
        data = json.loads(raw)
    except json.decoder.JSONDecodeError as err:
        logger.debug(err, exc_info=True)
        return
    if not isinstance(data, dict):
        logger.warning(f"Missing client data for object: {object_key}")
        return
    return models.Client(**data)

def save_client(client: models.Client) -> bool:
    object_key = f"{APP_ENV}/accounts/{client.account.name}/client-tokens/{client.name}.json"
    return store_s3(
        STORE_BUCKET,
        object_key,
        json.dumps(client.dict(), default=str),
        storage_class=StorageClass.STANDARD
    )

def save_support(support: models.Support) -> bool:
    clean_subject = ''.join(e for e in '-'.join(support.subject.split()).replace('/', '-').lower() if e.isalnum() or e == '-')
    object_key = f"{APP_ENV}/accounts/{support.member.account.name}/members/{support.member.email}/support/{clean_subject}.json"
    return store_s3(
        STORE_BUCKET,
        object_key,
        json.dumps(support.dict(), default=str),
        storage_class=StorageClass.STANDARD
    )

def is_registered(account_name: str, trivialscan_client: Union[str, None] = None) -> bool:
    if trivialscan_client:
        if validators.email(trivialscan_client) is True:
            object_key = f"{APP_ENV}/accounts/{account_name}/members/{trivialscan_client}/profile.json"
        else:
            object_key = f"{APP_ENV}/accounts/{account_name}/client-tokens/{trivialscan_client}.json"
    else:
        object_key = f"{APP_ENV}/accounts/{account_name}/registration.json"

    raw = get_s3(
        bucket_name=STORE_BUCKET,
        path_key=object_key,
    )
    if not raw:
        return False
    try:
        data = json.loads(raw)
    except json.decoder.JSONDecodeError as err:
        logger.debug(err, exc_info=True)
        return False

    return isinstance(data, dict)

def store_summary(report: dict, path_prefix: str) -> bool:
    account_name = report["config"].get("account_name")
    summary_key = path.join(APP_ENV, "accounts", account_name, "results", path_prefix, "summary.json")
    logger.info(f"Storing {summary_key}")
    return store_s3(
        bucket_name=STORE_BUCKET,
        path_key=summary_key,
        value=json.dumps(report, default=str)
    )

def store_evaluations(report: list, account_name: str, path_prefix: str) -> bool:
    evaluations_key = path.join(APP_ENV, "accounts", account_name, "results", path_prefix, "evaluations.json")
    logger.info(f"Storing {evaluations_key}")
    return store_s3(
        bucket_name=STORE_BUCKET,
        path_key=evaluations_key,
        value=json.dumps(report, default=str)
    )

def store_host(report: dict) -> bool:
    host_key = path.join(APP_ENV, "hosts", report["transport"]["hostname"], str(report["transport"]["port"]), "latest.json")
    logger.info(f"Storing {host_key}")
    if not store_s3(
        bucket_name=STORE_BUCKET,
        path_key=host_key,
        value=json.dumps(report, default=str),
        storage_class=StorageClass.ONEZONE_IA,
    ):
        return False
    scan_date = datetime.fromisoformat(report["last_updated"]).strftime("%Y%m%d")
    host_key2 = path.join(APP_ENV, "hosts", report["transport"]["hostname"], str(report["transport"]["port"]), report["transport"]["peer_address"], f"{scan_date}.json")
    if object_exists(STORE_BUCKET, host_key2):
        logger.info(f"Exists {host_key2}")
        return True
    logger.info(f"Storing {host_key2}")
    return store_s3(
        bucket_name=STORE_BUCKET,
        path_key=host_key2,
        value=json.dumps(report, default=str),
    )

def store_certificate(report: dict) -> bool:
    cert_key = path.join(APP_ENV, "certificates", f"{report['sha1_fingerprint']}.json")
    if object_exists(STORE_BUCKET, cert_key):
        logger.info(f"Exists {cert_key}")
        return True
    logger.info(f"Storing {cert_key}")
    return store_s3(
        bucket_name=STORE_BUCKET,
        path_key=cert_key,
        value=json.dumps(report, default=str),
    )

def store_certificate_pem(pem: str, sha1_fingerprint: str) -> bool:
    pem_key = path.join(APP_ENV, "certificates", f"{sha1_fingerprint}.pem")
    if object_exists(STORE_BUCKET, pem_key):
        logger.info(f"Exists {pem_key}")
        return True
    logger.info(f"Storing {pem_key}")
    return store_s3(
        bucket_name=STORE_BUCKET,
        path_key=pem_key,
        value=pem,
    )

SENDGRID_TEMPLATES = {
    "account_recovery": "d-da9d3ba3389643289b8d3596e902068d",
    "magic_link": "d-48aa0ed2e9ff442ea6ee9b73ac984b96",
    "recovery_request": "d-1958843496444e7bb8e29f4277e74182",
    "registrations": "d-a0a115275e404b32bf96b540ecdffeda",
    "subscriptions": "d-1d20f029d4eb46b5957c253c3ccd3262",
    "updated_email": "d-fef742bc0a754165a8778f4929df3dbb",
    "invitations": "d-c4a471191062414ea3cefd67c98deed4",
    "support": "",
}
SENDGRID_GROUPS = {
    'notifications': 18318,
    'focus_group': 18317,
    'subscriptions': 18319,
    'marketing': 18316,
}
SENDGRID_LISTS = {
    'subscribers': "09998a12-998c-4ca8-990d-2c5e66f0c0ef",
    'members': "ce2b465e-60cd-426c-9ac1-78cdb8e9a4c4",
    'trials': "f0c56ac3-7317-4b39-9a26-b4e37bc33efd",
}

def send_email(
    subject: str,
    template: str,
    data: dict,
    recipient: str,
    group: str = 'notifications',
    sender: str = 'support@trivialsec.com',
    sender_name: str = 'Chris @ Trivial Security',
    bcc: Union[str, None] = "support@trivialsec.com"
):
    sendgrid_api_key = get_ssm(f'/{APP_ENV}/Deploy/{APP_NAME}/sendgrid_api_key', WithDecryption=True)
    sendgrid = SendGridAPIClient(sendgrid_api_key)
    tmp_url = sendgrid.client.mail.send._build_url(query_params={})  # pylint: disable=protected-access
    req_body = {
        'subject': subject,
        'from': {'email': "donotreply@trivialsec.com", 'name': sender_name},
        'reply_to': {'email': sender},
        'mail_settings': {
            'bcc': {'email': bcc, 'enable': bcc is not None and bcc != recipient},
            "footer": {
                "enable": False,
            },
            "sandbox_mode": {
                "enable": APP_ENV != "Prod"
            }
        },
        'template_id': SENDGRID_TEMPLATES.get(template),
        'asm': {
            'group_id': SENDGRID_GROUPS.get(group)
        },
        'personalizations': [
            {
                'subject': subject,
                'dynamic_template_data': {**data, **{'email': recipient}},
                'to': [
                    {
                        'email': recipient
                    }
                ],
                'bcc': [
                    {
                        'email': bcc,
                        'enable': bcc is not None and bcc != recipient
                    }
                ]
            }
        ]
    }
    res = requests.post(
        url=tmp_url,
        json=req_body,
        headers=sendgrid.client.request_headers,
        timeout=10
    )
    logger.info(res.__dict__)
    return res

def upsert_contact(recipient_email: str, list_name: str = 'subscribers'):
    sendgrid_api_key = get_ssm(f'/{APP_ENV}/Deploy/{APP_NAME}/sendgrid_api_key', WithDecryption=True)
    sendgrid = SendGridAPIClient(sendgrid_api_key)
    res = requests.put(
        url='https://api.sendgrid.com/v3/marketing/contacts',
        json={
            "list_ids": [
                SENDGRID_LISTS.get(list_name)
            ],
            "contacts": [{
                "email": recipient_email
            }]
        },
        headers=sendgrid.client.request_headers,
        timeout=10
    )
    logger.debug(res.__dict__)
    return res
