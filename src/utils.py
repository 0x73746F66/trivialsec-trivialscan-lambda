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
RESERVED_CLIENTS = ["dashboard", "cli"]
logger = logging.getLogger()
boto3.set_stream_logger('')
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

def retrieve_token(account_name: str, client_name: str) -> Union[str, None]:
    if client_name in RESERVED_CLIENTS:
        object_key = f"{APP_ENV}/accounts/{account_name}/registration.json"
    else:
        object_key = f"{APP_ENV}/accounts/{account_name}/client-tokens/{client_name}.json"
    register_str = get_s3(
        bucket_name=STORE_BUCKET,
        path_key=object_key,
    )
    logger.warning(register_str)
    if not register_str:
        return None
    try:
        register_data = json.loads(register_str)
    except json.decoder.JSONDecodeError as err:
        logger.debug(err, exc_info=True)
        return None

    return register_data.get("api_key") if client_name in RESERVED_CLIENTS else register_data.get("access_token")

def member_exists(member_email: str, account_name: Union[str, None] = None) -> bool:
    suffix = f"/members/{member_email}/profile.json"
    if account_name:
        return object_exists(STORE_BUCKET, f"{APP_ENV}/accounts/{account_name}{suffix}")
    prefix_matches = list_s3(bucket_name=STORE_BUCKET, prefix_key=f"{APP_ENV}/accounts")
    return len([k for k in prefix_matches if k.endswith(suffix)]) == 1

def load_member(member_email: str) -> Union[models.MemberProfile, None]:
    suffix = f"/members/{member_email}/profile.json"
    prefix_matches = list_s3(bucket_name=STORE_BUCKET, prefix_key=f"{APP_ENV}/accounts")
    matches = [k for k in prefix_matches if k.endswith(suffix)]
    if len(matches) != 1:
        return
    return models.MemberProfile(**json.loads(get_s3(STORE_BUCKET, matches[0])))

def is_registered(account_name: str, trivialscan_client: Union[str, None] = None) -> bool:
    if trivialscan_client and trivialscan_client not in RESERVED_CLIENTS:
        object_key = f"{APP_ENV}/accounts/{account_name}/client-tokens/{trivialscan_client}.json"
    else:
        object_key = f"{APP_ENV}/accounts/{account_name}/registration.json"

    register_str = get_s3(
        bucket_name=STORE_BUCKET,
        path_key=object_key,
    )
    if not register_str:
        return False
    try:
        register_data = json.loads(register_str)
    except json.decoder.JSONDecodeError as err:
        logger.debug(err, exc_info=True)
        return False

    return isinstance(register_data, dict)

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
    'invitations': "d-ddd501dd76634f12bdba7dfcee416270",
    'registrations': "d-1259c22153484803bdc4d6cb490571a6",
    'subscriptions': "d-14c95c71ba5f40deac27eb8e0bcd0373",
    'updated_email': 'd-30f820fc0f8a4f4d9f0fd5592a7419b5',
    'account_recovery': "d-a791985ca56f4339acd9a77cc5d66cbd",
    'magic_link': "d-c356f835c3b541d2ba76f5f50bb5a27b",
    'recovery_request': "d-11d132b6513749a48005d21cb56df2dc",
}
SENDGRID_GROUPS = {
    'notifications': 14193,
    'focus_group': 14107,
    'subscriptions': 14106,
    'marketing': 14105,
}
SENDGRID_LISTS = {
    'subscribers': "a656c506-1a36-45ad-ad29-bb54db25ccd9",
    'members': "7c88b8a4-9b7a-4a25-9b09-be3d3a0cdcf3",
    'trials': "6d72d4a5-5e15-455f-9cd4-0f28a9f06e24",
}
def send_email(subject: str, template: str, data: dict, recipient: str, group: str = 'notifications', sender: str = 'support@trivialsec.com'):
    sendgrid_api_key = get_ssm(f'/{APP_ENV}/Deploy/trivialsec/sendgrid_api_key', WithDecryption=True)
    sendgrid = SendGridAPIClient(sendgrid_api_key)
    tmp_url = sendgrid.client.mail.send._build_url(query_params={})  # pylint: disable=protected-access
    req_body = {
        'subject': subject,
        'from': {'email': sender},
        'template_id': SENDGRID_TEMPLATES.get(template),
        'asm': {
            'group_id': SENDGRID_GROUPS.get(group)
        },
        'personalizations': [
            {
                'dynamic_template_data': {**data, **{'email': recipient}},
                'to': [
                    {
                        'email': recipient
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
    logger.debug(res.__dict__)
    return res

def upsert_contact(recipient_email: str, list_name: str = 'subscribers'):
    sendgrid_api_key = get_ssm(f'/{APP_ENV}/Deploy/trivialsec/sendgrid_api_key', WithDecryption=True)
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
