import logging
import re
import hmac
import hashlib
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from os import getenv
from typing import Union

import validators
from user_agents import parse as ua_parser
from starlette.requests import Request
from pydantic import IPvAnyAddress

JITTER_SECONDS = int(getenv("JITTER_SECONDS", "30"))
APP_ENV = getenv("APP_ENV", "Dev")
APP_NAME = getenv("APP_NAME", "trivialscan-lambda")
GENERIC_SECURITY_MESSAGE = "Your malformed request has been logged for investigation"
ALLOWED_ORIGINS = [
    "https://www.trivialsec.com",
    "http://jager:5173",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://100.73.142.90:5173",
    "http://[fd7a:115c:a1e0:ab12:4843:cd96:6249:8e5a]:5173",
]
DASHBOARD_URL = "https://www.trivialsec.com"
logger = logging.getLogger()

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
        return int(self.parsed_header.get('ts'))  # type: ignore

    @property
    def mac(self):
        return self.parsed_header.get('mac')

    @property
    def canonical_string(self) -> str:
        parsed_url = urlparse(self.request_url)
        port = 443 if parsed_url.port is None else parsed_url.port
        bits = []
        bits.append(self.request_method.upper())
        bits.append(parsed_url.hostname.lower())  # type: ignore
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
            raw_body: Union[str, None] = None,  # type: ignore
            algorithm: Union[str, None] = None,  # type: ignore
            not_before_seconds: int = JITTER_SECONDS,
            expire_after_seconds: int = JITTER_SECONDS,
        ):
        self.authorization_header = authorization_header
        self.raw = raw_body
        self.request_method = method
        self.request_url = request_url
        if not self.supported_algorithms.get(algorithm):  # type: ignore
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
                if not pairs or self.auth_param_re.match(pairs[-1]):  # type: ignore
                    pairs.append(pair)
                else:
                    pairs[-1] = pairs[-1] + "," + pair
            if not self.auth_param_re.match(pairs[-1]):  # type: ignore
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
            for _x, _y in zip(chk_bytes(prev), chk_bytes(this)):  # type: ignore
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
        if not self.supported_algorithms.get(self.algorithm):  # type: ignore
            logger.error(f'algorithm {self.algorithm} is not supported')
            return False

        digestmod = self.supported_algorithms.get(self.algorithm)  # type: ignore
        # Sign HMAC using server-side secret (not provided by client)
        digest = hmac.new(secret_key.encode(
            'utf8'), self.canonical_string.encode('utf8'), digestmod).hexdigest()  # type: ignore
        self.server_mac = digest
        # Compare server-side HMAC with client provided HMAC
        if invalid := not hmac.compare_digest(digest, self.mac):  # type: ignore
            logger.error(f'server_mac {self.server_mac} canonical_string {self.canonical_string}')
        return not invalid

class Authorization:
    def __init__(self,
        request: Request,
        user_agent: Union[str, None] = None,
        ip_addr: Union[IPvAnyAddress, None] = None,
        account_name: Union[str, None] = None,
        algorithm: Union[str, None] = None,  # type: ignore
        not_before_seconds: int = JITTER_SECONDS,
        expire_after_seconds: int = JITTER_SECONDS,
        raw_body: Union[str, None] = None,
    ):
        import models  # pylint: disable=import-outside-toplevel
        if postman_token := request.headers.get("Postman-Token"):
            logger.info(f"Postman-Token: {postman_token}")
        if not raw_body and hasattr(request, '_body'):
            raw_body = request._body.decode("utf8")  # pylint: disable=protected-access
        self._hmac = HMAC(
            authorization_header=request.headers.get("Authorization"),
            request_url=str(request.url),
            method=request.method.upper(),
            raw_body=raw_body,
            algorithm=algorithm,
            not_before_seconds=not_before_seconds,
            expire_after_seconds=expire_after_seconds,
        )
        self.ip_addr = ip_addr if ip_addr else request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP"))
        self.user_agent = user_agent if user_agent else request.headers.get("User-Agent")
        if not self.ip_addr:
            logger.error("IP Address not determined, potential conflict if not deliberate or is running locally")

        self.is_valid: bool = False
        self.account: Union[models.MemberAccount, None] = None
        self.session: Union[models.MemberSession, None] = None
        self.client: Union[models.Client, None] = None
        self.member: Union[models.MemberProfile, None] = None
        logger.info(f"Authorization validation id {self._hmac.id}")
        secret_key = None
        if validators.email(self._hmac.id) is True:  # type: ignore
            if not self.user_agent:
                logger.critical("Missing User-Agent")
                return
            ua = ua_parser(self.user_agent)
            if ua.is_bot:
                logger.critical("DENY Bot User-Agent")
                return
            if not any([ua.is_mobile, ua.is_tablet, ua.is_pc]) and not postman_token:
                logger.critical("DENY unrecognisable User-Agent")
                return
            self.member = models.MemberProfile(email=self._hmac.id).load()
            if not self.member:
                logger.critical(f"DENY missing MemberProfile {self._hmac.id}")
                return
            self.account = self.member.account.load()  # type: ignore
            session_token = hashlib.sha224(bytes(f'{self.member.email}{self.ip_addr}{self.user_agent}', 'ascii')).hexdigest()
            logger.info(f"Session HMAC-based Authorization: session_token {session_token}")
            self.session = models.MemberSession(member=self.member, session_token=session_token).load()  # type: ignore
            if not self.session:
                logger.critical(f"DENY missing MemberSession {self._hmac.id}")
                return
            if any([
                self.account.display != self.member.account.display,  # type: ignore
                self.account.billing_email != self.member.account.billing_email,  # type: ignore
                self.account.primary_email != self.member.account.primary_email,  # type: ignore
            ]):
                self.member.account = self.account
                self.member.save()
            if any([
                self.account.display != self.session.member.account.display,  # type: ignore
                self.account.billing_email != self.session.member.account.billing_email,  # type: ignore
                self.account.primary_email != self.session.member.account.primary_email,  # type: ignore
            ]):
                self.session.member = self.member  # type: ignore
                self.session.save()  # type: ignore
            secret_key = self.session.access_token  # type: ignore
        elif account_name is None or self._hmac.id == account_name:
            logger.info(f"Secret Key HMAC-based Authorization: account_name {account_name}")
            self.account = models.MemberAccount(name=self._hmac.id).load()  # type: ignore
            if self.account:
                secret_key = self.account.api_key
        elif account_name:
            logger.info(f"Client Token HMAC-based Authorization: client_name {self._hmac.id}")
            self.account = models.MemberAccount(name=account_name).load()  # type: ignore
            if not self.account:
                return
            self.client = models.Client(account=self.account, name=self._hmac.id).load()  # type: ignore
            if self.client:
                if any([
                    self.account.display != self.client.account.display,  # type: ignore
                    self.account.billing_email != self.client.account.billing_email,  # type: ignore
                    self.account.primary_email != self.client.account.primary_email,  # type: ignore
                ]):
                    self.client.account = self.account
                    self.client.save()
                secret_key = self.client.access_token
        if not secret_key:
            logger.critical("Unhandled validation")
            return
        self.is_valid = self._hmac.validate(secret_key)
