# pylint: disable=line-too-long
import json
import logging
import hmac
import hashlib
from base64 import b64encode, b64decode
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from os import getenv
from typing import Union
from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv6Address,
)

import validators
from user_agents import parse as ua_parser
from starlette.requests import Request
from fastapi import Header, HTTPException, status, File, UploadFile
from pydantic import (
    IPvAnyAddress,
    AnyHttpUrl,
    PositiveInt,
    PositiveFloat,
    EmailStr,
)


CACHE_DIR = getenv("CACHE_DIR", "/tmp")
JITTER_SECONDS = int(getenv("JITTER_SECONDS", default="30"))
APP_ENV = getenv("APP_ENV", "Dev")
APP_NAME = getenv("APP_NAME", "trivialscan-lambda")
GENERIC_SECURITY_MESSAGE = "Your malformed request has been logged for investigation"
ALLOWED_ORIGINS = (
    [
        "https://dev.trivialsec.com",
        "http://localhost:5173",
        "http://jager:5173",
    ]
    if APP_ENV == "Dev"
    else [
        "https://www.trivialsec.com",
    ]
)
DASHBOARD_URL = (
    "https://dev.trivialsec.com" if APP_ENV == "Dev" else "https://www.trivialsec.com"
)
AUTHZ_REALM = 'HMAC realm="trivialscan"'
ERR_INVALID_AUTHORIZATION = "Invalid Authorization"
ERR_MISSING_AUTHORIZATION = "Missing Authorization header"

logger = logging.getLogger()


class HMAC:
    default_algorithm = "sha512"
    supported_algorithms = {
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3_256": hashlib.sha3_256,
        "sha3_384": hashlib.sha3_384,
        "sha3_512": hashlib.sha3_512,
        "blake2b512": hashlib.blake2b,
    }
    _not_before_seconds: int = JITTER_SECONDS
    _expire_after_seconds: int = JITTER_SECONDS

    @property
    def scheme(self) -> Union[str, None]:
        return None if not hasattr(self, 'parsed_header') else self.parsed_header.get("scheme")

    @property
    def id(self) -> Union[str, None]:
        return None if not hasattr(self, 'parsed_header') else self.parsed_header.get("id")

    @property
    def ts(self) -> Union[int, None]:
        return None if not hasattr(self, 'parsed_header') else int(self.parsed_header.get("ts"))  # type: ignore

    @property
    def mac(self) -> Union[str, None]:
        return None if not hasattr(self, 'parsed_header') else self.parsed_header.get("mac")

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
        if self.contents:
            bits.append(b64encode(self.contents.encode("utf8")).decode("utf8"))
        return "\n".join(bits)

    def __init__(
        self,
        authorization_header: str,
        request_url: str,
        method: str = "GET",
        raw_body: Union[str, None] = None,  # type: ignore
        algorithm: Union[str, None] = None,  # type: ignore
        not_before_seconds: int = JITTER_SECONDS,
        expire_after_seconds: int = JITTER_SECONDS,
    ):
        self.server_mac: str = ""
        self.authorization_header: str = authorization_header
        self.contents = raw_body
        self.request_method: str = method
        self.request_url: str = request_url
        self.algorithm: str = self.default_algorithm if not self.supported_algorithms.get(algorithm) else algorithm  # type: ignore
        self._expire_after_seconds: int = expire_after_seconds
        self._not_before_seconds: int = not_before_seconds
        from services.helpers import (
            parse_authorization_header,
        )  # pylint: disable=import-outside-toplevel
        self.parsed_header: dict[str, str] = parse_authorization_header(authorization_header)

    def is_valid_scheme(self) -> bool:
        return self.authorization_header.startswith("HMAC")

    def is_valid_timestamp(self) -> bool:
        # not_before prevents replay attacks
        compare_date = datetime.fromtimestamp(float(self.ts), tz=timezone.utc)  # type: ignore
        now = datetime.now(tz=timezone.utc)
        not_before = now - timedelta(seconds=self._not_before_seconds)
        expire_after = now + timedelta(seconds=self._expire_after_seconds)
        # expire_after can assist with support for offline/aeroplane mode
        if compare_date < not_before or compare_date > expire_after:
            logger.info(
                f"now {now} compare_date {compare_date} not_before {not_before} expire_after {expire_after}"
            )
            logger.info(
                f"compare_date < not_before {compare_date < not_before} compare_date > expire_after {compare_date > expire_after}"
            )
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
            return ord(
                val if isinstance(val, (bytes, bytearray)) else val.encode("utf8")
            )

        result = 0
        for index, this in enumerate(values):
            if index == 0:  # first index has nothing to compare
                continue
            # use the index variable i to locate prev
            prev = values[index - 1]
            # Constant time string comparison, mitigates side channel attacks.
            if len(prev) != len(this):
                return False
            for _x, _y in zip(chk_bytes(prev), chk_bytes(this)):  # type: ignore
                result |= _x ^ _y
        return result == 0

    def validate(self, secret_key: str):
        if not self.is_valid_scheme():
            logger.error(
                'incompatible authorization scheme, expected "Authorization: HMAC ..."'
            )
            return False
        if not self.is_valid_timestamp():
            logger.error(f"jitter detected {self.ts}")
            return False
        if not self.supported_algorithms.get(self.algorithm):  # type: ignore
            logger.error(f"algorithm {self.algorithm} is not supported")
            return False

        digestmod = self.supported_algorithms.get(self.algorithm, self.default_algorithm)  # type: ignore
        # Sign HMAC using server-side secret (not provided by client)
        digest = hmac.new(
            secret_key.encode("utf8"), self.canonical_string.encode("utf8"), digestmod
        ).hexdigest()  # type: ignore
        self.server_mac = digest
        # Compare server-side HMAC with client provided HMAC
        if invalid := not hmac.compare_digest(digest, self.mac):  # type: ignore
            logger.error(
                f"server_mac {self.server_mac} canonical_string {self.canonical_string}"
            )
        return not invalid


class TokenTypes(str, Enum):
    SESSION_TOKEN = "session_token"
    CLIENT_TOKEN = "client_token"
    SECRET_KEY = "secret_token"


class AuthorizationRoute(str, Enum):
    STORE_SUMMARY = "/store/report"
    STORE_REPORT = "/store/evaluations"
    STORE_CERTIFICATE = "/store/certificate"
    LIST_REPORTS = "/reports"
    FULL_REPORT = "/report/"
    REPORT_SUMMARY = "/summary/"
    DASHBOARD_COMPLIANCE = "/dashboard/compliance"
    DASHBOARD_CERTIFICATE_ISSUES = "/findings/certificate"
    DASHBOARD_LATEST_ISSUES = "/findings/latest"
    DASHBOARD_QUOTAS = "/dashboard/quotas"
    SEARCH_HOST = "/search/host/"
    SEARCH_IP = "/search/ip/"
    CERTIFICATE_SHA1 = "/certificate/"
    ENABLE_MONITOR = "/scanner/monitor/"
    DEACTIVATE_MONITOR = "/scanner/deactivate/"
    SCANNER_QUEUE = "/scanner/queue/"
    VALIDATE = "/validate"
    ME = "/me"
    LIST_SESSIONS = "/sessions"
    LIST_MEMBERS = "/members"
    INVITE_MEMBER = "/member/invite"
    DELETE_MEMBER = "/member/"
    REVOKE_SESSION = "/revoke/"
    MAGIC_LINK_LOGIN = "/magic-link/"
    MAGIC_LINK_GENERATION = "/magic-link"
    CHANGE_MEMBER_EMAIL = "/member/email"
    ACCEPT_CHANGE_REQUEST = "/accept/"
    LIST_HOSTS = "/hosts"
    GET_HOST = "/host/"
    LIST_CLIENTS = "/clients"
    GET_CLIENT = "/client/"
    CLAIM_CLIENT = "/claim/"
    CLIENT_AUTH = "/auth/"
    CLIENT_ACTIVATE = "/activate/"
    CLIENT_DEACTIVATE = "/deactivate/"
    SUPPORT = "/support"


class Authorization:
    client_allow: list[AuthorizationRoute] = [
        AuthorizationRoute.STORE_SUMMARY,
        AuthorizationRoute.STORE_REPORT,
        AuthorizationRoute.STORE_CERTIFICATE,
        AuthorizationRoute.VALIDATE,
        AuthorizationRoute.CLAIM_CLIENT,
        AuthorizationRoute.CLIENT_AUTH,
    ]
    session_allow: list[AuthorizationRoute] = [
        AuthorizationRoute.LIST_REPORTS,
        AuthorizationRoute.FULL_REPORT,
        AuthorizationRoute.REPORT_SUMMARY,
        AuthorizationRoute.DASHBOARD_COMPLIANCE,
        AuthorizationRoute.DASHBOARD_QUOTAS,
        AuthorizationRoute.DASHBOARD_CERTIFICATE_ISSUES,
        AuthorizationRoute.DASHBOARD_LATEST_ISSUES,
        AuthorizationRoute.SEARCH_HOST,
        AuthorizationRoute.SEARCH_IP,
        AuthorizationRoute.CERTIFICATE_SHA1,
        AuthorizationRoute.ENABLE_MONITOR,
        AuthorizationRoute.DEACTIVATE_MONITOR,
        AuthorizationRoute.SCANNER_QUEUE,
        AuthorizationRoute.ME,
        AuthorizationRoute.LIST_CLIENTS,
        AuthorizationRoute.LIST_MEMBERS,
        AuthorizationRoute.INVITE_MEMBER,
        AuthorizationRoute.DELETE_MEMBER,
        AuthorizationRoute.LIST_SESSIONS,
        AuthorizationRoute.REVOKE_SESSION,
        AuthorizationRoute.MAGIC_LINK_LOGIN,
        AuthorizationRoute.MAGIC_LINK_GENERATION,
        AuthorizationRoute.CHANGE_MEMBER_EMAIL,
        AuthorizationRoute.ACCEPT_CHANGE_REQUEST,
        AuthorizationRoute.LIST_HOSTS,
        AuthorizationRoute.GET_HOST,
        AuthorizationRoute.CLIENT_ACTIVATE,
        AuthorizationRoute.CLIENT_DEACTIVATE,
        AuthorizationRoute.GET_CLIENT,
        AuthorizationRoute.SUPPORT,
        AuthorizationRoute.CLAIM_CLIENT,
    ]
    secret_allow: list[AuthorizationRoute] = [
    ]

    def __init__(
        self,
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
        self.hmac: HMAC
        self.token_type: TokenTypes
        self.route: AuthorizationRoute
        self.is_valid: bool = False
        self.is_authorized: bool = False
        self.account: Union[models.MemberAccount, None] = None
        self.session: Union[models.MemberSession, None] = None
        self.client: Union[models.Client, None] = None
        self.member: Union[models.MemberProfile, None] = None
        self.ip_addr: Union[IPvAnyAddress, None] = None
        self.user_agent: str

        if postman_token := request.headers.get("Postman-Token"):
            logger.info(f"Postman-Token: {postman_token}")

        self.hmac = HMAC(
            authorization_header=request.headers.get("Authorization"),
            request_url=str(request.url),
            method=request.method.upper(),
            raw_body=raw_body,
            algorithm=algorithm,
            not_before_seconds=not_before_seconds,
            expire_after_seconds=expire_after_seconds,
        )
        self.ip_addr = (
            ip_addr
            if ip_addr
            else request.headers.get(
                "X-Forwarded-For", request.headers.get("X-Real-IP")
            )
        )
        self.user_agent = (
            user_agent if user_agent else request.headers.get("User-Agent")
        )
        if not self.ip_addr:
            logger.warning(
                "IP Address not determined, potential conflict if not deliberate or is running locally"
            )

        logger.info(f"Authorization validation id {self.hmac.id}")
        secret_key = None
        if validators.email(self.hmac.id) is True:  # type: ignore
            if not self.user_agent:
                logger.critical("Missing User-Agent")
                return
            ua = ua_parser(self.user_agent)
            if ua.is_bot:
                logger.critical("DENY Bot User-Agent")
                return
            if not any([ua.is_mobile, ua.is_tablet, ua.is_pc]) and not postman_token:
                logger.critical(f"DENY unrecognisable User-Agent {self.user_agent}")
                return
            self.member = models.MemberProfile(email=self.hmac.id).load()
            if not isinstance(self.member, models.MemberProfile):
                logger.critical(f"DENY missing MemberProfile {self.hmac.id}")
                return
            self.account = self.member.account  # type: ignore
            if not isinstance(self.account, models.MemberAccount):
                logger.critical(f"DENY missing MemberAccount {self.hmac.id}")
                return
            logger.info(
                f"Session inputs; {self.member.email} | {ua.get_browser()} | {ua.get_os()} | {ua.get_device()}"
            )
            session_token = hashlib.sha224(
                bytes(
                    f"{self.member.email}{ua.get_browser()}{ua.get_os()}{ua.get_device()}",
                    "ascii",
                )
            ).hexdigest()
            logger.info(
                f"AUTH_FLOW Session HMAC-based Authorization: session_token {session_token}"
            )
            self.session = models.MemberSession(member=self.member, session_token=session_token).load()  # type: ignore
            if not isinstance(self.session, models.MemberSession):
                logger.critical(f"DENY missing MemberSession {self.hmac.id}")
                return
            secret_key = self.session.access_token  # type: ignore
            self.token_type = TokenTypes.SESSION_TOKEN
        elif account_name is None or self.hmac.id == account_name:
            logger.info(
                f"AUTH_FLOW Secret Key HMAC-based Authorization: account_name {account_name}"
            )
            self.account = models.MemberAccount(name=self.hmac.id).load()  # type: ignore
            if not isinstance(self.account, models.MemberAccount):
                logger.critical(f"DENY missing MemberAccount {self.hmac.id}")
                return
            secret_key = self.account.api_key  # type: ignore pylint: disable=no-member
            self.token_type = TokenTypes.SECRET_KEY
        elif account_name:
            logger.info(
                f"AUTH_FLOW Client Token HMAC-based Authorization: client_name {self.hmac.id}"
            )
            self.client = models.Client(name=self.hmac.id).load(account_name=account_name)  # type: ignore
            if not isinstance(self.client, models.Client):
                logger.critical(f"DENY missing Client {self.hmac.id}")
                return
            self.account = self.client.account
            if not isinstance(self.account, models.MemberAccount):
                logger.critical(f"DENY missing MemberAccount {self.hmac.id}")
            if self.client.active:
                secret_key = self.client.access_token
                self.token_type = TokenTypes.CLIENT_TOKEN
        if not secret_key:
            logger.critical("Unhandled validation")
            return

        self.is_valid = self.hmac.validate(secret_key)
        logger.info(f"is_valid {self.is_valid}")
        self.is_authorized = self.is_valid and self.authorized(request.url.path)

    def authorized(self, request_url_path: str) -> bool:
        """
        Based on the authentication type, what endpoints should be allowed
        """
        if self.token_type == TokenTypes.CLIENT_TOKEN:
            logger.info(f"request_url_path {request_url_path}")
            for route in self.client_allow:
                logger.info(f"startswith {route.value}")
                if request_url_path.startswith(route.value):
                    logger.info("break")
                    self.route = route
                    break
        if self.token_type == TokenTypes.SECRET_KEY:
            for route in self.secret_allow:
                if request_url_path.startswith(route.value):
                    self.route = route
                    break
        if self.token_type == TokenTypes.SESSION_TOKEN:
            for route in self.session_allow:
                if request_url_path.startswith(route.value):
                    self.route = route
                    break

        return hasattr(self, 'route') and isinstance(self.route, AuthorizationRoute)

    def dict(self):
        return {
            "token_type": self.token_type,
            "route": self.route,
            "is_valid": self.is_valid,
            "is_authorized": self.is_authorized,
            "account": None
            if not hasattr(self, "account") or not self.account
            else self.account.dict(),
            "session": None
            if not hasattr(self, "session") or not self.session
            else self.session.dict(),
            "client": None
            if not hasattr(self, "client") or not self.client
            else self.client.dict(),
            "member": None
            if not hasattr(self, "member") or not self.member
            else self.member.dict(),
            "ip_addr": self.ip_addr,
            "user_agent": self.user_agent,
        }


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(
            o,
            (
                PositiveInt,
                PositiveFloat,
            ),
        ):
            return int(o)
        if isinstance(
            o,
            (
                AnyHttpUrl,
                IPv4Address,
                IPv6Address,
                EmailStr,
            ),
        ):
            return str(o)
        if hasattr(o, "dict"):
            return json.dumps(o.dict(), cls=JSONEncoder)

        return super().default(o)


async def get_contents(
    request: Request,
    raw_body: Union[str, None] = None,
) -> Union[str, None]:
    if not raw_body and hasattr(request, 'form'):
        if form := await request.form():
            if upload := form.get("files"):
                raw_body = upload.file.read().decode()
                upload.file.seek(0)
    if not raw_body and hasattr(request, "_body"):
        raw_body = request._body.decode("utf8")  # pylint: disable=protected-access
    if not raw_body:
        if event := request.scope.get("aws.event", {}):
            raw_body = b64decode(event.get("body", '')).decode() if event.get("isBase64Encoded") else event.get("body")

    return raw_body

async def auth_required(
    request: Request,
    authorization: str = Header(
        alias="Authorization", title="HMAC-SHA512 Signed Request"
    ),
    x_trivialscan_account: Union[str, None] = Header(
        default=None, alias="X-Trivialscan-Account", title="CLI Client Token hint"
    ),
):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERR_MISSING_AUTHORIZATION,
            headers={"WWW-Authenticate": AUTHZ_REALM},
        )
    event = request.scope.get("aws.event", {})
    raw_body = await get_contents(request)
    authz = Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
        account_name=x_trivialscan_account,
        raw_body=raw_body
    )
    if not authz.is_authorized:
        logger.error(ERR_INVALID_AUTHORIZATION)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERR_INVALID_AUTHORIZATION,
            headers={"WWW-Authenticate": AUTHZ_REALM},
        )
    return authz
