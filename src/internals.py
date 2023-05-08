# pylint: disable=line-too-long
import contextlib
import re
import json
import logging
import hmac
import hashlib
import threading
from inspect import getframeinfo, stack
from base64 import b64encode, b64decode
from time import sleep, time
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlparse, unquote
from os import getenv
from typing import Union, Any
from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
)
from uuid import UUID

import boto3
import validators
import requests
import jwt
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    base64url_to_bytes,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    UserVerificationRequirement,
    AuthenticationCredential,
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    PublicKeyCredentialRequestOptions,
)
from lumigo_tracer import add_execution_tag, error as lumigo_error
from user_agents.parsers import UserAgent, parse as ua_parser
from starlette.requests import Request
from fastapi import Header, HTTPException, status
from pydantic import (
    HttpUrl,
    AnyHttpUrl,
    PositiveInt,
    PositiveFloat,
)


CACHE_DIR = getenv("CACHE_DIR", default="/tmp")
JITTER_SECONDS = int(getenv("JITTER_SECONDS", default="30"))
APP_ENV = getenv("APP_ENV", default="Dev")
APP_NAME = getenv("APP_NAME", default="trivialscan-api")
DEFAULT_LOG_LEVEL = "WARNING"
LOG_LEVEL = getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL)
NAMESPACE = UUID("bc6e2cd5-1f59-487f-b05b-49946bd078b2")
GENERIC_SECURITY_MESSAGE = "Your malformed request has been logged for investigation"
APEX_DOMAIN = "trivialsec.com"
ORIGIN_HOST = f"dev.{APEX_DOMAIN}" if APP_ENV == "Dev" else f"www.{APEX_DOMAIN}"
DASHBOARD_URL = f"https://{ORIGIN_HOST}"
ALLOWED_ORIGINS = (
    [
        DASHBOARD_URL,
        "http://localhost:5173",
        "https://localhost:5173",
        "http://jager:5173",
        "https://jager.tail55052.ts.net:5173",
    ]
    if APP_ENV == "Dev"
    else [DASHBOARD_URL]
)
AUTHZ_REALM = 'JWT realm="trivialscan"'
ERR_INVALID_AUTHORIZATION = "Invalid Bearer Token"
ERR_MISSING_AUTHORIZATION = "Missing Bearer Token"

logger = logging.getLogger()
boto3.set_stream_logger("boto3", getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))  # type: ignore
logger.setLevel(getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))


def always_log(message: Union[str, Exception]):
    caller = getframeinfo(stack()[1][0])
    alert_type = (
        message.__class__.__name__
        if hasattr(message, "__class__") and message is not str
        else "UnhandledError"
    )
    filename = (
        caller.filename.replace(getenv("LAMBDA_TASK_ROOT", ""), "")
        if getenv("AWS_EXECUTION_ENV") is not None and getenv("LAMBDA_TASK_ROOT")
        else caller.filename.split("/src/")[1]
    )
    lumigo_error(
        f"{filename}:{caller.function}:{caller.lineno} - {message}",
        alert_type,
        extra={
            "LOG_LEVEL": LOG_LEVEL,
            "NAMESPACE": NAMESPACE.hex,
        },
    )


class DenyAuthorisation(Exception):
    """
    Denied Authorisation Attempt
    """


class DelayRetryHandler(Exception):
    """
    Delay the retry handler and provide a useful message when retries are exceeded
    """

    def __init__(self, **kwargs):
        sleep(kwargs.get("delay", 3) or 3)
        Exception.__init__(self, kwargs.get("msg", "Max retries exceeded"))


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
        return (
            self.parsed_header.get("scheme") if hasattr(self, "parsed_header") else None
        )

    @property
    def id(self) -> Union[str, None]:  # pylint: disable=invalid-name
        return self.parsed_header.get("id") if hasattr(self, "parsed_header") else None

    @property
    def ts(self) -> Union[int, None]:  # pylint: disable=invalid-name
        return (
            int(self.parsed_header.get("ts"))  # type: ignore
            if hasattr(self, "parsed_header")
            else None
        )

    @property
    def mac(self) -> Union[str, None]:
        return self.parsed_header.get("mac") if hasattr(self, "parsed_header") else None

    @property
    def canonical_string(self) -> str:
        parsed_url = urlparse(self.request_url)
        port = 443 if parsed_url.port is None else parsed_url.port
        bits = [self.request_method.upper()]
        bits.extend(
            (parsed_url.hostname.lower(), str(port), unquote(parsed_url.path), str(self.ts))  # type: ignore
        )
        if self.contents:
            bits.append(b64encode(self.contents.encode("utf8")).decode("utf8"))
        return "\n".join(bits)

    def __init__(
        self,
        authorization_header: str,
        request_url: str,
        method: str = "GET",
        raw_body: Union[str, None] = None,
        algorithm: Union[str, None] = None,
        not_before_seconds: int = JITTER_SECONDS,
        expire_after_seconds: int = JITTER_SECONDS,
    ):
        self.server_mac: str = ""
        self.authorization_header: str = authorization_header
        self.contents = raw_body
        self.request_method: str = method
        self.request_url: str = request_url
        self.algorithm: str = (
            algorithm
            if self.supported_algorithms.get(algorithm)  # type: ignore
            else self.default_algorithm
        )
        self._expire_after_seconds: int = expire_after_seconds
        self._not_before_seconds: int = not_before_seconds
        self.parsed_header: dict[str, str] = HMAC.parse_authorization_header(
            authorization_header
        )

    @staticmethod
    def parse_authorization_header(authorization_header: str) -> dict[str, str]:
        auth_param_re = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
        auth_param_re = re.compile(r"^\s*" + auth_param_re + r"\s*$")
        unesc_quote_re = re.compile(r'(^")|([^\\]")')
        scheme, pairs_str = authorization_header.split(None, 1)
        parsed_header = {"scheme": scheme}
        pairs = []
        if pairs_str:
            for pair in pairs_str.split(","):
                if not pairs or auth_param_re.match(pairs[-1]):
                    pairs.append(pair)
                else:
                    pairs[-1] = f"{pairs[-1]},{pair}"
            if not auth_param_re.match(pairs[-1]):
                raise ValueError("Malformed auth parameters")
        for pair in pairs:
            (key, value) = pair.strip().split("=", 1)
            # For quoted strings, remove quotes and backslash-escapes.
            if value.startswith('"'):
                value = value[1:-1]
                if unesc_quote_re.search(value):
                    raise ValueError("Unescaped quote in quoted-string")
                value = re.compile(r"\\.").sub(lambda m: m.group(0)[1], value)
            parsed_header[key] = value
        return parsed_header

    def is_valid_scheme(self) -> bool:
        return self.authorization_header.startswith("HMAC")

    def is_valid_timestamp(self) -> bool:
        # not_before prevents replay attacks
        compare_date = datetime.fromtimestamp(float(self.ts), tz=timezone.utc)  # type: ignore
        now = datetime.now(tz=timezone.utc)
        not_before = now - timedelta(seconds=self._not_before_seconds)
        expire_after = now + timedelta(seconds=self._expire_after_seconds)
        # expire_after can assist with support for offline/airplane mode
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
        if not self.supported_algorithms.get(self.algorithm):
            logger.error(f"algorithm {self.algorithm} is not supported")
            return False

        digestmod = self.supported_algorithms.get(
            self.algorithm, self.default_algorithm
        )
        # Sign HMAC using server-side secret (not provided by client)
        digest = hmac.new(
            secret_key.encode("utf8"), self.canonical_string.encode("utf8"), digestmod
        ).hexdigest()
        self.server_mac = digest
        # Compare server-side HMAC with client provided HMAC
        if invalid := not hmac.compare_digest(digest, self.mac):  # type: ignore
            logger.error(
                f"server_mac {self.server_mac} canonical_string {self.canonical_string}"
            )
        return not invalid


class TokenTypes(str, Enum):
    SIGNED_SESSION = "signed_session"
    BEARER_TOKEN = "bearer_token"
    CLIENT_TOKEN = "client_token"


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
    UPDATE_FINDING_STATUS = "/finding/status"
    UPDATE_FINDING_DEFERRED_TO = "/finding/deferred"
    DASHBOARD_QUOTAS = "/dashboard/quotas"
    SEARCH_HOST = "/search/host/"
    SEARCH_IP = "/search/ip/"
    SEARCH_ANY = "/search/any/"
    CERTIFICATE_SHA1 = "/certificate/"
    SCANNER_CONFIG = "/scanner/config"
    ENABLE_MONITOR = "/scanner/monitor/"
    DEACTIVATE_MONITOR = "/scanner/deactivate/"
    SCANNER_QUEUE = "/scanner/queue/"
    VALIDATE = "/validate"
    ME = "/me"
    STRIPE_CUSTOMER_PORTAL = "/stripe/create-customer-portal-session"
    UPDATE_BILLING_EMAIL = "/billing/email"
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
    CLIENT_DEACTIVATE = "/deactivated/"
    SUPPORT = "/support"
    NOTIFICATION_DISABLE = "/notification/disable/"
    NOTIFICATION_ENABLE = "/notification/enable/"
    WEBHOOK_ENABLE = "/webhook/enable"
    WEBHOOK_ENDPOINT = "/webhook/endpoint"
    WEBHOOK_DELETE = "/webhook"
    DELETE_ACCOUNT = "/account"
    FIDO_REGISTER = "/webauthn/register"
    FIDO_ENROLL = "/webauthn/enroll"
    FIDO_DELETE = "/webauthn/delete"
    FIDO_LOGIN = "/webauthn/login"
    EWS_ALERTS = "/early-warning-service/alerts"


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
        AuthorizationRoute.UPDATE_FINDING_STATUS,
        AuthorizationRoute.UPDATE_FINDING_DEFERRED_TO,
        AuthorizationRoute.SEARCH_HOST,
        AuthorizationRoute.SEARCH_IP,
        AuthorizationRoute.SEARCH_ANY,
        AuthorizationRoute.CERTIFICATE_SHA1,
        AuthorizationRoute.SCANNER_CONFIG,
        AuthorizationRoute.ENABLE_MONITOR,
        AuthorizationRoute.DEACTIVATE_MONITOR,
        AuthorizationRoute.SCANNER_QUEUE,
        AuthorizationRoute.ME,
        AuthorizationRoute.STRIPE_CUSTOMER_PORTAL,
        AuthorizationRoute.UPDATE_BILLING_EMAIL,
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
        AuthorizationRoute.NOTIFICATION_DISABLE,
        AuthorizationRoute.NOTIFICATION_ENABLE,
        AuthorizationRoute.WEBHOOK_ENABLE,
        AuthorizationRoute.WEBHOOK_DELETE,
        AuthorizationRoute.WEBHOOK_ENDPOINT,
        AuthorizationRoute.DELETE_ACCOUNT,
        AuthorizationRoute.FIDO_REGISTER,
        AuthorizationRoute.FIDO_ENROLL,
        AuthorizationRoute.FIDO_DELETE,
        AuthorizationRoute.FIDO_LOGIN,
        AuthorizationRoute.EWS_ALERTS,
    ]

    def __init__(
        self,
        request: Request,
        user_agent: Union[str, None] = None,
        ip_addr: Union[IPv4Address, IPv6Address, None] = None,
        account_name: Union[str, None] = None,
        algorithm: Union[str, None] = None,
        not_before_seconds: int = JITTER_SECONDS,
        expire_after_seconds: int = JITTER_SECONDS,
        raw_body: Union[str, None] = None,
    ):
        import models  # pylint: disable=import-outside-toplevel

        self.hmac: HMAC
        self.token_type: TokenTypes
        self.route: AuthorizationRoute
        self.is_valid: bool = False
        self.account: models.MemberAccount
        self.session: models.MemberSession
        self.client: models.Client
        self.member: models.MemberProfile
        self.ip_addr: Union[IPv4Address, IPv6Address, None] = ip_addr
        self.user_agent: UserAgent = ua_parser(
            user_agent or request.headers.get("User-Agent", "")
        )
        if postman_token := request.headers.get("Postman-Token"):
            trace_tag({"postman_token": postman_token})  # type: ignore
            logger.info(f"Postman-Token: {postman_token}")
        if is_trivial_scanner := self.user_agent.ua_string.startswith(
            "Trivial Scanner"
        ):
            trace_tag({"is_trivial_scanner": str(is_trivial_scanner)})  # type: ignore
        _check_ip: Any = request.headers.get(
            "X-Forwarded-For", request.headers.get("X-Real-IP")
        )
        if _check_ip and validators.ipv4(_check_ip) is True:
            self.ip_addr = IPv4Address(_check_ip)
        if _check_ip and validators.ipv6(_check_ip) is True:
            self.ip_addr = IPv6Address(_check_ip)
        if not self.ip_addr:
            always_log(
                "IP Address not determined, potential risk if not deliberate or is running locally"
            )
        trace_tag({"ip_addr": str(self.ip_addr)})  # type: ignore
        if not self.user_agent:
            raise DenyAuthorisation("Missing User-Agent")

        trace_tag({"is_bot": str(self.user_agent.is_bot)})  # type: ignore
        if self.user_agent.is_bot:
            raise DenyAuthorisation("Bot User-Agent")

        trace_tag({"is_mobile": str(self.user_agent.is_mobile)})  # type: ignore
        trace_tag({"is_tablet": str(self.user_agent.is_tablet)})  # type: ignore
        trace_tag({"is_pc": str(self.user_agent.is_pc)})  # type: ignore
        if (
            not any(
                [
                    self.user_agent.is_mobile,
                    self.user_agent.is_tablet,
                    self.user_agent.is_pc,
                ]
            )
            and not postman_token
            and not is_trivial_scanner
        ):
            raise DenyAuthorisation(f"Unrecognisable User-Agent {self.user_agent}")

        authorization_header = request.headers.get("Authorization", "")
        if authorization_header.startswith("HMAC "):
            self.hmac = HMAC(
                authorization_header=authorization_header,
                request_url=str(request.url),
                method=request.method.upper(),
                raw_body=raw_body,
                algorithm=algorithm,
                not_before_seconds=not_before_seconds,
                expire_after_seconds=expire_after_seconds,
            )
            logger.info(f"Signature validation for id {self.hmac.id}")
            if validators.email(self.hmac.id) is True:  # type: ignore
                logger.critical(
                    DeprecationWarning(
                        f"Deprecated use of symmetric signed session {self.hmac.id}"
                    )
                )
                self.member = models.MemberProfile(email=self.hmac.id)
                if not self.member.load():
                    raise DenyAuthorisation(f"Missing MemberProfile {self.hmac.id}")

                self.account = models.MemberAccount(name=self.member.account_name)  # type: ignore
                if not self.account.load():
                    raise DenyAuthorisation(f"Missing MemberAccount {self.hmac.id}")

                logger.info(
                    f"Session inputs; {self.member.email} | {self.user_agent.get_browser()} | {self.user_agent.get_os()} | {self.user_agent.get_device()}"
                )
                session_token = hashlib.sha224(
                    bytes(
                        f"{self.member.email}{self.user_agent.get_browser()}{self.user_agent.get_os()}{self.user_agent.get_device()}",
                        "ascii",
                    )
                ).hexdigest()
                logger.info(
                    f"AUTH_FLOW Session HMAC-based Authorization: session_token {session_token}"
                )
                self.session = models.MemberSession(member_email=self.member.email, session_token=session_token)  # type: ignore
                if not self.session.load():
                    raise DenyAuthorisation(f"Missing MemberSession {self.hmac.id}")

                self.is_valid = self.hmac.validate(self.session.access_token)  # type: ignore
                self.token_type = TokenTypes.SIGNED_SESSION

            else:
                logger.info(
                    f"AUTH_FLOW Checking client Token HMAC-based Authorization: client_name {self.hmac.id}"
                )
                self.account = models.MemberAccount(name=account_name)  # type: ignore
                if not self.account.load():
                    raise DenyAuthorisation(f"Missing MemberAccount {self.hmac.id}")

                self.client = models.Client(account_name=self.account.name, name=self.hmac.id)  # type: ignore
                if not self.client.load():
                    raise DenyAuthorisation(f"Missing Client {self.hmac.id}")

                if not isinstance(self.account, models.MemberAccount):
                    raise DenyAuthorisation(f"Missing MemberAccount {self.hmac.id}")

                if self.client.active:
                    self.is_valid = self.hmac.validate(self.client.access_token)  # type: ignore
                    self.token_type = TokenTypes.CLIENT_TOKEN

        if self.is_valid:
            return
        if authorization_header and authorization_header.startswith("Bearer "):
            bearer_token = authorization_header[7:]
        else:
            cookie_name = (
                f"__Host-{ORIGIN_HOST}-jwt-bearer"
                if APP_ENV == "Prod"
                else "jwt-bearer"
            )
            bearer_token = request.cookies.get(cookie_name)

        if bearer_token:
            unverified_header = jwt.get_unverified_header(bearer_token)
            jwt_kid = unverified_header.get("kid")
            logger.info(f"JWT validation for kid {jwt_kid}")
            self.session = models.MemberSession(session_token=jwt_kid)  # type: ignore
            if not self.session.load():
                raise DenyAuthorisation(f"Missing MemberSession {jwt_kid}")

            try:
                decoded = jwt.decode(
                    jwt=bearer_token,
                    key=self.session.access_token,  # type: ignore
                    options={"require": ["iat", "nbf", "exp", "aud", "iss", "sub"]},
                    leeway=JITTER_SECONDS,
                    audience="urn:trivialsec:authz:api:jwt-bearer",
                    issuer=DASHBOARD_URL,
                    algorithms=["HS256"],
                )
            except jwt.InvalidSignatureError as err:
                raise DenyAuthorisation(f"Bearer token {jwt_kid}") from err

            except jwt.ExpiredSignatureError as err:
                self.session.delete()
                raise DenyAuthorisation(f"Bearer token {jwt_kid}") from err

            self.member = models.MemberProfile(email=self.session.member_email)  # type: ignore
            if not self.member.load():
                raise DenyAuthorisation(
                    f"Missing MemberProfile {self.session.member_email}"
                )

            expected_session_token = hashlib.sha224(
                bytes(
                    f"{self.member.email}{self.user_agent.get_browser()}{self.user_agent.get_os()}{self.user_agent.get_device()}",
                    "ascii",
                )
            ).hexdigest()
            if self.session.session_token != expected_session_token:
                raise DenyAuthorisation(
                    f"Expected Session Token: session_token {self.session.session_token} != {expected_session_token}"
                )

            self.account = models.MemberAccount(name=self.member.account_name)  # type: ignore
            if not self.account.load():
                raise DenyAuthorisation(
                    f"Missing MemberAccount {self.member.account_name}"
                )

            self.is_valid = (
                decoded.get("acc") == self.member.account_name
            )  # the only custom claim we signed
            self.token_type = TokenTypes.BEARER_TOKEN

        trace_tags = {
            "account_name": self.account.name,
            "is_valid": str(self.is_valid),
        }
        if isinstance(self.token_type, TokenTypes):
            trace_tags["token_type"] = self.token_type.value
        if isinstance(self.member, models.MemberSession) and self.member.email:
            trace_tags["member_email"] = self.member.email
        if (
            isinstance(self.session, models.MemberSession)
            and self.session.session_token
        ):
            trace_tags["session_token"] = self.session.session_token
        trace_tag(trace_tags)
        if not self.is_valid:
            raise DenyAuthorisation("Unhandled validation")

        if isinstance(self.session, models.MemberSession):
            self.session.timestamp = round(time() * 1000)
            if not self.session.save():
                logger.warning("Silently broken MemberSession")

    def authorized(self, request_url_path: str) -> bool:
        """
        Based on the authentication type, what endpoints should be allowed
        """
        if self.token_type == TokenTypes.CLIENT_TOKEN:
            for route in self.client_allow:
                if request_url_path.startswith(route.value):
                    self.route = route
                    break
        if self.token_type in [TokenTypes.SIGNED_SESSION, TokenTypes.BEARER_TOKEN]:
            for route in self.session_allow:
                if request_url_path.startswith(route.value):
                    self.route = route
                    break

        return hasattr(self, "route") and isinstance(self.route, AuthorizationRoute)

    def dict(self):
        return {
            "token_type": self.token_type,
            "authorized_route": self.route,
            "is_valid": self.is_valid,
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
            "user_agent": self.user_agent.ua_string,
        }


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, date):
            return o.isoformat()
        if isinstance(o, datetime):
            return o.replace(microsecond=0).isoformat()
        if isinstance(o, int) and o > 10 ^ 38 - 1:
            return str(o)
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
                HttpUrl,
                AnyHttpUrl,
                IPv4Address,
                IPv6Address,
                IPv4Network,
                IPv6Network,
                UUID,
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
    if not raw_body and hasattr(request, "form"):
        if form := await request.form():
            if upload := form.get("files"):
                raw_body = upload.file.read().decode()
                upload.file.seek(0)
    if not raw_body and hasattr(request, "_body"):
        raw_body = request._body.decode("utf8")  # pylint: disable=protected-access
    if not raw_body:
        if event := request.scope.get("aws.event", {}):
            raw_body = (
                b64decode(event.get("body", "")).decode()
                if event.get("isBase64Encoded")
                else event.get("body")
            )

    return raw_body


async def auth_required(
    request: Request,
    authorization: str = Header(
        alias="Authorization", title="Contained JWT", default=""
    ),
    x_trivialscan_account: Union[str, None] = Header(
        default=None, alias="X-Trivialscan-Account", title="CLI Client Token hint"
    ),
):
    cookie_name = (
        f"__Host-{ORIGIN_HOST}-jwt-bearer" if APP_ENV == "Prod" else "jwt-bearer"
    )
    if not authorization and not request.cookies.get(cookie_name):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERR_MISSING_AUTHORIZATION,
            headers={"WWW-Authenticate": AUTHZ_REALM},
        )
    event = request.scope.get("aws.event", {})
    raw_body = await get_contents(request)
    try:
        authz = Authorization(
            request=request,
            user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
            ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
            account_name=x_trivialscan_account,
            raw_body=raw_body,
        )
    except DenyAuthorisation as err:
        always_log(err)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERR_INVALID_AUTHORIZATION,
            headers={"WWW-Authenticate": AUTHZ_REALM},
        ) from err

    if not authz.is_valid or not authz.authorized(request.url.path):
        logger.error(ERR_INVALID_AUTHORIZATION)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERR_INVALID_AUTHORIZATION,
            headers={"WWW-Authenticate": AUTHZ_REALM},
        )
    return authz


def _request_task(url: str, body: dict, headers: dict):
    with contextlib.suppress(requests.exceptions.ConnectionError):
        requests.post(
            url,
            data=json.dumps(body, cls=JSONEncoder),
            headers=headers,
            timeout=(15, 30),
        )


def post_beacon(url: AnyHttpUrl, body: dict, headers: dict = None):  # type: ignore
    """
    A beacon is a fire and forget HTTP POST, the response is not
    needed so we do not even wait for one, so there is no
    response to discard because it was never received
    """
    if headers is None:
        headers = {"Content-Type": "application/json"}
    threading.Thread(target=_request_task, args=(url, body, headers)).start()


def trace_tag(data: dict[str, str]):
    if not isinstance(data, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in data.items()
    ):
        raise ValueError
    for key, value in data.items():
        if 1 > len(key) > 50:
            logger.warning(
                f"Trace key must be less than 50 for: {key} See: https://docs.lumigo.io/docs/execution-tags#execution-tags-naming-limits-and-requirements"
            )
        if 1 > len(value) > 70:
            logger.warning(
                f"Trace value must be less than 70 for: {value} See: https://docs.lumigo.io/docs/execution-tags#execution-tags-naming-limits-and-requirements"
            )
    if getenv("AWS_EXECUTION_ENV") is None or APP_ENV != "Prod":
        return
    for key, value in data.items():
        add_execution_tag(key[:50], value=value[:70])


class fido:
    """
    FIDO authentication support.
    """

    @staticmethod
    def register(user_email: str, record_id: UUID):
        """Start FIDO auth registration process

        Arguments:
            userID -- User's ID

            userName -- The User's username

        Returns:
            registration options and registration challenge
        """
        registration_options = generate_registration_options(
            rp_id=ORIGIN_HOST if getenv("AWS_EXECUTION_ENV") else "localhost",
            rp_name="Trivial Security",
            user_id=user_email,
            user_name=str(record_id),
            user_display_name=user_email,
            attestation=AttestationConveyancePreference.DIRECT,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.DISCOURAGED,
            ),
        )
        return registration_options

    @staticmethod
    def register_verification(
        credentials: str, challenge: bytes, require_user_verification: bool = True
    ):
        """Complete registration

        Arguments:
            credentials -- The user's fido credentials, recieved from the browser

            challenge -- The expected challenge

        Raises:
            AuthError: registration failure

        Returns:
            credential id and credential public key
        """

        registration_creds = RegistrationCredential.parse_raw(credentials)
        registration_verification = verify_registration_response(
            credential=registration_creds,
            expected_challenge=challenge,
            expected_origin=DASHBOARD_URL
            if getenv("AWS_EXECUTION_ENV")
            else "http://localhost:5173",
            expected_rp_id=ORIGIN_HOST if getenv("AWS_EXECUTION_ENV") else "localhost",
            require_user_verification=require_user_verification,
        )
        if registration_verification.credential_id == base64url_to_bytes(
            registration_creds.id
        ):
            return registration_verification

    @staticmethod
    def authenticate(
        allow_credentials: list[PublicKeyCredentialDescriptor],
    ) -> PublicKeyCredentialRequestOptions:
        """Begin user authentication

        Arguments:
            cred_id -- The user's credential's id

        Returns:
            verification options, expected challange
        """
        return generate_authentication_options(
            rp_id=ORIGIN_HOST if getenv("AWS_EXECUTION_ENV") else "localhost",
            timeout=60000,
            user_verification=UserVerificationRequirement.DISCOURAGED,
            allow_credentials=allow_credentials,
        )

    @staticmethod
    def authenticate_verify(challenge: bytes, public_key: bytes, credential_json: str):
        """Complete Authentication

        Arguments:
            challenge -- The expected challange from authenticate

            credential_public_key -- The user's public key

            credentials -- The credentials provided by the user

        Returns:
            True on success, False otherwise
        """
        authentication_verification = verify_authentication_response(
            credential=AuthenticationCredential.parse_raw(credential_json),
            expected_challenge=challenge,
            expected_origin=DASHBOARD_URL
            if getenv("AWS_EXECUTION_ENV")
            else "http://localhost:5173",
            expected_rp_id=ORIGIN_HOST if getenv("AWS_EXECUTION_ENV") else "localhost",
            credential_public_key=public_key,
            credential_current_sign_count=0,
        )
        success = authentication_verification.new_sign_count > 0
        return success
