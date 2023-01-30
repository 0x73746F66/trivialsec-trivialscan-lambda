# pylint: disable=no-self-argument, arguments-differ
import json
import hashlib
from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import Union, Any, Optional
from datetime import datetime

import validators
from pydantic import (
    BaseModel,
    Field,
    AnyHttpUrl,
    validator,
    conint,
    PositiveInt,
    PositiveFloat,
    IPvAnyAddress,
    EmailStr,
)
from pydantic.error_wrappers import ValidationError

import internals
import services.aws
import services.stripe
import models.stripe


class DAL(metaclass=ABCMeta):
    @abstractmethod
    def exists(self, **kwargs) -> bool:
        raise NotImplementedError

    @abstractmethod
    def load(self, **kwargs) -> Union[BaseModel, None]:
        raise NotImplementedError

    @abstractmethod
    def save(self, **kwargs) -> bool:
        raise NotImplementedError

    @abstractmethod
    def delete(self, **kwargs) -> bool:
        raise NotImplementedError


class Message(BaseModel):
    message: str


class OutputType(str, Enum):
    JSON = "json"
    CONSOLE = "console"


class OutputWhen(str, Enum):
    FINAL = "final"
    PER_HOST = "per_host"
    PER_CERTIFICATE = "per_certificate"


class CertificateType(str, Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    LEAF = "leaf"
    CLIENT = "client"


class ValidationLevel(str, Enum):
    DOMAIN_VALIDATION = "Domain Validation (DV)"
    ORGANIZATION_VALIDATION = "Organization Validation (OV)"
    EXTENDED_VALIDATION = "Extended Validation (EV)"


class PublicKeyType(str, Enum):
    RSA = "RSA"
    DSA = "DSA"
    EC = "EC"
    DH = "DH"


class ReportType(str, Enum):
    HOST = "host"
    CERTIFICATE = "certificate"
    REPORT = "report"
    EVALUATIONS = "evaluations"


class AccountRegistration(BaseModel):
    name: str
    display: Optional[str]
    primary_email: Optional[EmailStr]


class Billing(BaseModel):
    product_name: str
    is_trial: bool = Field(default=False)
    description: Optional[str]
    display_amount: str = Field(default="free")
    display_period: Optional[str]
    next_due: Optional[int]
    has_invoice: bool = Field(default=False)


class AccountNotifications(BaseModel):
    scan_completed: Optional[bool] = Field(default=False)
    monitor_completed: Optional[bool] = Field(default=False)
    self_hosted_uploads: Optional[bool] = Field(default=False)
    early_warning: Optional[bool] = Field(default=False)
    new_findings_certificates: Optional[bool] = Field(default=False)
    new_findings_domains: Optional[bool] = Field(default=False)
    include_warning: Optional[bool] = Field(default=False)
    include_info: Optional[bool] = Field(default=False)


class Webhooks(BaseModel):
    endpoint: AnyHttpUrl = Field(default=None)
    signing_secret: Optional[str]
    hosted_monitoring: Optional[bool] = Field(default=False)
    hosted_scanner: Optional[bool] = Field(default=False)
    self_hosted_uploads: Optional[bool] = Field(default=False)
    early_warning_email: Optional[bool] = Field(default=False)
    early_warning_domain: Optional[bool] = Field(default=False)
    early_warning_ip: Optional[bool] = Field(default=False)
    new_findings_certificates: Optional[bool] = Field(default=False)
    new_findings_domains: Optional[bool] = Field(default=False)
    include_warning: Optional[bool] = Field(default=False)
    include_info: Optional[bool] = Field(default=False)
    client_status: Optional[bool] = Field(default=False)
    client_activity: Optional[bool] = Field(default=False)
    scanner_configurations: Optional[bool] = Field(default=False)
    report_created: Optional[bool] = Field(default=False)
    report_deleted: Optional[bool] = Field(default=False)
    account_activity: Optional[bool] = Field(default=False)
    member_activity: Optional[bool] = Field(default=False)


class WebhooksRedacted(Webhooks):
    class Config:
        validate_assignment = True

    @validator("signing_secret")
    def set_signing_secret(cls, _):
        return None


class Webauthn(BaseModel):
    id: str
    public_key: str
    challenge: str
    alias: str
    created_at: datetime


class Totp(BaseModel):
    assertion_response_raw_id: str
    public_key: str
    challenge: str
    alias: Optional[str] = Field(default="")
    active: Optional[bool] = Field(default=True)
    created_at: datetime


class MfaSetting(str, Enum):
    ENROLL = "enroll"
    OPT_OUT = "opt_out"
    TOTP = "totp"
    WEBAUTHN = "webauthn"


class MemberAccount(AccountRegistration, DAL):
    billing_email: Optional[EmailStr]
    api_key: Optional[str]
    ip_addr: Optional[IPvAnyAddress]
    user_agent: Optional[str]
    timestamp: Optional[int]
    # mfa: Optional[MfaSetting] = Field(default=MfaSetting.ENROLL)
    billing: Union[Billing, None] = Field(default=None)
    notifications: Optional[AccountNotifications] = Field(
        default=AccountNotifications()
    )
    webhooks: Optional[list[Webhooks]] = Field(default=[])

    def exists(self, account_name: Union[str, None] = None) -> bool:
        return self.load(account_name) is not None

    def load(
        self, account_name: Union[str, None] = None
    ) -> Union["MemberAccount", None]:
        if account_name:
            self.name = account_name
        if not self.name:
            return
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing account object: {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing account data for object: {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD,
        )

    def delete(self) -> Union[bool, None]:
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        return services.aws.delete_s3(object_key)

    def load_billing(self):
        if sub := models.stripe.SubscriptionAddon().load(self.name):  # type: ignore
            return self._billing(sub)
        elif sub := models.stripe.SubscriptionPro().load(self.name):  # type: ignore
            return self._billing(sub)  # NOSONAR
        elif sub := models.stripe.SubscriptionEnterprise().load(self.name):  # type: ignore
            return self._billing(sub)  # NOSONAR
        elif sub := models.stripe.SubscriptionUnlimited().load(self.name):  # type: ignore
            return self._billing(sub)  # NOSONAR
        self.billing = Billing(
            product_name=services.stripe.PRODUCTS.get(services.stripe.Product.COMMUNITY_EDITION).get("name")  # type: ignore
        )

    def _billing(self, sub: models.stripe.SubscriptionBase):
        self.billing = Billing(
            product_name=services.stripe.PRODUCTS.get(services.stripe.PRODUCT_MAP.get(sub.plan.product), {}).get("name")  # type: ignore
        )
        self.billing.is_trial = sub.status == models.stripe.SubscriptionStatus.TRIALING
        self.billing.has_invoice = isinstance(
            sub.latest_invoice, str
        ) and sub.latest_invoice.startswith("in_")
        currency = sub.subscription_item.price.currency  # type: ignore
        amount = sub.subscription_item.price.unit_amount_decimal  # type: ignore
        self.billing.display_amount = f"{currency.upper()} ${amount}"
        self.billing.display_period = sub.subscription_item.price.recurring.interval.capitalize()  # type: ignore
        if not sub.cancel_at_period_end:
            # JavaScript compatibility
            self.billing.next_due = sub.current_period_end * 1000  # type: ignore
        if (
            sub.default_payment_method
            and sub.collection_method
            == models.stripe.SubscriptionCollectionMethod.CHARGE_AUTOMATICALLY
        ):
            self.billing.description = "Stripe Payments"
        elif (
            sub.collection_method
            == models.stripe.SubscriptionCollectionMethod.SEND_INVOICE
        ):
            self.billing.description = "Send Invoice"

    def update_members(
        self,
    ) -> bool:  # TODO this should be a Lambda trigger on suffix registration.json
        prefix_key = f"{internals.APP_ENV}/accounts/{self.name}/"
        members: list["MemberProfile"] = []
        member_matches = services.aws.list_s3(prefix_key=f"{prefix_key}members/")
        results: list[bool] = []
        for object_path in member_matches:
            if not object_path.endswith("profile.json"):
                continue
            raw = services.aws.get_s3(path_key=object_path)
            if raw:
                try:
                    member = MemberProfile(**json.loads(raw))
                except ValidationError:
                    internals.logger.warning(f"Bad data for MemberProfile\n{raw}")
                    results.append(False)
                    continue
                member.account = self
                results.append(member.save())
                members.append(member)
        for member in members:
            session_matches = services.aws.list_s3(
                prefix_key=f"{prefix_key}members/{member.email}/sessions/"
            )
            for object_path in session_matches:
                raw = services.aws.get_s3(path_key=object_path)
                if raw:
                    session = MemberSession(**json.loads(raw))
                    session.member = member
                    results.append(session.save())
        return all(results)


class MemberAccountRedacted(MemberAccount):
    class Config:
        validate_assignment = True

    @validator("api_key")
    def set_api_key(cls, _):
        return None

    @validator("webhooks")
    def set_webhooks(cls, webhooks):
        return [WebhooksRedacted(**webhook.dict()) for webhook in webhooks]


class MemberProfile(BaseModel):
    account: Optional[MemberAccount]
    email: EmailStr
    email_md5: Optional[str]
    confirmed: bool = Field(default=False)
    confirmation_token: Optional[str]
    timestamp: Optional[int]
    current: Optional[bool] = Field(default=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.email_md5 = hashlib.md5(self.email.encode()).hexdigest()

    def exists(self, member_email: Union[EmailStr, None] = None) -> bool:
        return self.load(member_email) is not None

    def load(
        self, member_email: Union[EmailStr, None] = None
    ) -> Union["MemberProfile", None]:
        if member_email:
            self.email = member_email
        if validators.email(self.email) is False:  # type: ignore
            internals.logger.warning(f"Invalid email: {self.email}")
            return
        suffix = f"/members/{self.email}/profile.json"
        prefix_matches = services.aws.list_s3(
            prefix_key=f"{internals.APP_ENV}/accounts"
        )
        matches = [k for k in prefix_matches if k.endswith(suffix)]
        if len(matches) > 1:
            internals.logger.critical(
                "MemberProfile.load found too many matches, this is a data taint, likely manual data edits"
            )
            internals.logger.info(matches)
        if len(matches) == 0:
            internals.logger.warning(f"Missing member for: {member_email}")
            return
        raw = services.aws.get_s3(path_key=matches[0])
        if not raw:
            internals.logger.warning(f"Missing member for: {member_email}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing member data for: {member_email}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/members/{self.email}/profile.json"  # type: ignore pylint: disable=no-member
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD,
        )

    def delete(self) -> bool:
        prefix_key = f"{internals.APP_ENV}/accounts/{self.account.name}/members/{self.email}/"  # type: ignore pylint: disable=no-member
        prefix_matches = services.aws.list_s3(prefix_key=prefix_key)
        if len(prefix_matches) == 0:
            return True
        results: list[bool] = []
        for object_key in prefix_matches:
            results.append(services.aws.delete_s3(object_key))
        return all(results)


class MemberProfileRedacted(MemberProfile):
    class Config:
        validate_assignment = True

    @validator("account")
    def set_account(cls, account):
        return (
            None
            if not isinstance(account, MemberAccount)
            else MemberAccountRedacted(**account.dict())
        )

    @validator("confirmation_token")
    def set_confirmation_token(cls, _):
        return None


class ClientInfo(BaseModel):
    operating_system: Optional[str]
    operating_system_release: Optional[str]
    operating_system_version: Optional[str]
    architecture: Optional[str]


class Client(BaseModel, DAL):
    account: Optional[MemberAccount]
    client_info: Optional[ClientInfo]
    name: str
    cli_version: Optional[str]
    access_token: Optional[str]
    ip_addr: Optional[IPvAnyAddress]
    user_agent: Optional[str]
    timestamp: Optional[int]
    active: Optional[bool] = Field(default=False)

    def exists(
        self,
        account_name: Union[str, None] = None,
        client_name: Union[str, None] = None,
    ) -> bool:
        return self.load(account_name, client_name) is not None

    def load(
        self,
        account_name: Union[str, None] = None,
        client_name: Union[str, None] = None,
    ) -> Union["Client", None]:
        if client_name:
            self.name = client_name
        if account_name:
            self.account = MemberAccount(name=account_name).load()  # type: ignore
        if not isinstance(self.account, MemberAccount):
            return
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/client-tokens/{self.name}.json"  # type: ignore
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing account object: {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing account data for object: {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/client-tokens/{self.name}.json"  # type: ignore
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD,
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/client-tokens/{self.name}.json"  # type: ignore
        return services.aws.delete_s3(object_key)


class ClientRedacted(Client):
    class Config:
        validate_assignment = True

    @validator("account")
    def set_account(cls, account):
        return (
            None
            if not isinstance(account, MemberAccount)
            else MemberAccountRedacted(**account.dict())
        )


class MagicLinkRequest(BaseModel):
    email: EmailStr


class MagicLink(MagicLinkRequest, DAL):
    magic_token: str
    ip_addr: Optional[IPvAnyAddress]
    user_agent: Optional[str]
    timestamp: Optional[int]
    sendgrid_message_id: Optional[str]

    def exists(self, magic_token: Union[str, None] = None) -> bool:
        return self.load(magic_token) is not None

    def load(self, magic_token: Union[str, None] = None) -> Union["MagicLink", None]:
        if magic_token:
            self.magic_token = magic_token
        object_key = f"{internals.APP_ENV}/magic-links/{self.magic_token}.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing MagicLink {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing MagicLink {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/magic-links/{self.magic_token}.json"
        return services.aws.store_s3(object_key, json.dumps(self.dict(), default=str))

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/magic-links/{self.magic_token}.json"
        return services.aws.delete_s3(object_key)


class MemberSession(BaseModel, DAL):
    member: Optional[MemberProfile]
    session_token: str
    access_token: Optional[str]
    ip_addr: Optional[IPvAnyAddress]
    user_agent: Optional[str]
    browser: Optional[str]
    platform: Optional[str]
    lat: Optional[float]
    lon: Optional[float]
    timestamp: Optional[int]
    map_svg: Optional[str]
    current: Optional[bool] = Field(default=False)

    def exists(
        self,
        member_email: Union[EmailStr, None] = None,
        session_token: Union[str, None] = None,
    ) -> bool:
        return self.load(member_email, session_token) is not None

    def load(
        self,
        member_email: Union[EmailStr, None] = None,
        session_token: Union[str, None] = None,
    ) -> Union["MemberSession", None]:
        if member_email:
            self.member = MemberProfile(email=member_email).load()
        if session_token:
            self.session_token = session_token
        if not self.session_token or validators.email(self.member.email) is False:  # type: ignore
            return
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/sessions/{self.session_token}.json"  # type: ignore
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing session object: {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing session data for object: {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/sessions/{self.session_token}.json"  # type: ignore
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.ONEZONE_IA,
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/sessions/{self.session_token}.json"  # type: ignore
        return services.aws.delete_s3(object_key)


class MemberSessionRedacted(MemberSession):
    class Config:
        validate_assignment = True

    @validator("member")
    def set_member(cls, member):
        return (
            None
            if not isinstance(member, MemberProfile)
            else MemberProfileRedacted(**member.dict())
        )

    @validator("access_token")
    def set_access_token(cls, _):
        return None


class CheckToken(BaseModel):
    version: Optional[str]
    session: Optional[MemberSessionRedacted]
    client: Optional[ClientRedacted]
    account: Optional[MemberAccountRedacted]
    member: Optional[MemberProfileRedacted]
    authorisation_valid: bool = Field(
        default=False,
        title="HMAC Signature validation",
        description="Provides verifiable proof the client has possession of the Registration Token (without exposing/transmitting the token), using SHA256 hashing of the pertinent request information",
    )
    ip_addr: Optional[str] = Field(description="Source IP Address")
    user_agent: Optional[str] = Field(description="Source HTTP Client")


class SupportRequest(BaseModel):
    subject: str
    message: str


class Support(SupportRequest, DAL):
    member: MemberProfileRedacted
    ip_addr: Optional[IPvAnyAddress]
    user_agent: Optional[str]
    timestamp: Optional[int]
    sendgrid_message_id: Optional[str]

    def exists(
        self,
        member_email: Union[EmailStr, None] = None,
        subject: Union[str, None] = None,
    ) -> bool:
        return self.load(member_email, subject) is not None

    def load(
        self,
        member_email: Union[EmailStr, None] = None,
        subject: Union[str, None] = None,
    ) -> Union["Support", None]:
        if subject:
            self.subject = subject
        if member_email:
            self.member = MemberProfile(email=member_email).load()  # type: ignore
        clean_subject = "".join(
            e
            for e in "-".join(self.subject.split()).replace("/", "-").lower()
            if e.isalnum() or e == "-"
        )
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/support/{clean_subject}.json"  # type: ignore pylint: disable=no-member
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing Support {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Support {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        clean_subject = "".join(
            e
            for e in "-".join(self.subject.split()).replace("/", "-").lower()
            if e.isalnum() or e == "-"
        )
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/support/{clean_subject}.json"  # type: ignore pylint: disable=no-member
        return services.aws.store_s3(object_key, json.dumps(self.dict(), default=str))

    def delete(self) -> bool:
        clean_subject = "".join(
            e
            for e in "-".join(self.subject.split()).replace("/", "-").lower()
            if e.isalnum() or e == "-"
        )
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/support/{clean_subject}.json"  # type: ignore pylint: disable=no-member
        return services.aws.delete_s3(object_key)


class DefaultInfo(BaseModel):
    generator: str = Field(default="trivialscan")
    version: Optional[str] = Field(default=None, description="trivialscan CLI version")
    account_name: Optional[str] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Optional[str] = Field(
        default=None, description="Machine name where trivialscan CLI executes"
    )


class ConfigDefaults(BaseModel):
    use_sni: bool
    cafiles: Optional[str]
    tmp_path_prefix: str = Field(default="/tmp")
    http_path: str = Field(default="/")
    checkpoint: Optional[bool]


class ConfigOutput(BaseModel):
    type: OutputType
    use_icons: Optional[bool]
    when: OutputWhen = Field(default=OutputWhen.FINAL)
    path: Optional[str]


class ConfigTarget(BaseModel):
    hostname: str
    port: PositiveInt = Field(default=443)
    client_certificate: Optional[str]
    http_request_paths: list[str] = Field(default=["/"])


class Config(BaseModel):
    account_name: Optional[str] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Optional[str] = Field(
        default=None, description="Machine name where trivialscan CLI execcutes"
    )
    project_name: Optional[str] = Field(
        default=None, description="Trivial Scanner project assignment for the report"
    )
    defaults: ConfigDefaults
    outputs: list[ConfigOutput]
    targets: list[ConfigTarget]


class Flags(BaseModel):
    hide_progress_bars: Optional[bool]
    synchronous_only: Optional[bool]
    hide_banner: Optional[bool]
    track_changes: Optional[bool]
    previous_report: Optional[str]
    quiet: Optional[bool]


class HostTLSProtocol(BaseModel):
    negotiated: str
    preferred: str
    offered: list[str]


class HostTLSCipher(BaseModel):
    forward_anonymity: Optional[bool] = Field(default=False)
    offered: list[str]
    offered_rfc: Optional[list[str]]
    negotiated: str
    negotiated_bits: PositiveInt
    negotiated_rfc: Optional[str]


class HostTLSClient(BaseModel):
    certificate_mtls_expected: Optional[bool] = Field(default=False)
    certificate_trusted: Optional[bool] = Field(default=False)
    certificate_match: Optional[bool] = Field(default=False)
    expected_client_subjects: list[str] = Field(default=[])


class HostTLSSessionResumption(BaseModel):
    cache_mode: str
    tickets: bool
    ticket_hint: bool


class HostTLS(BaseModel):
    certificates: list[str] = Field(default=[])
    client: HostTLSClient
    cipher: HostTLSCipher
    protocol: HostTLSProtocol
    session_resumption: HostTLSSessionResumption


class HostHTTP(BaseModel):
    title: Optional[str]
    status_code: Optional[conint(ge=100, le=599)]  # type: ignore
    headers: Optional[dict[str, str]]
    body_hash: Optional[str]
    request_url: Optional[str]


class HostTransport(BaseModel):
    error: Optional[tuple[str, str]]
    hostname: str = Field(title="Domain Name")
    port: PositiveInt = Field(default=443)
    sni_support: Optional[bool]
    peer_address: Optional[IPvAnyAddress]
    certificate_mtls_expected: Optional[bool] = Field(default=False)


class ThreatIntelSource(str, Enum):
    CHARLES_HALEY = "CharlesHaley"
    DATAPLANE = "DataPlane"
    TALOS_INTELLIGENCE = "TalosIntelligence"
    DARKLIST = "Darklist"


class ThreatIntel(BaseModel):
    source: ThreatIntelSource
    feed_identifier: Any
    feed_date: datetime


class Host(BaseModel, DAL):
    last_updated: Optional[datetime]
    transport: HostTransport
    tls: Optional[HostTLS]
    http: Optional[list[HostHTTP]]
    monitoring_enabled: Optional[bool] = Field(default=False)
    threat_intel: Optional[list[ThreatIntel]] = Field(default=[])

    def exists(
        self,
        hostname: Union[str, None] = None,
        port: Union[int, None] = 443,
        peer_address: Union[str, None] = None,
        last_updated: Union[datetime, None] = None,
    ) -> bool:
        return self.load(hostname, port, peer_address, last_updated) is not None

    def load(
        self,
        hostname: Union[str, None] = None,
        port: Union[int, None] = 443,
        peer_address: Union[str, None] = None,
        last_updated: Union[datetime, None] = None,
    ) -> Union["Host", None]:
        if last_updated:
            self.last_updated = last_updated
        if hostname:
            self.transport = HostTransport(hostname=hostname, port=port, peer_address=peer_address)  # type: ignore

        prefix_key = (
            f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}"
        )
        if self.transport.peer_address and self.last_updated:
            scan_date = self.last_updated.strftime("%Y%m%d")
            object_key = f"{prefix_key}/{self.transport.peer_address}/{scan_date}.json"
        else:
            object_key = f"{prefix_key}/latest.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing Host {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Host {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        data = self.dict()
        scan_date = self.last_updated.strftime("%Y%m%d")  # type: ignore
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/{self.transport.peer_address}/{scan_date}.json"
        if not services.aws.store_s3(object_key, json.dumps(data, default=str)):
            return False
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/latest.json"
        # preserve threat_intel
        original = json.loads(services.aws.get_s3(object_key))
        data["threat_intel"] = {
            **original.get("threat_intel", {}),
            **data.get("threat_intel", {}),
        }
        return services.aws.store_s3(object_key, json.dumps(data, default=str))

    def delete(self) -> bool:
        scan_date = self.last_updated.strftime("%Y%m%d")  # type: ignore
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/{self.transport.peer_address}/{scan_date}.json"
        return services.aws.delete_s3(object_key)


class Certificate(BaseModel, DAL):
    authority_key_identifier: Optional[str]
    expired: Optional[bool]
    expiry_status: Optional[str]
    extensions: Optional[list] = Field(default=[])
    external_refs: Optional[dict[str, Optional[AnyHttpUrl]]] = Field(default={})
    is_self_signed: Optional[bool]
    issuer: Optional[str]
    known_compromised: Optional[bool]
    md5_fingerprint: Optional[str]
    not_after: Optional[datetime]
    not_before: Optional[datetime]
    public_key_curve: Optional[str]
    public_key_exponent: Optional[PositiveInt]
    public_key_modulus: Optional[PositiveInt]
    public_key_size: Optional[PositiveInt]
    public_key_type: Optional[PublicKeyType]
    revocation_crl_urls: Optional[list[AnyHttpUrl]] = Field(default=[])
    san: Optional[list[str]] = Field(default=[])
    serial_number: Optional[str]
    serial_number_decimal: Optional[Any]
    serial_number_hex: Optional[str]
    sha1_fingerprint: str
    sha256_fingerprint: Optional[str]
    signature_algorithm: Optional[str]
    spki_fingerprint: Optional[str]
    subject: Optional[str]
    subject_key_identifier: Optional[str]
    validation_level: Optional[ValidationLevel]
    validation_oid: Optional[str]
    version: Optional[Any] = Field(default=None)
    type: Optional[CertificateType]

    def exists(self, sha1_fingerprint: Union[str, None] = None) -> bool:
        return self.load(sha1_fingerprint) is not None

    def load(
        self, sha1_fingerprint: Union[str, None] = None
    ) -> Union["Certificate", None]:
        if sha1_fingerprint:
            self.sha1_fingerprint = sha1_fingerprint

        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing Certificate {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Certificate {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        return services.aws.store_s3(object_key, json.dumps(self.dict(), default=str))

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        return services.aws.delete_s3(object_key)


class ComplianceItem(BaseModel):
    requirement: Optional[str]
    title: Optional[str]
    description: Optional[str]


class ComplianceName(str, Enum):
    PCI_DSS = "PCI DSS"
    NIST_SP800_131A = "NIST SP800-131A"
    FIPS_140_2 = "FIPS 140-2"


class ComplianceGroup(BaseModel):
    compliance: Optional[ComplianceName]
    version: Optional[str]
    items: Optional[list[ComplianceItem]] = Field(default=[])


class ThreatItem(BaseModel):
    standard: str
    version: str
    tactic: Optional[str]
    tactic_id: Optional[str]
    tactic_url: Optional[AnyHttpUrl]
    tactic_description: Optional[str]
    technique: Optional[str]
    technique_id: Optional[str]
    technique_url: Optional[AnyHttpUrl]
    technique_description: Optional[str]
    mitigation: Optional[str]
    mitigation_id: Optional[str]
    mitigation_url: Optional[AnyHttpUrl]
    mitigation_description: Optional[str]
    sub_technique: Optional[str]
    sub_technique_id: Optional[str]
    sub_technique_url: Optional[AnyHttpUrl]
    sub_technique_description: Optional[str]
    data_source: Optional[str]
    data_source_id: Optional[str]
    data_source_url: Optional[AnyHttpUrl]
    data_source_description: Optional[str]


class ReferenceType(str, Enum):
    WEBSITE = "website"
    JSON = "json"


class ReferenceItem(BaseModel):
    name: str
    url: AnyHttpUrl
    type: Optional[ReferenceType] = Field(default=ReferenceType.WEBSITE)


class ScanRecordType(str, Enum):
    MONITORING = "Managed Monitoring"
    ONDEMAND = "Managed On-demand"
    SELF_MANAGED = "Customer-managed"


class ScanRecordCategory(str, Enum):
    ASM = "Attack Surface Monitoring"
    RECONNAISSANCE = "Reconnaissance"
    OSINT = "Public Data Sources"
    INTEGRATION_DATA = "Third Party Integration"


class ReportSummary(DefaultInfo):
    report_id: str
    project_name: Optional[str]
    targets: list[Host] = Field(default=[])
    date: Optional[datetime]
    execution_duration_seconds: Optional[PositiveFloat]
    score: int = Field(default=0)
    results: Optional[dict[str, int]]
    certificates: Optional[list[Certificate]] = Field(default=[])
    results_uri: Optional[str]
    flags: Optional[Flags]
    config: Optional[Config]
    client: Optional[ClientInfo]
    type: Optional[ScanRecordType]
    category: Optional[ScanRecordCategory]
    is_passive: Optional[bool] = Field(default=True)


class EvaluationItem(DefaultInfo):
    class Config:
        validate_assignment = True

    report_id: str
    rule_id: int
    group_id: int
    key: str
    name: str
    group: str
    observed_at: Optional[datetime]
    result_value: Union[bool, str, None]
    result_label: str
    result_text: str
    result_level: Optional[str]
    score: int = Field(default=0)
    description: Optional[str]
    recommendation: Optional[str]
    metadata: dict[str, Any] = Field(default={})
    cve: Optional[list[str]] = Field(default=[])
    cvss2: Union[str, Any] = Field(default=None)
    cvss3: Union[str, Any] = Field(default=None)
    references: Optional[list[ReferenceItem]] = Field(default=[])
    compliance: Optional[list[ComplianceGroup]] = Field(default=[])
    threats: Optional[list[ThreatItem]] = Field(default=[])
    transport: Optional[HostTransport]
    certificate: Optional[Certificate]

    @validator("references")
    def set_references(cls, references):
        return [] if not isinstance(references, list) else references

    @validator("cvss2")
    def set_cvss2(cls, cvss2):
        return None if not isinstance(cvss2, str) else cvss2

    @validator("cvss3")
    def set_cvss3(cls, cvss3):
        return None if not isinstance(cvss3, str) else cvss3


class FullReport(ReportSummary, DAL):
    evaluations: Optional[list[EvaluationItem]] = Field(default=[])

    def exists(
        self, report_id: Union[str, None] = None, account_name: Union[str, None] = None
    ) -> bool:
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        return services.aws.object_exists(object_key)

    def load(
        self, report_id: Union[str, None] = None, account_name: Union[str, None] = None
    ) -> Union["FullReport", None]:
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name

        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing FullReport {object_key}")
            return
        data = json.loads(raw)
        if data:
            super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        return services.aws.delete_s3(object_key)


class EmailEditRequest(BaseModel):
    email: EmailStr


class NameEditRequest(BaseModel):
    name: str


class MemberInvitationRequest(BaseModel):
    email: EmailStr


class AcceptEdit(BaseModel, DAL):
    account: Optional[MemberAccountRedacted]
    requester: Optional[MemberProfileRedacted]
    accept_token: str
    old_value: Optional[Any]
    new_value: Optional[Any]
    change_model: Optional[str]
    change_prop: Optional[str]
    model_key: Optional[str]
    model_value: Optional[str]
    ip_addr: Optional[IPvAnyAddress]
    user_agent: Optional[str]
    timestamp: Optional[int]
    sendgrid_message_id: Optional[str]

    def exists(self, accept_token: Union[str, None] = None) -> bool:
        return self.load(accept_token) is not None

    def load(self, accept_token: Union[str, None] = None) -> Union["AcceptEdit", None]:
        if accept_token:
            self.accept_token = accept_token
        object_key = f"{internals.APP_ENV}/accept-links/{self.accept_token}.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing AcceptEdit {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing MagicLink {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accept-links/{self.accept_token}.json"
        return services.aws.store_s3(object_key, json.dumps(self.dict(), default=str))

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accept-links/{self.accept_token}.json"
        return services.aws.delete_s3(object_key)


class GraphLabelRanges(str, Enum):
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"


class GraphLabel(str, Enum):
    PCIDSS3 = "PCI DSS v3.2.1"
    PCIDSS4 = "PCI DSS v4.0"
    NISTSP800_131A_STRICT = "NIST SP800-131A (strict mode)"
    NISTSP800_131A_TRANSITION = "NIST SP800-131A (transition mode)"
    FIPS1402 = "FIPS 140-2 Annex A"


class ComplianceChartItem(BaseModel):
    name: str
    num: int
    timestamp: int


class DashboardCompliance(BaseModel):
    label: GraphLabel
    ranges: list[GraphLabelRanges]
    data: dict[GraphLabelRanges, list[ComplianceChartItem]]


class Quota(str, Enum):
    USED = "used"
    TOTAL = "total"
    PERIOD = "period"


class AccountQuotas(BaseModel):
    unlimited_monitoring: bool
    unlimited_scans: bool
    monitoring: dict[Quota, Any]
    passive: dict[Quota, Any]
    active: dict[Quota, Any]


class SearchResult(BaseModel):
    last_scanned: Optional[int]
    hostname: Optional[str]
    monitoring: Optional[bool] = Field(default=False)
    queued_timestamp: Optional[int]
    queue_status: Optional[str]
    ip_addr: list[IPvAnyAddress]
    resolved_ip: Optional[list[IPvAnyAddress]]
    ports: Optional[list[int]]
    reports: Optional[list[str]]
    scanned: Optional[bool] = Field(default=False)


class MonitorHostname(BaseModel):
    hostname: str
    ports: Optional[list[int]] = Field(default=[443])
    timestamp: int
    enabled: bool = Field(default=False)
    path_names: Optional[list[str]] = Field(default=["/"])


class ScannerRecord(BaseModel, DAL):
    account: MemberAccountRedacted
    monitored_targets: list[MonitorHostname] = Field(default=[])
    history: list[ReportSummary] = Field(default=[])

    @property
    def object_key(self):
        return f"{internals.APP_ENV}/accounts/{self.account.name}/scanner-record.json"

    def exists(self, account_name: Union[str, None] = None) -> bool:
        if account_name:
            self.account = MemberAccount(name=account_name).load()  # type: ignore
        return services.aws.object_exists(self.object_key) is True

    def load(
        self, account_name: Union[str, None] = None
    ) -> Union["ScannerRecord", None]:
        if account_name:
            self.account = MemberAccount(name=account_name).load()  # type: ignore
        raw = services.aws.get_s3(path_key=self.object_key)
        if not raw:
            internals.logger.warning(f"Missing Queue {self.object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Queue {self.object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        return services.aws.store_s3(
            self.object_key, json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        return services.aws.delete_s3(self.object_key)


class HostResponse(BaseModel):
    host: Host
    reports: list[ReportSummary]
    versions: list[str]
    external_refs: dict[str, Union[AnyHttpUrl, str]]


class CertificateResponse(BaseModel):
    certificate: Certificate
    reports: list[ReportSummary]


class WebhookEndpointRequest(BaseModel):
    endpoint: AnyHttpUrl


class WebhookEvent(str, Enum):
    HOSTED_MONITORING = "hosted_monitoring"
    HOSTED_SCANNER = "hosted_scanner"
    SELF_HOSTED_UPLOADS = "self_hosted_uploads"
    EARLY_WARNING_EMAIL = "early_warning_email"
    EARLY_WARNING_DOMAIN = "early_warning_domain"
    EARLY_WARNING_IP = "early_warning_ip"
    NEW_FINDINGS_CERTIFICATES = "new_findings_certificates"
    NEW_FINDINGS_DOMAINS = "new_findings_domains"
    INCLUDE_WARNING = "include_warning"
    INCLUDE_INFO = "include_info"
    CLIENT_STATUS = "client_status"
    CLIENT_ACTIVITY = "client_activity"
    SCANNER_CONFIGURATIONS = "scanner_configurations"
    REPORT_CREATED = "report_created"
    REPORT_DELETED = "report_deleted"
    ACCOUNT_ACTIVITY = "account_activity"
    MEMBER_ACTIVITY = "member_activity"


class WebhookPayload(BaseModel):
    event_name: WebhookEvent
    timestamp: datetime
    payload: dict


class ConfigUpdateRequest(BaseModel):
    hostname: str
    enabled: Optional[bool]
    http_paths: Optional[list[str]]
    ports: Optional[list[PositiveInt]]