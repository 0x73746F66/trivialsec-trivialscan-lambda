# pylint: disable=no-self-argument, arguments-differ
import json
import hashlib
from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import Union, Any, Optional
from datetime import datetime

import validators
from pydantic import BaseModel, Field, AnyHttpUrl, validator, conint, PositiveInt, PositiveFloat, IPvAnyAddress, EmailStr

import internals
import services
import services.aws


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

class MemberAccount(AccountRegistration, DAL):
    billing_email: Optional[EmailStr]
    api_key: Optional[str]
    ip_addr: Union[IPvAnyAddress, None] = Field(default=None)
    user_agent: Union[str, None] = Field(default=None)
    timestamp: Optional[int]

    def exists(self, account_name: Union[str, None] = None) -> bool:
        return self.load(account_name) is not None

    def load(self, account_name: Union[str, None] = None) -> Union['MemberAccount', None]:
        if account_name:
            self.name = account_name
        if not self.name:
            return
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing account object: {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(
                f"Missing account data for object: {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        return services.aws.delete_s3(object_key)

class MemberAccountRedacted(MemberAccount):
    class Config:
        validate_assignment = True
    @validator("api_key")
    def set_api_key(cls, _):
        return None

class MemberProfile(BaseModel, DAL):
    account: Optional[MemberAccount]
    email: EmailStr
    email_md5: Optional[str]
    confirmed: bool = Field(default=False)
    confirmation_token: Union[str, None] = Field(default=None)
    ip_addr: Union[IPvAnyAddress, None] = Field(default=None)
    user_agent: Union[str, None] = Field(default=None)
    timestamp: Optional[int]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.email_md5 = hashlib.md5(self.email.encode()).hexdigest()

    def exists(self, member_email: Union[EmailStr, None] = None) -> bool:
        return self.load(member_email) is not None

    def load(self, member_email: Union[EmailStr, None] = None) -> Union['MemberProfile', None]:
        if member_email:
            self.email = member_email
        if validators.email(self.email) is False:
            return
        suffix = f"/members/{self.email}/profile.json"
        prefix_matches = services.aws.list_s3(prefix_key=f"{internals.APP_ENV}/accounts")
        matches = [k for k in prefix_matches if k.endswith(suffix)]
        if len(matches) > 1:
            internals.logger.critical("MemberProfile.load found too many matches, this is a data taint, likely manual data edits")
            internals.logger.info(matches)
        if len(matches) == 0:
            internals.logger.warning(f"Missing member for: {member_email}")
            return
        raw = services.aws.get_s3(matches[0])
        if not raw:
            internals.logger.warning(f"Missing member for: {member_email}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        data = json.loads(raw)
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing member data for: {member_email}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/members/{self.email}/profile.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/members/{self.email}/profile.json"
        return services.aws.delete_s3(object_key)

class MemberProfileRedacted(MemberProfile):
    class Config:
        validate_assignment = True
    @validator("account")
    def set_account(cls, account):
        return None if not isinstance(account, MemberAccount) else MemberAccountRedacted(**account.dict())
    @validator("confirmation_token")
    def set_confirmation_token(cls, _):
        return None

class ClientInfo(BaseModel):
    operating_system: str
    operating_system_release: str
    operating_system_version: str
    architecture: str

class Client(BaseModel, DAL):
    account: Optional[MemberAccount]
    client_info: Optional[ClientInfo]
    name: str
    cli_version: Optional[str]
    access_token: Union[str, None] = Field(default=None)
    ip_addr: Union[IPvAnyAddress, None] = Field(default=None)
    user_agent: Union[str, None] = Field(default=None)
    timestamp: Optional[int]
    active: bool = Field(default=False)

    def exists(self, account_name: Union[str, None] = None, client_name: Union[str, None] = None) -> bool:
        return self.load(account_name, client_name) is not None

    def load(self, account_name: Union[str, None] = None, client_name: Union[str, None] = None) -> Union['Client', None]:
        if client_name:
            self.name = client_name
        if account_name:
            self.account = MemberAccount(name=account_name).load()
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/client-tokens/{self.name}.json"
        raw = services.aws.get_s3(object_key)
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
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/client-tokens/{self.name}.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/client-tokens/{self.name}.json"
        return services.aws.delete_s3(object_key)

class ClientRedacted(Client):
    class Config:
        validate_assignment = True
    @validator("account")
    def set_account(cls, account):
        return None if not isinstance(account, MemberAccount) else MemberAccountRedacted(**account.dict())
    @validator("access_token")
    def set_access_token(cls, _):
        return None

class MagicLinkRequest(BaseModel):
    email: EmailStr

class MagicLink(MagicLinkRequest, DAL):
    magic_token: str
    ip_addr: Union[IPvAnyAddress, None] = Field(default=None)
    user_agent: Union[str, None] = Field(default=None)
    timestamp: Union[int, None] = Field(default=None)
    sendgrid_message_id: Union[str, None] = Field(default=None)

    def exists(self, magic_token: Union[str, None] = None) -> bool:
        return self.load(magic_token) is not None

    def load(self, magic_token: Union[str, None] = None) -> Union['Client', None]:
        if magic_token:
            self.magic_token = magic_token
        object_key = f"{internals.APP_ENV}/magic-links/{self.magic_token}.json"
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing MagicLink {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(
                f"Missing MagicLink {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/magic-links/{self.magic_token}.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/magic-links/{self.magic_token}.json"
        return services.aws.delete_s3(object_key)

class MemberSession(BaseModel, DAL):
    member: Optional[MemberProfile]
    session_token: str
    access_token: Optional[str]
    ip_addr: Union[IPvAnyAddress, None] = Field(default=None)
    user_agent: Union[str, None] = Field(default=None)
    timestamp: Optional[int]

    def exists(self, member_email: Union[EmailStr, None] = None, session_token: Union[str, None] = None) -> bool:
        return self.load(member_email, session_token) is not None

    def load(self, member_email: Union[EmailStr, None] = None, session_token: Union[str, None] = None) -> Union['MemberSession', None]:
        if member_email:
            self.member = MemberProfile(email=member_email).load()
        if session_token:
            self.session_token = session_token
        if not self.session_token or validators.email(self.member.email) is False:
            return
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/sessions/{self.session_token}.json"
        raw = services.aws.get_s3(object_key)
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
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/sessions/{self.session_token}.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.ONEZONE_IA
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/sessions/{self.session_token}.json"
        return services.aws.delete_s3(object_key)

class MemberSessionRedacted(MemberSession):
    class Config:
        validate_assignment = True
    @validator("member")
    def set_member(cls, member):
        return None if not isinstance(member, MemberProfile) else MemberProfileRedacted(**member.dict())
    @validator("access_token")
    def set_access_token(cls, _):
        return None

class CheckToken(BaseModel):
    version: Union[str, None] = Field(default=None)
    session: Union[MemberSession, None] = Field(default=None)
    client: Union[Client, None] = Field(default=None)
    account: Union[MemberAccount, None] = Field(default=None)
    member: Union[MemberProfile, None] = Field(default=None)
    sessions: list[MemberSession] = Field(default=[])
    authorisation_valid: bool = Field(default=False, title="HMAC Signature validation", description="Provides verifiable proof the client has possession of the Registration Token (without exposing/transmitting the token), using SHA256 hashing of the pertinent request information")
    ip_addr: Union[str, None] = Field(default=None, description="Source IP Address")
    user_agent: Union[str, None] = Field(default=None, description="Source HTTP Client")

class SupportRequest(BaseModel):
    subject: str
    message: str

class Support(SupportRequest, DAL):
    member: MemberProfile
    ip_addr: Union[IPvAnyAddress, None] = Field(default=None)
    user_agent: Union[str, None] = Field(default=None)
    timestamp: Union[int, None] = Field(default=None)
    sendgrid_message_id: Union[str, None] = Field(default=None)

    def exists(self, member_email: Union[EmailStr, None] = None, subject: Union[str, None] = None) -> bool:
        return self.load(member_email, subject) is not None

    def load(self, member_email: Union[EmailStr, None] = None, subject: Union[str, None] = None) -> Union['Client', None]:
        if subject:
            self.subject = subject
        if member_email:
            self.member = MemberProfile(email=member_email).load()
        clean_subject = ''.join(e for e in '-'.join(self.subject.split()).replace('/', '-').lower() if e.isalnum() or e == '-')
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/support/{clean_subject}.json"
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing Support {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(
                f"Missing Support {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        clean_subject = ''.join(e for e in '-'.join(self.subject.split()).replace('/', '-').lower() if e.isalnum() or e == '-')
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/support/{clean_subject}.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        clean_subject = ''.join(e for e in '-'.join(self.subject.split()).replace('/', '-').lower() if e.isalnum() or e == '-')
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/support/{clean_subject}.json"
        return services.aws.delete_s3(object_key)

class DefaultInfo(BaseModel):
    generator: str = Field(default="trivialscan")
    version: Union[str, None] = Field(default=None, description="trivialscan CLI version")
    account_name: Union[str, None] = Field(default=None, description="Trivial Security account name")
    client_name: Union[str, None] = Field(default=None, description="Machine name where trivialscan CLI execcutes")

class ConfigDefaults(BaseModel):
    use_sni: bool
    cafiles: Union[str, None]
    tmp_path_prefix: str = Field(default="/tmp")
    http_path: str = Field(default="/")
    checkpoint: bool

class ConfigOutput(BaseModel):
    type: OutputType
    use_icons: Union[bool, None]
    when: OutputWhen = Field(default=OutputWhen.FINAL)
    path: Union[str, None] = Field(default=None)

class ConfigTarget(BaseModel):
    hostname: str
    port: PositiveInt = Field(default=443)
    client_certificate: Union[bool, None] = Field(default=False)
    http_request_paths: list[str] = Field(default=["/"])

class Config(BaseModel):
    account_name: Union[str, None] = Field(default=None, description="Trivial Security account name")
    client_name: Union[str, None] = Field(default=None, description="Machine name where trivialscan CLI execcutes")
    project_name: Union[str, None] = Field(default=None, description="Trivial Scanner project assignment for the report")
    defaults: ConfigDefaults
    outputs: list[ConfigOutput]
    targets: list[ConfigTarget]

class Flags(BaseModel):
    hide_progress_bars: bool
    synchronous_only: bool
    hide_banner: bool
    track_changes: bool
    previous_report: Union[str, None]
    quiet: bool

class ReportSummary(DefaultInfo, DAL):
    report_id: str
    project_name: Union[str, None]
    targets: list[str]
    date: datetime
    execution_duration_seconds: Union[PositiveFloat, None] = Field(default=None)
    score: int = Field(default=0)
    results: dict[str, int]
    certificates: list[str] = Field(default=[])
    results_uri: str
    flags: Union[Flags, None] = Field(default=None)
    config: Union[Config, None] = Field(default=None)

    def exists(self, report_id: Union[str, None] = None, account_name: Union[str, None] = None) -> bool:
        return self.load(report_id, account_name) is not None

    def load(self, report_id: Union[str, None] = None, account_name: Union[str, None] = None) -> Union['ReportSummary', None]:
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name

        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/summary.json"
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing ReportSummary {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(
                f"Missing ReportSummary {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/summary.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/summary.json"
        return services.aws.delete_s3(object_key)

class HostTLSProtocol(BaseModel):
    negotiated: str
    negotiated_rfc: str
    preferred: str
    preferred_rfc: str
    offered: list[str]
    offered_rfc: list[str]

class HostTLSCipher(BaseModel):
    forward_anonymity: Union[bool, None] = Field(default=False)
    offered: list[str]
    negotiated: str
    negotiated_bits: PositiveInt

class HostTLSClient(BaseModel):
    certificate_mtls_expected: Union[bool, None] = Field(default=False)
    certificate_trusted: Union[bool, None] = Field(default=False)
    certificate_match: Union[bool, None] = Field(default=False)
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
    title: str
    status_code: conint(ge=100, le=599)
    headers: dict[str, str]
    body_hash: str

class HostTransport(BaseModel):
    hostname: str = Field(title="Domain Name")
    port: PositiveInt = Field(default=443)
    sni_support: Optional[bool]
    peer_address: Optional[IPvAnyAddress]
    certificate_mtls_expected: Union[bool, None] = Field(default=False)

class Host(BaseModel, DAL):
    last_updated: Optional[datetime]
    transport: HostTransport
    tls: Optional[HostTLS]
    http: Optional[list[HostHTTP]]

    def exists(self,
            hostname: Union[str, None] = None,
            port: Union[int, None] = 443,
            peer_address: Union[str, None] = None,
            last_updated: Union[datetime, None] = None,
    ) -> bool:
        return self.load(hostname, port, peer_address, last_updated) is not None

    def load(self,
            hostname: Union[str, None] = None,
            port: Union[int, None] = 443,
            peer_address: Union[str, None] = None,
            last_updated: Union[datetime, None] = None,
    ) -> Union['Host', None]:
        if last_updated:
            self.last_updated = last_updated
        if hostname:
            self.transport = HostTransport(hostname=hostname, port=port, peer_address=peer_address)

        prefix_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}"
        if self.transport.peer_address and self.last_updated:
            scan_date = datetime.fromisoformat(self.last_updated).strftime("%Y%m%d")
            object_key = f"{prefix_key}/{self.transport.peer_address}/{scan_date}.json"
        else:
            object_key = f"{prefix_key}/latest.json"
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing Host {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(
                f"Missing Host {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        scan_date = datetime.fromisoformat(self.last_updated).strftime("%Y%m%d")
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/{self.transport.peer_address}/{scan_date}.json"
        if not services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        ):
            return False
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/latest.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        scan_date = datetime.fromisoformat(self.last_updated).strftime("%Y%m%d")
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/{self.transport.peer_address}/{scan_date}.json"
        return services.aws.delete_s3(object_key)

class Certificate(BaseModel, DAL):
    authority_key_identifier: Union[str, None] = Field(default=None)
    expired: Optional[bool]
    expiry_status: Optional[str]
    extensions: list = Field(default=[])
    external_refs: dict[str, AnyHttpUrl] = Field(default={})
    is_self_signed: Optional[bool]
    issuer: Optional[str]
    known_compromised: Optional[bool]
    md5_fingerprint: Optional[str]
    not_after: Optional[datetime]
    not_before: Optional[datetime]
    public_key_curve: Union[str, None] = Field(default=None)
    public_key_exponent: Union[PositiveInt, None] = Field(default=None)
    public_key_modulus: Union[PositiveInt, None] = Field(default=None)
    public_key_size: Optional[PositiveInt]
    public_key_type: Optional[PublicKeyType]
    revocation_crl_urls: list[AnyHttpUrl] = Field(default=[])
    san: list[str] = Field(default=[])
    serial_number: Optional[str]
    serial_number_decimal: Optional[PositiveInt]
    serial_number_hex: Optional[str]
    sha1_fingerprint: str
    sha256_fingerprint: Optional[str]
    signature_algorithm: Optional[str]
    spki_fingerprint: Optional[str]
    subject: Optional[str]
    subject_key_identifier: Optional[str]
    validation_level: Union[ValidationLevel, None] = Field(default=None)
    validation_oid: Union[str, None] = Field(default=None)
    version: Optional[PositiveInt]
    type: Optional[CertificateType]

    def exists(self, sha1_fingerprint: Union[str, None] = None) -> bool:
        return self.load(sha1_fingerprint) is not None

    def load(self, sha1_fingerprint: Union[str, None] = None) -> Union['Certificate', None]:
        if sha1_fingerprint:
            self.sha1_fingerprint = sha1_fingerprint

        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing Certificate {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(
                f"Missing Certificate {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        return services.aws.delete_s3(object_key)

class ComplianceItem(BaseModel):
    compliance: str
    version: str
    requirement: Union[str, None] = Field(default=None)
    description: Union[str, None] = Field(default=None)

class ThreatItem(BaseModel):
    standard: str
    version: str
    tactic_id: Union[str, None] = Field(default=None)
    tactic_url: Union[AnyHttpUrl, None] = Field(default=None)
    tactic: Union[str, None] = Field(default=None)
    description: Union[str, None] = Field(default=None)
    technique_id: Union[str, None] = Field(default=None)
    technique_url: Union[AnyHttpUrl, None] = Field(default=None)
    technique: Union[str, None] = Field(default=None)
    technique_description: Union[str, None] = Field(default=None)
    sub_technique_id: Union[str, None] = Field(default=None)
    sub_technique_url: Union[AnyHttpUrl, None] = Field(default=None)
    sub_technique: Union[str, None] = Field(default=None)
    sub_technique_description: Union[str, None] = Field(default=None)
    data_source_id: Union[str, None] = Field(default=None)
    data_source_url: Union[AnyHttpUrl, None] = Field(default=None)
    data_source: Union[str, None] = Field(default=None)

class ReferenceItem(BaseModel):
    name: str
    url: AnyHttpUrl

class EvaluationItem(DefaultInfo):
    class Config:
        validate_assignment = True
    report_id: str
    rule_id: str
    group_id: str
    key: str
    name: str
    group: str
    result_value: Union[bool, str, None]
    result_label: str
    result_text: str
    result_level: Union[str, None] = Field(default=None)
    result_color: Union[str, None] = Field(default=None)
    score: int = Field(default=0)
    description: str
    metadata: dict[str, Any] = Field(default={})
    cve: Union[list[str], None] = Field(default=[])
    cvss2: Union[str, Any] = Field(default=None)
    cvss3: Union[str, Any] = Field(default=None)
    references: Union[list[ReferenceItem], None] = Field(default=[])
    compliance: Union[list[ComplianceItem], None] = Field(default=[])
    threats: Union[list[ThreatItem], None] = Field(default=[])
    @validator("cvss2")
    def set_cvss2(cls, cvss2):
        return None if not isinstance(cvss2, str) else cvss2
    @validator("cvss3")
    def set_cvss3(cls, cvss3):
        return None if not isinstance(cvss3, str) else cvss3

class EvaluationReport(ReportSummary, DAL):
    evaluations: list[EvaluationItem]

    def exists(self, report_id: Union[str, None] = None, account_name: Union[str, None] = None) -> bool:
        return self.load(report_id, account_name) is not None

    def load(self, report_id: Union[str, None] = None, account_name: Union[str, None] = None) -> Union['EvaluationReport', None]:
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name

        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/evaluations.json"
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing EvaluationReport {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(
                f"Missing EvaluationReport {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/evaluations.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/evaluations.json"
        return services.aws.delete_s3(object_key)
