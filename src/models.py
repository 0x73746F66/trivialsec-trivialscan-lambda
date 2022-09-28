# pylint: disable=no-self-argument
from enum import Enum
from typing import Union, Any
from datetime import datetime

from pydantic import BaseModel, Field, AnyHttpUrl, validator, conint, PositiveInt, PositiveFloat, IPvAnyAddress

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

class DefaultInfo(BaseModel):
    generator: str = Field(default="trivialscan")
    version: Union[str, None] = Field(default=None, description="trivialscan CLI version")
    account_name: Union[str, None] = Field(default=None, description="Trivial Security account name")
    client_name: Union[str, None] = Field(default=None, description="Machine name where trivialscan CLI execcutes")

class CheckToken(DefaultInfo):
    authorisation_valid: bool = Field(default=False, title="HMAC Signature validation", description="Provides verifiable proof the client has possession of the Registration Token (without exposing/transmitting the token), using SHA256 hashing of the pertinent request information")
    registered: bool = Field(default=False, description="Client is registered")
    ip_address: Union[str, None] = Field(default=None, description="Source IP Address")
    user_agent: Union[str, None] = Field(default=None, description="Source HTTP Client")

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

class ReportSummary(DefaultInfo):
    project_name: Union[str, None]
    targets: list[str]
    date: datetime
    execution_duration_seconds: Union[PositiveFloat, None] = Field(
        default=None)
    score: int = Field(default=0)
    results: dict[str, int]
    certificates: list[str] = Field(default=[])
    results_uri: str
    flags: Union[Flags, None] = Field(default=None)
    config: Union[Config, None] = Field(default=None)

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
    sni_support: bool
    peer_address: IPvAnyAddress
    certificate_mtls_expected: Union[bool, None] = Field(default=False)

class Host(BaseModel):
    last_updated: datetime
    transport: HostTransport
    tls: HostTLS
    http: list[HostHTTP]

class Certificate(BaseModel):
    authority_key_identifier: str
    expired: bool
    expiry_status: str
    extensions: list
    external_refs: dict[str, AnyHttpUrl]
    is_self_signed: bool
    issuer: str
    known_compromised: bool
    md5_fingerprint: str
    not_after: datetime
    not_before: datetime
    public_key_curve: str
    public_key_exponent: Union[PositiveInt, None]
    public_key_modulus: Union[PositiveInt, None]
    public_key_size: PositiveInt
    public_key_type: PublicKeyType
    revocation_crl_urls: list[AnyHttpUrl]
    san: list[str]
    serial_number: str
    serial_number_decimal: PositiveInt
    serial_number_hex: str
    sha1_fingerprint: str
    sha256_fingerprint: str
    signature_algorithm: str
    spki_fingerprint: str
    subject: str
    subject_key_identifier: str
    validation_level: ValidationLevel
    validation_oid: Union[str, None]
    version: PositiveInt
    type: CertificateType

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

class EvaluationReport(ReportSummary):
    evaluations: list[EvaluationItem]
