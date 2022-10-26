# pylint: disable=no-self-argument, arguments-differ
import json
import hashlib
from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import Union, Any, Optional
from decimal import Decimal
from datetime import datetime

import validators
from pydantic import BaseModel, Field, AnyHttpUrl, validator, conint, PositiveInt, PositiveFloat, IPvAnyAddress, EmailStr
from pydantic.error_wrappers import ValidationError

import internals
import services.aws
import services.stripe


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

class PriceType(str, Enum):
    ONE_TIME = "one_time"
    RECURRING = "recurring"

class BillingScheme(str, Enum):
    PER_UNIT = "per_unit"
    TIERED = "tiered"

class SupportedCurrency(str, Enum):
    USD = "usd"
    AUD = "aud"

class RecurringInterval(str, Enum):
    MONTH = "month"
    YEAR = "year"
    WEEK = "week"
    DAY = "day"

class RecurringType(str, Enum):
    LICENSED = "licensed"
    METERED = "metered"

class PriceRecurring(BaseModel):
    aggregate_usage: Union[str, None] = Field(default=None)
    interval: RecurringInterval
    interval_count: int
    trial_period_days: Union[str, None] = Field(default=None)
    usage_type: RecurringType

class SubscriptionPrice(BaseModel):
    id: str
    active: bool
    billing_scheme: BillingScheme
    created: int
    currency: SupportedCurrency
    livemode: bool
    metadata: dict = Field(default={})
    nickname: Union[str, None] = Field(default=None)
    product: str
    recurring: PriceRecurring
    type: PriceType
    unit_amount: Decimal
    unit_amount_decimal: str

class SubscriptionItem(BaseModel):
    id: str
    created: int
    metadata: dict = Field(default={})
    price: SubscriptionPrice
    quantity: int
    subscription: str
    tax_rates: list = Field(default=[])

class SubscriptionCollectionMethod(str, Enum):
    CHARGE_AUTOMATICALLY = "charge_automatically"
    SEND_INVOICE = "send_invoice"

class SubscriptionPauseBehavior(str, Enum):
    KEEP_AS_DRAFT = "keep_as_draft"
    MARK_UNCOLLECTIBLE = "mark_uncollectible"
    VOID = "void"

class SubscriptionCouponDuration(str, Enum):
    ONCE = "once"
    REPEATING = "repeating"
    FOREVER = "forever"

class SubscriptionStatus(str, Enum):
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    UNPAID = "unpaid"

class SubscriptionPause(BaseModel):
    behavior: SubscriptionPauseBehavior
    resumes_at: int


class SubscriptionCoupon(BaseModel):
    id: str
    amount_off: Union[Decimal, None] = Field(default=None)
    created: int
    currency: Union[SupportedCurrency, None] = Field(default=None)
    duration: SubscriptionCouponDuration
    duration_in_months: Union[int, None] = Field(default=None)
    livemode: bool
    max_redemptions: Union[int, None] = Field(default=None)
    metadata: Union[dict, None] = Field(default={})
    name: str
    percent_off: Union[Decimal, None] = Field(default=None)
    redeem_by: int
    times_redeemed: int
    valid: bool

class SubscriptionDiscount(BaseModel):
    id: str
    coupon: SubscriptionCoupon
    customer: str
    end: Union[int, None] = Field(default=None)
    invoice: Union[str, None] = Field(default=None)
    invoice_item: Union[str, None] = Field(default=None)
    promotion_code: str
    start: int
    subscription: str

class SubscriptionPlan(BaseModel):
    id: str
    active: bool
    aggregate_usage: Union[str, None] = Field(default=None)
    amount: Decimal
    amount_decimal: str
    billing_scheme: BillingScheme
    created: int
    currency: SupportedCurrency
    interval: RecurringInterval
    interval_count: int
    livemode: bool
    metadata: Union[dict, None] = Field(default={})
    nickname: Union[str, None] = Field(default=None)
    product: str
    trial_period_days: Union[int, None] = Field(default=None)
    usage_type: RecurringType

class SubscriptionBase(BaseModel):
    id: Optional[str]
    billing_cycle_anchor: Optional[int]
    cancel_at: Union[int, None] = Field(default=None)
    cancel_at_period_end: Union[bool, None] = Field(default=None)
    canceled_at: Union[int, None] = Field(default=None)
    collection_method: Optional[SubscriptionCollectionMethod]
    created: Optional[int]
    currency: Optional[SupportedCurrency]
    current_period_end: Union[int, None] = Field(default=None)
    current_period_start: Union[int, None] = Field(default=None)
    customer: Optional[str]
    days_until_due: Union[int, None] = Field(default=None)
    default_payment_method: Optional[str]
    description: Optional[str]
    discount: Union[SubscriptionDiscount, None] = Field(default=None)
    ended_at: Union[int, None] = Field(default=None)
    latest_invoice: Optional[str]
    livemode: Optional[bool]
    metadata: Union[dict, None] = Field(default={})
    next_pending_invoice_item_invoice: Union[int, None] = Field(default=None)
    pause_collection: Union[SubscriptionPause, None] = Field(default=None)
    plan: Optional[SubscriptionPlan]
    quantity: Optional[int]
    start_date: Optional[int]
    status: Optional[SubscriptionStatus]
    trial_end: Optional[int]
    trial_start: Optional[int]
    subscription_item: Optional[SubscriptionItem]

    def load(self, *args, **kwargs):
        raise NotImplementedError

    def exists(self, account_name: str) -> bool:
        return self.load(account_name) is not None

    def save(self) -> bool:
        raise RuntimeWarning("This is not a supported method. Use the Stripe SDK/API to modify payments")

    def delete(self) -> bool:
        raise RuntimeWarning("This is not a supported method. Use the Stripe SDK/API to modify payments")

class SubscriptionAddon(SubscriptionBase, DAL):
    def load(self, account_name: str) -> Union['SubscriptionAddon', None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError('Subscription.load missing account_name')

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.UNLIMITED_RESCANS}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(match)
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.decoder.JSONDecodeError as err:
                internals.logger.debug(err, exc_info=True)
                continue
            if not data or not isinstance(data, dict):
                internals.logger.debug(f"not data {match}")
                continue
            if data.get('livemode') and data.get('status') in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get('created')))
        if res:
            super().__init__(**res[-1])
            return self

class SubscriptionBooster(SubscriptionBase, DAL):
    def load(self, account_name: str) -> Union['SubscriptionBooster', None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError('Subscription.load missing account_name')

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.CONTINUOUS_MONITORING_BOOSTER}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(match)
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.decoder.JSONDecodeError as err:
                internals.logger.debug(err, exc_info=True)
                continue
            if not data or not isinstance(data, dict):
                internals.logger.debug(f"not data {match}")
                continue
            if data.get('livemode') and data.get('status') in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get('created')))
        if res:
            super().__init__(**res[-1])
            return self

class SubscriptionPro(SubscriptionBase, DAL):
    def load(self, account_name: str) -> Union['SubscriptionPro', None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError('Subscription.load missing account_name')

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.PROFESSIONAL}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(match)
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.decoder.JSONDecodeError as err:
                internals.logger.debug(err, exc_info=True)
                continue
            if not data or not isinstance(data, dict):
                internals.logger.debug(f"not data {match}")
                continue
            if data.get('livemode') and data.get('status') in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get('created')))
        if res:
            super().__init__(**res[-1])
            return self

class SubscriptionEnterprise(SubscriptionBase, DAL):
    def load(self, account_name: str) -> Union['SubscriptionEnterprise', None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError('Subscription.load missing account_name')

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.ENTERPRISE}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(match)
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.decoder.JSONDecodeError as err:
                internals.logger.debug(err, exc_info=True)
                continue
            if not data or not isinstance(data, dict):
                internals.logger.debug(f"not data {match}")
                continue
            if data.get('livemode') and data.get('status') in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get('created')))
        if res:
            super().__init__(**res[-1])
            return self

class SubscriptionUnlimited(SubscriptionBase, DAL):
    def load(self, account_name: str) -> Union['SubscriptionUnlimited', None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError('Subscription.load missing account_name')

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.UNLIMITED}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(match)
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except json.decoder.JSONDecodeError as err:
                internals.logger.debug(err, exc_info=True)
                continue
            if not data or not isinstance(data, dict):
                internals.logger.debug(f"not data {match}")
                continue
            if data.get('livemode') and data.get('status') in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get('created')))
        if res:
            super().__init__(**res[-1])
            return self

class AccountRegistration(BaseModel):
    name: str
    display: Optional[str]
    primary_email: Optional[EmailStr]

class Billing(BaseModel):
    product_name: str
    is_trial: bool = Field(default=False)
    description: Union[str, None] = Field(default=None)
    display_amount: str = Field(default="free")
    display_period: Union[str, None] = Field(default=None)
    next_due: Union[int, None] = Field(default=None)
    has_invoice: bool = Field(default=False)

class MemberAccount(AccountRegistration, DAL):
    billing_email: Optional[EmailStr]
    api_key: Optional[str]
    ip_addr: Union[IPvAnyAddress, None] = Field(default=None)
    user_agent: Union[str, None] = Field(default=None)
    timestamp: Optional[int]
    billing: Union[Billing, None] = Field(default=None)

    def load_billing(self):
        if sub := SubscriptionAddon().load(self.name):  # type: ignore
            return self._billing(sub)
        elif sub := SubscriptionPro().load(self.name):  # type: ignore
            return self._billing(sub)
        elif sub := SubscriptionEnterprise().load(self.name):  # type: ignore
            return self._billing(sub)
        elif sub := SubscriptionUnlimited().load(self.name):  # type: ignore
            return self._billing(sub)
        self.billing = Billing(
            product_name=services.stripe.PRODUCTS.get(services.stripe.Product.COMMUNITY_EDITION).get("name")  # type: ignore
        )

    def _billing(self, sub: SubscriptionBase):
        self.billing = Billing(
            product_name=services.stripe.PRODUCTS.get(services.stripe.PRODUCT_MAP.get(sub.plan.product), {}).get("name")  # type: ignore
        )
        self.billing.is_trial = sub.status == SubscriptionStatus.TRIALING
        self.billing.has_invoice = isinstance(sub.latest_invoice, str) and sub.latest_invoice.startswith("in_")
        currency = sub.subscription_item.price.currency  # type: ignore
        amount = sub.subscription_item.price.unit_amount_decimal  # type: ignore
        self.billing.display_amount = f'{currency.upper()} ${amount}'
        self.billing.display_period = sub.subscription_item.price.recurring.interval.capitalize()  # type: ignore
        if not sub.cancel_at_period_end:
            # JavaScript compatibility
            self.billing.next_due = sub.current_period_end * 1000  # type: ignore
        if sub.default_payment_method and sub.collection_method == SubscriptionCollectionMethod.CHARGE_AUTOMATICALLY:
            self.billing.description = "Stripe Payments"
        elif sub.collection_method == SubscriptionCollectionMethod.SEND_INVOICE:
            self.billing.description = "Send Invoice"

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

    def delete(self) -> Union[bool, None]:
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        return services.aws.delete_s3(object_key)

    def update_members(self) -> bool:
        prefix_key = f"{internals.APP_ENV}/accounts/{self.name}/"
        members: list['MemberProfile'] = []
        member_matches = services.aws.list_s3(f"{prefix_key}members/")
        results: list[bool] = []
        for object_path in member_matches:
            if not object_path.endswith("profile.json"):
                continue
            raw = services.aws.get_s3(object_path)
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
            session_matches = services.aws.list_s3(f"{prefix_key}members/{member.email}/sessions/")
            for object_path in session_matches:
                raw = services.aws.get_s3(object_path)
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

class MemberProfile(BaseModel, DAL):
    account: Optional[MemberAccount]
    email: EmailStr
    email_md5: Optional[str]
    confirmed: bool = Field(default=False)
    confirmation_token: Union[str, None] = Field(default=None)
    timestamp: Optional[int]
    current: Optional[bool] = Field(default=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.email_md5 = hashlib.md5(self.email.encode()).hexdigest()

    def exists(self, member_email: Union[EmailStr, None] = None) -> bool:
        return self.load(member_email) is not None

    def load(self, member_email: Union[EmailStr, None] = None) -> Union['MemberProfile', None]:
        if member_email:
            self.email = member_email
        if validators.email(self.email) is False:  # type: ignore
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
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing member data for: {member_email}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/members/{self.email}/profile.json"  # type: ignore
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD
        )

    def delete(self) -> bool:
        prefix_key = f"{internals.APP_ENV}/accounts/{self.account.name}/members/{self.email}/"  # type: ignore
        prefix_matches = services.aws.list_s3(prefix_key)
        if len(prefix_matches) == 0:
            return False
        results: list[bool] = []
        for object_key in prefix_matches:
            results.append(services.aws.delete_s3(object_key))
        return all(results)

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
    operating_system: Optional[str]
    operating_system_release: Optional[str]
    operating_system_version: Optional[str]
    architecture: Optional[str]

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
            self.account = MemberAccount(name=account_name).load()  # type: ignore
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/client-tokens/{self.name}.json"  # type: ignore
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
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/client-tokens/{self.name}.json"  # type: ignore
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/client-tokens/{self.name}.json"  # type: ignore
        return services.aws.delete_s3(object_key)

class ClientRedacted(Client):
    class Config:
        validate_assignment = True
    @validator("account")
    def set_account(cls, account):
        return None if not isinstance(account, MemberAccount) else MemberAccountRedacted(**account.dict())

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

    def load(self, magic_token: Union[str, None] = None) -> Union['MagicLink', None]:
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
    browser: Union[str, None] = Field(default=None)
    platform: Union[str, None] = Field(default=None)
    lat: Optional[float]
    lon: Optional[float]
    timestamp: Optional[int]
    map_svg: Optional[str]
    current: Optional[bool] = Field(default=False)

    def exists(self, member_email: Union[EmailStr, None] = None, session_token: Union[str, None] = None) -> bool:
        return self.load(member_email, session_token) is not None

    def load(self, member_email: Union[EmailStr, None] = None, session_token: Union[str, None] = None) -> Union['MemberSession', None]:
        if member_email:
            self.member = MemberProfile(email=member_email).load()
        if session_token:
            self.session_token = session_token
        if not self.session_token or validators.email(self.member.email) is False:  # type: ignore
            return
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/sessions/{self.session_token}.json"  # type: ignore
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
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/sessions/{self.session_token}.json"  # type: ignore
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.ONEZONE_IA
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/sessions/{self.session_token}.json"  # type: ignore
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
    session: Union[MemberSessionRedacted, None] = Field(default=None)
    client: Union[ClientRedacted, None] = Field(default=None)
    account: Union[MemberAccountRedacted, None] = Field(default=None)
    member: Union[MemberProfileRedacted, None] = Field(default=None)
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

    def load(self, member_email: Union[EmailStr, None] = None, subject: Union[str, None] = None) -> Union['Support', None]:
        if subject:
            self.subject = subject
        if member_email:
            self.member = MemberProfile(email=member_email).load()  # type: ignore
        clean_subject = ''.join(e for e in '-'.join(self.subject.split()).replace('/', '-').lower() if e.isalnum() or e == '-')
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/support/{clean_subject}.json"  # type: ignore
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
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/support/{clean_subject}.json"  # type: ignore
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        clean_subject = ''.join(e for e in '-'.join(self.subject.split()).replace('/', '-').lower() if e.isalnum() or e == '-')
        object_key = f"{internals.APP_ENV}/accounts/{self.member.account.name}/members/{self.member.email}/support/{clean_subject}.json"  # type: ignore
        return services.aws.delete_s3(object_key)

class DefaultInfo(BaseModel):
    generator: str = Field(default="trivialscan")
    version: Union[str, None] = Field(default=None, description="trivialscan CLI version")
    account_name: Union[str, None] = Field(default=None, description="Trivial Security account name")
    client_name: Union[str, None] = Field(default=None, description="Machine name where trivialscan CLI execcutes")

class ConfigDefaults(BaseModel):
    use_sni: bool
    cafiles: Union[str, None] = Field(default=None)
    tmp_path_prefix: str = Field(default="/tmp")
    http_path: str = Field(default="/")
    checkpoint: Optional[bool]

class ConfigOutput(BaseModel):
    type: OutputType
    use_icons: Union[bool, None]
    when: OutputWhen = Field(default=OutputWhen.FINAL)
    path: Union[str, None] = Field(default=None)

class ConfigTarget(BaseModel):
    hostname: str
    port: PositiveInt = Field(default=443)
    client_certificate: Union[str, None] = Field(default=None)
    http_request_paths: list[str] = Field(default=["/"])

class Config(BaseModel):
    account_name: Union[str, None] = Field(default=None, description="Trivial Security account name")
    client_name: Union[str, None] = Field(default=None, description="Machine name where trivialscan CLI execcutes")
    project_name: Union[str, None] = Field(default=None, description="Trivial Scanner project assignment for the report")
    defaults: ConfigDefaults
    outputs: list[ConfigOutput]
    targets: list[ConfigTarget]

class Flags(BaseModel):
    hide_progress_bars: Optional[bool]
    synchronous_only: Optional[bool]
    hide_banner: Optional[bool]
    track_changes: Optional[bool]
    previous_report: Union[str, None]
    quiet: Optional[bool]

class HostTLSProtocol(BaseModel):
    negotiated: str
    preferred: str
    offered: list[str]

class HostTLSCipher(BaseModel):
    forward_anonymity: Union[bool, None] = Field(default=False)
    offered: list[str]
    offered_rfc: list[str]
    negotiated: str
    negotiated_bits: PositiveInt
    negotiated_rfc: str

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
    status_code: conint(ge=100, le=599)  # type: ignore
    headers: dict[str, str]
    body_hash: str

class HostTransport(BaseModel):
    hostname: str = Field(title="Domain Name")
    port: PositiveInt = Field(default=443)
    sni_support: Optional[bool]
    peer_address: Optional[IPvAnyAddress]
    certificate_mtls_expected: Union[bool, None] = Field(default=False)

class Host(BaseModel, DAL):
    error: Optional[tuple[str, str]]
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
            self.transport = HostTransport(hostname=hostname, port=port, peer_address=peer_address)  # type: ignore

        prefix_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}"
        if self.transport.peer_address and self.last_updated:
            scan_date = self.last_updated.strftime("%Y%m%d")
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
        scan_date = self.last_updated.strftime("%Y%m%d")  # type: ignore
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
        scan_date = self.last_updated.strftime("%Y%m%d")  # type: ignore
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/{self.transport.peer_address}/{scan_date}.json"
        return services.aws.delete_s3(object_key)

class Certificate(BaseModel, DAL):
    authority_key_identifier: Union[str, None] = Field(default=None)
    expired: Optional[bool]
    expiry_status: Optional[str]
    extensions: Optional[list] = Field(default=[])
    external_refs: Optional[dict[str, Union[AnyHttpUrl, None]]] = Field(default={})
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
    validation_level: Union[ValidationLevel, None] = Field(default=None)
    validation_oid: Union[str, None] = Field(default=None)
    version: Optional[Any] = Field(default=None)
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
    url: Union[AnyHttpUrl, None]

class ReportSummary(DefaultInfo, DAL):
    report_id: str
    project_name: Union[str, None]
    targets: Optional[list[str]]
    date: Optional[datetime]
    execution_duration_seconds: Union[PositiveFloat, None] = Field(default=None)
    score: int = Field(default=0)
    results: Optional[dict[str, int]]
    certificates: list[str] = Field(default=[])
    results_uri: Optional[str]
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

class EvaluationItem(DefaultInfo):
    class Config:
        validate_assignment = True
    report_id: str
    rule_id: str
    group_id: str
    key: str
    name: str
    group: str
    observed_at: Union[datetime, None] = Field(default=None)
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

    def exists(self, report_id: Union[str, None] = None, account_name: Union[str, None] = None) -> bool:
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        return services.aws.object_exists(object_key)

    def load(self, report_id: Union[str, None] = None, account_name: Union[str, None] = None) -> Union['FullReport', None]:
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name

        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing FullReport {object_key}")
            return
        data = json.loads(raw)
        if data:
            super().__init__(**data)
        return self

    def save(self) -> bool:
        results: list[bool] = []
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        results.append(services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
        ))
        return all(results)

    def delete(self) -> bool:
        if not self.exists():
            return False
        results: list[bool] = []
        prefix_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/"
        for item in self.evaluations:  # type: ignore
            object_key = f"{prefix_key}{item.group_id}/{item.rule_id}.json"
            results.append(services.aws.delete_s3(object_key))

        return all(results)

class EmailEditRequest(BaseModel):
    email: EmailStr

class NameEditRequest(BaseModel):
    name: str

class MemberInvitationRequest(BaseModel):
    email: EmailStr

class AcceptEdit(BaseModel, DAL):
    account: Optional[MemberAccount]
    requester: Optional[MemberProfile]
    accept_token: str
    old_value: Optional[Any]
    new_value: Optional[Any]
    change_model: Optional[str]
    change_prop: Optional[str]
    model_key: Optional[str]
    model_value: Optional[str]
    ip_addr: Union[IPvAnyAddress, None] = Field(default=None)
    user_agent: Union[str, None] = Field(default=None)
    timestamp: Union[int, None] = Field(default=None)
    sendgrid_message_id: Union[str, None] = Field(default=None)

    def exists(self, accept_token: Union[str, None] = None) -> bool:
        return self.load(accept_token) is not None

    def load(self, accept_token: Union[str, None] = None) -> Union['AcceptEdit', None]:
        if accept_token:
            self.accept_token = accept_token
        object_key = f"{internals.APP_ENV}/accept-links/{self.accept_token}.json"
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing AcceptEdit {object_key}")
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
        object_key = f"{internals.APP_ENV}/accept-links/{self.accept_token}.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        )

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

class MonitorRecord(BaseModel):
    port: int
    date_checked: datetime
    http_paths: list[str]
    report_id: str

class MonitorHostname(BaseModel):
    hostname: str
    timestamp: int
    enabled: bool = Field(default=False)
    history: list[MonitorRecord] = Field(default=[])

class Monitor(BaseModel, DAL):
    account: Optional[MemberAccount]
    targets: list[MonitorHostname] = Field(default=[])

    def exists(self, account_name: Union[str, None] = None) -> bool:
        return self.load(account_name) is not None

    def load(self, account_name: Union[str, None] = None) -> Union['Monitor', None]:
        if account_name:
            self.account = MemberAccount(name=account_name).load()  # type: ignore
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/monitor.json"  # type: ignore
        raw = services.aws.get_s3(object_key)
        if not raw:
            internals.logger.warning(f"Missing Monitor {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(
                f"Missing Monitor {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/monitor.json"  # type: ignore
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.account.name}/monitor.json"  # type: ignore
        return services.aws.delete_s3(object_key)
