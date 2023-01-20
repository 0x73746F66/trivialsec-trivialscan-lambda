# pylint: disable=no-self-argument, arguments-differ
import json
from enum import Enum
from typing import Union, Optional
from decimal import Decimal
from datetime import datetime

from pydantic import BaseModel, Field

import internals
import services.aws
import services.stripe


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
    aggregate_usage: Optional[str]
    interval: RecurringInterval
    interval_count: int
    trial_period_days: Optional[str]
    usage_type: RecurringType


class SubscriptionPrice(BaseModel):
    id: str
    active: bool
    billing_scheme: BillingScheme
    created: int
    currency: SupportedCurrency
    livemode: bool
    metadata: dict = Field(default={})
    nickname: Optional[str]
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
    amount_off: Optional[Decimal]
    created: int
    currency: Optional[SupportedCurrency]
    duration: SubscriptionCouponDuration
    duration_in_months: Optional[int]
    livemode: bool
    max_redemptions: Optional[int]
    metadata: Union[dict, None] = Field(default={})
    name: str
    percent_off: Optional[Decimal]
    redeem_by: int
    times_redeemed: int
    valid: bool


class SubscriptionDiscount(BaseModel):
    id: str
    coupon: SubscriptionCoupon
    customer: str
    end: Optional[int]
    invoice: Optional[str]
    invoice_item: Optional[str]
    promotion_code: str
    start: int
    subscription: str


class SubscriptionPlan(BaseModel):
    id: str
    active: bool
    aggregate_usage: Optional[str]
    amount: Decimal
    amount_decimal: str
    billing_scheme: BillingScheme
    created: int
    currency: SupportedCurrency
    interval: RecurringInterval
    interval_count: int
    livemode: bool
    metadata: Union[dict, None] = Field(default={})
    nickname: Optional[str]
    product: str
    trial_period_days: Optional[int]
    usage_type: RecurringType


class SubscriptionBase(BaseModel):
    id: Optional[str]
    billing_cycle_anchor: Optional[int]
    cancel_at: Optional[int]
    cancel_at_period_end: Optional[bool]
    canceled_at: Optional[int]
    collection_method: Optional[SubscriptionCollectionMethod]
    created: Optional[int]
    currency: Optional[SupportedCurrency]
    current_period_end: Optional[int]
    current_period_start: Optional[int]
    customer: Optional[str]
    days_until_due: Optional[int]
    default_payment_method: Optional[str]
    description: Optional[str]
    discount: Optional[SubscriptionDiscount]
    ended_at: Optional[int]
    latest_invoice: Optional[str]
    livemode: Optional[bool]
    metadata: Union[dict, None] = Field(default={})
    next_pending_invoice_item_invoice: Optional[int]
    pause_collection: Optional[SubscriptionPause]
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
        raise RuntimeWarning(
            "This is not a supported method. Use the Stripe SDK/API to modify payments"
        )

    def delete(self) -> bool:
        raise RuntimeWarning(
            "This is not a supported method. Use the Stripe SDK/API to modify payments"
        )


class SubscriptionAddon(SubscriptionBase):
    def load(self, account_name: str) -> Union["SubscriptionAddon", None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError("Subscription.load missing account_name")

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.UNLIMITED_RESCANS}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(path_key=match)
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
            if data.get("livemode") and data.get("status") in [
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.TRIALING,
            ]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get("created")))
        if res:
            super().__init__(**res[-1])
            return self


class SubscriptionBasics(SubscriptionBase):
    def load(self, account_name: str) -> Union["SubscriptionBasics", None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError("Subscription.load missing account_name")

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.BASICS}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(path_key=match)
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
            if data.get("livemode") and data.get("status") in [
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.TRIALING,
            ]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get("created")))
        if res:
            super().__init__(**res[-1])
            return self


class SubscriptionPro(SubscriptionBase):
    def load(self, account_name: str) -> Union["SubscriptionPro", None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError("Subscription.load missing account_name")

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.PROFESSIONAL}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(path_key=match)
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
            if data.get("livemode") and data.get("status") in [
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.TRIALING,
            ]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get("created")))
        if res:
            super().__init__(**res[-1])
            return self


class SubscriptionEnterprise(SubscriptionBase,):
    def load(self, account_name: str) -> Union["SubscriptionEnterprise", None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError("Subscription.load missing account_name")

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.ENTERPRISE}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(path_key=match)
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
            if data.get("livemode") and data.get("status") in [
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.TRIALING,
            ]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get("created")))
        if res:
            super().__init__(**res[-1])
            return self


class SubscriptionUnlimited(SubscriptionBase):
    def load(self, account_name: str) -> Union["SubscriptionUnlimited", None]:
        """
        Derives a Stripe subscription based on having at least one active record
        and returns only the most recent. Any other requirements should load the
        data directly outside this class
        """
        if not account_name:
            raise AttributeError("Subscription.load missing account_name")

        subs = []
        prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/subscriptions/{services.stripe.Product.UNLIMITED}/"
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            raw = services.aws.get_s3(path_key=match)
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
            if data.get("livemode") and data.get("status") in [
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.TRIALING,
            ]:
                subs.append(data)

        res = sorted(subs, key=lambda x: datetime.fromtimestamp(x.get("created")))
        if res:
            super().__init__(**res[-1])
            return self
