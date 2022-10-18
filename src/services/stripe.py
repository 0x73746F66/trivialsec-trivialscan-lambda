import json
from enum import Enum
from typing import Union
from datetime import datetime

import stripe
from stripe.error import RateLimitError, APIConnectionError, InvalidRequestError, AuthenticationError, StripeError
from retry.api import retry
from pydantic import EmailStr

import services.aws
import internals
import models

class Product(str, Enum):
    UNLIMITED = "unlimited"
    PROFESSIONAL = "professional"
    COMMUNITY_EDITION = "community_edition"
    ENTERPRISE = "enterprise"
    CONTINUOUS_MONITORING_BOOSTER = "continuous_monitoring_booster"
    UNLIMITED_RESCANS = "unlimited_rescans"

PRODUCT_MAP = {
    'prod_McksvyXK7BHj0d': Product.UNLIMITED,
    'prod_MckkLWvtbYeTdh': Product.PROFESSIONAL,
    'prod_MckImIfrJUilft': Product.COMMUNITY_EDITION,
    'prod_KreCNP6tT8FWp3': Product.ENTERPRISE,
    'prod_Mcl2wa3xDNSTlx': Product.CONTINUOUS_MONITORING_BOOSTER,
    'prod_MckynJ669YGSzx': Product.UNLIMITED_RESCANS,
}
PRODUCTS = {
    Product.UNLIMITED: {
        'id': "prod_McksvyXK7BHj0d",
        'prices': ["price_1LtVMOGZtHTgMn6lbqoePJui"],
    },
    Product.PROFESSIONAL: {
        'id': "prod_MckkLWvtbYeTdh",
        'prices': ["price_1LtVF1GZtHTgMn6lO8JH0vFl", "price_1LtVF1GZtHTgMn6lJuTUrr7M"],
    },
    Product.COMMUNITY_EDITION: {
        'id': "prod_MckImIfrJUilft",
        'prices': ["price_1LtUnoGZtHTgMn6lwciymxvV"],
    },
    Product.ENTERPRISE: {
        'id': "prod_KreCNP6tT8FWp3",
        'prices': [],
    },
    Product.CONTINUOUS_MONITORING_BOOSTER: {
        'id': "prod_Mcl2wa3xDNSTlx",
        'prices': ["price_1LtVWiGZtHTgMn6l7bu4g4kd"],
    },
    Product.UNLIMITED_RESCANS: {
        'id': "prod_MckynJ669YGSzx",
        'prices': ["price_1LtVSlGZtHTgMn6laHNoAjTJ"],
    },
}

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def get_product(product: Product) -> stripe.Product:
    product_id = PRODUCTS[product].get('id')
    try:
        return stripe.Product.retrieve(product_id)

    except InvalidRequestError:
        internals.logger.error(f'[get_product] Invalid parameters were supplied to Stripe API: {product_id}')
    except AuthenticationError:
        internals.logger.error('[get_product] Authentication with Stripe API failed')
    except StripeError as ex:
        internals.logger.exception(ex)
    except Exception as ex:
        internals.logger.exception(ex)

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def get_pricing_by_id(price_id :str) -> stripe.Price:
    try:
        return stripe.Price.retrieve(price_id)

    except InvalidRequestError:
        internals.logger.error(f'[get_pricing_by_id] Invalid parameters were supplied to Stripe API: {price_id}')
    except AuthenticationError:
        internals.logger.error('[get_pricing_by_id] Authentication with Stripe API failed')
    except StripeError as ex:
        internals.logger.exception(ex)
    except Exception as ex:
        internals.logger.exception(ex)

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def create_customer(email :str) -> stripe.Customer:
    try:
        return stripe.Customer.create(
            email=email
        )

    except InvalidRequestError:
        internals.logger.error(f'[create_customer] Invalid parameters were supplied to Stripe API: {email}')
    except AuthenticationError:
        internals.logger.error('[create_customer] Authentication with Stripe API failed')
    except Exception as ex:
        internals.logger.exception(ex)


@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def get_customer(customer_id: str) -> stripe.Customer:
    try:
        return stripe.Customer.retrieve(customer_id)

    except InvalidRequestError:
        internals.logger.error(
            f'[get_customer] Invalid parameters were supplied to Stripe API: {customer_id}')
    except AuthenticationError:
        internals.logger.error('[get_customer] Authentication with Stripe API failed')
    except StripeError as ex:
        internals.logger.exception(ex)
    except Exception as ex:
        internals.logger.exception(ex)


@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def get_invoice(invoice_id: str) -> stripe.Invoice:
    try:
        return stripe.Invoice.retrieve(invoice_id)

    except InvalidRequestError:
        internals.logger.error(
            f'[get_invoice] Invalid parameters were supplied to Stripe API: {invoice_id}')
    except AuthenticationError:
        internals.logger.error('[get_invoice] Authentication with Stripe API failed')
    except StripeError as ex:
        internals.logger.exception(ex)
    except Exception as ex:
        internals.logger.exception(ex)


@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def get_subscription(subscription_id: str) -> stripe.Subscription:
    try:
        return stripe.Subscription.retrieve(subscription_id)

    except InvalidRequestError:
        internals.logger.error(
            f'[get_subscription] Invalid parameters were supplied to Stripe API: {subscription_id}')
    except AuthenticationError:
        internals.logger.error('[get_subscription] Authentication with Stripe API failed')
    except StripeError as ex:
        internals.logger.exception(ex)
    except Exception as ex:
        internals.logger.exception(ex)


def get_account_by_billing_email(billing_email: EmailStr) -> Union[models.MemberAccount, None]:
    prefix_key = f"{internals.APP_ENV}/accounts/"
    matches = services.aws.list_s3(prefix_key)
    for object_path in matches:
        if not object_path.endswith("registration.json"):
            continue
        raw = services.aws.get_s3(object_path)
        data = json.loads(raw)
        account = models.MemberAccount(**data)
        if account.billing_email == str(billing_email):
            return account

class Webhook:
    def __init__(self,
                 api_version: str,
                 event_id: str,
                 created: int,
                 data_object: dict,
                 event_type :str
                 ):
        stripe.api_version = api_version
        stripe.api_key = services.aws.get_ssm(f"/{internals.APP_ENV}/{internals.APP_NAME}/Stripe/secret-key", WithDecryption=True)
        self._api_version = api_version
        self._event_id = event_id
        self._created = datetime.fromtimestamp(created).strftime("%Y%m%d")
        self._data_object = data_object
        self.event_type = event_type
        if data_object.get('customer'):
            self._customer = get_customer(data_object.get('customer'))
            self.account = get_account_by_billing_email(self._customer.get('email'))

    def process(self) -> bool:
        if not hasattr(self, 'account') or not isinstance(self.account, models.MemberAccount):
            return False
        if self.event_type == 'payment_intent.succeeded':
            self._payment_intent_succeeded()
        elif self.event_type.startswith('invoice.'):
            return self._upsert_invoice()
        elif self.event_type.startswith('customer.subscription.'):
            return self._upsert_subscription()
        object_key = f"{internals.APP_ENV}/stripe/{self._created}/{self.event_type}.json"
        internals.logger.warning(f"Webhook [{self.event_type}] not processed {self._event_id}")
        return services.aws.store_s3(
            object_key,
            json.dumps(self._data_object, default=str)
        )

    def _upsert_subscription(self) -> bool:
        results: list[bool] = []
        subscription = get_subscription(self._data_object.get('id'))
        for _item in subscription['items']['data']:
            item = subscription.copy()
            item['subscription_item'] = _item.copy()
            product_id = _item['price']['product']
            results.append(services.aws.store_s3(
                f"{internals.APP_ENV}/accounts/{self.account.name}/subscriptions/{PRODUCT_MAP[product_id]}/{_item.get('id')}.json",
                json.dumps(item, default=str)
            ))
        return all(results)

    def _upsert_invoice(self) -> bool:
        invoice = get_invoice(self._data_object.get('id'))
        created = datetime.fromtimestamp(invoice.get('created')).strftime("%Y%m%d")
        return services.aws.store_s3(
            f"{internals.APP_ENV}/accounts/{self.account.name}/invoices/{created}/{invoice.get('id')}.json",
            json.dumps(invoice.to_dict_recursive(), default=str)
        )

    def _payment_intent_succeeded(self):
        results: list[bool] = []
        for charges_data in self._data_object['charges']['data']:
            created = datetime.fromtimestamp(charges_data.get('created')).strftime("%Y%m%d")
            results.append(services.aws.store_s3(
                f"{internals.APP_ENV}/accounts/{self.account.name}/payments/{created}/{charges_data.get('id')}.json",
                json.dumps(charges_data, default=str)
            ))
        return all(results)
