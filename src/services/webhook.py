from datetime import datetime

import validators

import internals
import models


def send(event_name: models.WebhookEvent, account: models.MemberAccount, data: dict):
    if account.webhooks.webhook_endpoint and validators.url(account.webhooks.webhook_endpoint) is not True:  # type: ignore
        internals.logger.info(f"Webhooks not enabled for {account.name}")
        return
    if not hasattr(account.webhooks, event_name.value):
        internals.logger.warning(f"Invalid webhook event {event_name}")
        return
    if getattr(account.webhooks, event_name.value) is True:
        internals.logger.info(f"Sending webhook event {event_name}")
        payload = models.WebhookPayload(
            event_name=event_name,
            timestamp=datetime.utcnow(),
            payload=data
        )
        internals.post_beacon(
            url=account.webhooks.webhook_endpoint,  # type: ignore
            body=payload.dict(),
        )
