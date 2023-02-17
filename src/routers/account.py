import contextlib
import hashlib
import json
from time import time
from datetime import timedelta
from random import random
from secrets import token_urlsafe
from uuid import UUID

import validators
from fastapi import APIRouter, Response, status, Depends
from starlette.requests import Request
from pydantic import AnyHttpUrl
from cachier import cachier
from tldextract.tldextract import TLDExtract

import internals
import models
import services.sendgrid
import services.stripe
import services.aws
import services.helpers
import services.webhook

router = APIRouter()


@router.post(
    "/account/register",
    response_model=models.MemberProfile,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    responses={
        208: {"description": "The account is already registered"},
        400: {
            "description": "The display name was not provided or email address is not valid"
        },
        409: {"description": "The email address has already been registered"},
        424: {"description": "Email sending errors were logged"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def account_register(
    request: Request,
    response: Response,
    data: models.AccountRegistration,
):
    """
    Registers an new account
    """
    event = request.scope.get("aws.event", {})
    if not data.display:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    if validators.email(data.primary_email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    if models.MemberProfile(email=data.primary_email).exists():
        response.status_code = status.HTTP_409_CONFLICT
        return
    ip_addr = (
        event.get("requestContext", {})
        .get("http", {})
        .get(
            "sourceIp",
            request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP")),
        )
    )
    user_agent = (
        event.get("requestContext", {})
        .get("http", {})
        .get("userAgent", request.headers.get("User-Agent"))
    )
    account = models.MemberAccount(
        name=data.name or "".join(e for e in data.display.lower() if e.isalnum()),
        display=data.display,
        primary_email=data.primary_email,
        billing_email=data.primary_email,
        api_key=token_urlsafe(nbytes=23),
        ip_addr=ip_addr,
        user_agent=user_agent,
        timestamp=round(time() * 1000),  # JavaScript support
    )  # type: ignore
    if not account.name:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    if not ip_addr or not user_agent:
        internals.logger.warning(f"ip_addr {ip_addr} user_agent {user_agent}")
    member = models.MemberProfile(
        account_name=account.name,
        email=account.primary_email,
        confirmed=False,
        confirmation_token=hashlib.sha224(bytes(str(random()), "ascii")).hexdigest(),
        timestamp=account.timestamp,
    )
    try:
        if models.MemberAccount(name=account.name).exists():  # type: ignore
            response.status_code = status.HTTP_208_ALREADY_REPORTED
            return
        if not member.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        with contextlib.suppress(Exception):
            customer = services.stripe.create_customer(email=account.billing_email)  # type: ignore
            account.billing_client_id = customer.id  # type: ignore
        if not account.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        services.sendgrid.upsert_contact(
            recipient_email=member.email, list_name="members"
        )
        activation_url = f"{internals.DASHBOARD_URL}/login/{member.confirmation_token}"
        sendgrid = services.sendgrid.send_email(
            subject="Registration Confirmation",
            recipient=member.email,
            template="registrations",
            data={"activation_url": activation_url},
            bcc="support@trivialsec.com",
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()  # pylint: disable=protected-access
            )
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return
        link = models.MagicLink(
            email=member.email,
            magic_token=member.confirmation_token,  # type: ignore
            ip_addr=ip_addr,
            user_agent=user_agent,
            timestamp=round(time() * 1000),
            sendgrid_message_id=sendgrid.headers.get("X-Message-Id"),
        )
        _, hostname = member.email.split("@")
        if hostname not in internals.EMAIL_PROVIDERS:
            with contextlib.suppress(Exception):
                queue_name = f"{internals.APP_ENV.lower()}-reconnaissance"
                queued_timestamp = round(time() * 1000)  # JavaScript support
                internals.logger.info(f"queue {queue_name} {hostname}")
                services.aws.store_sqs(
                    queue_name=queue_name,
                    message_body=json.dumps(
                        {
                            "hostname": hostname,
                            "ports": [443],
                            "path_names": ["/"],
                            "type": models.ScanRecordType.MONITORING,
                        },
                        default=str,
                    ),
                    deduplicate=False,
                    account=account.name,
                    queued_by=member.email,
                    queued_timestamp=queued_timestamp,
                )
                queue_name = f"{internals.APP_ENV.lower()}-subdomains"
                internals.logger.info(f"queue {queue_name} {hostname}")
                services.aws.store_sqs(
                    queue_name=queue_name,
                    message_body=json.dumps(
                        {
                            "hostname": TLDExtract(cache_dir=internals.CACHE_DIR)(
                                f"http://{hostname}"
                            ).registered_domain,
                            "type": models.ScanRecordType.SUBDOMAINS,
                        },
                        default=str,
                    ),
                    deduplicate=False,
                    account=account.name,
                    queued_by=member.email,
                    queued_timestamp=queued_timestamp,
                )
        if link.save():
            return member
    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


@router.post(
    "/support",
    response_model=models.Support,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        424: {"description": "Email sending errors were logged"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def support_request(
    response: Response,
    data: models.SupportRequest,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Generates a support request for the logged in member.
    """
    try:
        sendgrid = services.sendgrid.send_email(
            subject=f"Support | {data.subject}",
            sender_name=authz.account.name,
            sender=authz.member.email,
            recipient="support@trivialsec.com",
            template="support",
            data={
                "message": data.message,
                "json": json.dumps(
                    authz.member.dict(), indent=2, default=str, sort_keys=True
                ),
            },
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()  # pylint: disable=protected-access
            )
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return

        support = models.Support(
            member=authz.member,  # type: ignore
            subject=data.subject,
            message=data.message,
            ip_addr=authz.ip_addr,
            user_agent=authz.user_agent.ua_string,
            timestamp=round(time() * 1000),  # JavaScript support
            sendgrid_message_id=sendgrid.headers.get("X-Message-Id"),
        )
        if support.save():
            return support
    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


@router.post(
    "/billing/email",
    response_model=models.MemberAccountRedacted,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "The email address is not valid"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        424: {"description": "Email sending errors were logged"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def update_billing_email(
    response: Response,
    data: models.EmailEditRequest,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Updates the billing email address for the logged in members account.
    """
    if validators.email(data.email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    try:
        sendgrid = services.sendgrid.send_email(
            subject="Change of Billing Email Address notice",
            recipient=authz.account.billing_email,  # type: ignore
            cc=data.email,
            template="updated_email",
            data={
                "old_email": authz.account.billing_email,
                "new_email": data.email,
                "modifying_email": authz.member.email,
                "email_type_message": "account billing email address",
            },
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()  # pylint: disable=protected-access
            )
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return
        internals.logger.info(
            f"sendgrid_message_id {sendgrid.headers.get('X-Message-Id')}"
        )
        authz.account.billing_email = data.email
        with contextlib.suppress(Exception):
            customer = services.stripe.create_customer(
                email=authz.account.billing_email
            )
            authz.account.billing_client_id = customer.id  # type: ignore
        if not authz.account.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        services.webhook.send(
            event_name=models.WebhookEvent.ACCOUNT_ACTIVITY,
            account=authz.account,
            data={
                "type": "update_billing_email",
                "timestamp": round(time() * 1000),
                "account": authz.account.name,
                "member": authz.member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent.ua_string,
            },
        )
        return authz.account

    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


@router.post(
    "/account/email",
    response_model=models.MemberAccountRedacted,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "The email address is not valid"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        424: {"description": "Email sending errors were logged"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def update_primary_email(
    response: Response,
    data: models.EmailEditRequest,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Updates the primary contact email address for the account.
    """
    if validators.email(data.email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    try:
        sendgrid = services.sendgrid.send_email(
            subject="Change of Billing Email Address notice",
            recipient=authz.account.primary_email,  # type: ignore
            cc=data.email,
            template="updated_email",
            data={
                "old_email": authz.account.primary_email,
                "new_email": data.email,
                "modifying_email": authz.member.email,
                "email_type_message": "account primary contact email address",
            },
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()  # pylint: disable=protected-access
            )
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return
        internals.logger.info(
            f"sendgrid_message_id {sendgrid.headers.get('X-Message-Id')}"
        )
        authz.account.primary_email = data.email
        if not authz.account.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        services.webhook.send(
            event_name=models.WebhookEvent.ACCOUNT_ACTIVITY,
            account=authz.account,
            data={
                "type": "update_primary_email",
                "timestamp": round(time() * 1000),
                "account": authz.account.name,
                "member": authz.member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent.ua_string,
            },
        )
        return authz.account

    except RuntimeError as err:
        internals.logger.exception(err)


@router.post(
    "/account/display",
    response_model=models.MemberAccountRedacted,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def update_account_display_name(
    response: Response,
    data: models.NameEditRequest,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Updates the display name for the account.
    """
    try:
        authz.account.display = data.name
        if not authz.account.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        services.webhook.send(
            event_name=models.WebhookEvent.ACCOUNT_ACTIVITY,
            account=authz.account,
            data={
                "type": "update_account_name",
                "timestamp": round(time() * 1000),
                "account": authz.account.name,
                "member": authz.member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent.ua_string,
            },
        )
        return authz.account

    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


@router.get(
    "/notification/enable/{event_type}",
    response_model=models.AccountNotifications,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def enable_notification(
    response: Response,
    event_type: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Enables an email notification event type
    """
    try:
        setattr(authz.account.notifications, event_type, True)
        if authz.account.save():
            return authz.account.notifications
    except AttributeError:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


@router.get(
    "/notification/disable/{event_type}",
    response_model=models.AccountNotifications,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def disable_notification(
    response: Response,
    event_type: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Disables an email notification event type
    """
    try:
        setattr(authz.account.notifications, event_type, False)
        if authz.account.save():
            return authz.account.notifications
    except AttributeError:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


@router.get(
    "/webhook/{event_name}/{event_id}",
    # response_model=models.Webhooks,
    # response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
@cachier(stale_after=timedelta(days=30), cache_dir=internals.CACHE_DIR)
def webhook_event_download(
    event_id: UUID,
    event_name: models.WebhookEvent,
):
    """
    Download webhook event
    """
    prefix_key = f"{internals.APP_ENV}/accounts/"
    suffix_key = f"/webhooks/{event_name}/{event_id}.json"

    prefix_matches = services.aws.list_s3(prefix_key=prefix_key)
    if len(prefix_matches) == 0:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    for object_key in prefix_matches:
        if object_key.endswith(suffix_key):
            return (
                json.loads(raw)
                if (raw := services.aws.get_s3(object_key))
                else Response(status_code=status.HTTP_204_NO_CONTENT)
            )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/webhook/events",
    status_code=status.HTTP_200_OK,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
@cachier(
    stale_after=timedelta(seconds=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name,
)
def webhook_event_logs(
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    webhook event logs
    """
    prefix_key = f"{internals.APP_ENV}/accounts/{authz.member.account_name}/webhooks/"
    logs = []
    prefix_matches = services.aws.list_s3_objects(prefix_key=prefix_key)
    if len(prefix_matches) == 0:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    for item in prefix_matches:
        pieces = item["Key"].split("/")  # type: ignore
        logs.append(
            {
                "event_id": pieces[-1].replace(".json", ""),
                "event_name": pieces[-2],
                "date": item["LastModified"],  # type: ignore
            }
        )
    return logs or Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/webhook/enable",
    response_model=models.Webhooks,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def enable_webhook(
    response: Response,
    webhook: models.Webhooks,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Enables a webhook
    """
    found = False
    changed = False
    webhooks = []
    for _webhook in authz.account.webhooks:  # type: ignore
        if webhook.endpoint == _webhook.endpoint:
            found = True
            changed = True
            # preserve signing secret, clients cannot update this!
            webhook.signing_secret = _webhook.signing_secret
            webhooks.append(webhook)
            continue
        webhooks.append(_webhook)

    if found:
        response.status_code = status.HTTP_206_PARTIAL_CONTENT
    else:
        webhook.signing_secret = token_urlsafe(nbytes=23)
        webhooks.append(webhook)
        changed = True
        sendgrid = services.sendgrid.send_email(
            subject="Webhook Registered",
            recipient=authz.member.email,
            template="webhook_signing_secret",
            data={
                "endpoint": webhook.endpoint,
                "signing_secret": webhook.signing_secret,
            },
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()  # pylint: disable=protected-access
            )
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY

    authz.account.webhooks = webhooks
    if changed and authz.account.save():
        return webhook

    internals.logger.warning(f"found {found} changed {changed}")
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


@router.delete(
    "/webhook",
    response_model=bool,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def delete_webhook(
    endpoint: AnyHttpUrl,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Deletes a webhook
    """
    found = False
    webhooks = []
    for webhook in authz.account.webhooks:  # type: ignore
        if endpoint == webhook.endpoint:
            found = True
            continue
        webhooks.append(webhook)
    authz.account.webhooks = webhooks
    return bool(found and authz.account.save())


@router.delete(
    "/account",
    response_model=bool,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Account"],
)
async def delete_account(
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    DANGER!!!
    Deletes an account, cannot be undone
    """
    prefix_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/"
    prefix_matches = services.aws.list_s3(prefix_key=prefix_key)
    if len(prefix_matches) == 0:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return all(services.aws.delete_s3(object_key) for object_key in prefix_matches)
