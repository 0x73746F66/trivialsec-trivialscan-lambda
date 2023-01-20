import hashlib
import json
from time import time
from random import random
from secrets import token_urlsafe

import validators
from fastapi import APIRouter, Response, status, Depends
from starlette.requests import Request
from pydantic import AnyHttpUrl

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
    )
    if not account.name:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    if not ip_addr or not user_agent:
        internals.logger.warning(f"ip_addr {ip_addr} user_agent {user_agent}")
    member = models.MemberProfile(
        account=account,
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
        if not account.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        try:
            services.stripe.create_customer(email=account.billing_email)  # type: ignore
        except:
            pass  # pylint: disable=bare-except
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
                sendgrid._content.decode()
            )  # pylint: disable=protected-access
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
            sender_name=authz.account.name,  # type: ignore
            sender=authz.member.email,  # type: ignore
            recipient="support@trivialsec.com",
            template="support",
            data={
                "message": data.message,
                "json": json.dumps(authz.member.dict(), indent=2, default=str, sort_keys=True),  # type: ignore
            },
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()
            )  # pylint: disable=protected-access
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return

        support = models.Support(
            member=authz.member,  # type: ignore
            subject=data.subject,
            message=data.message,
            ip_addr=authz.ip_addr,
            user_agent=authz.user_agent,
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
                "old_email": authz.account.billing_email,  # type: ignore
                "new_email": data.email,
                "modifying_email": authz.member.email,  # type: ignore
                "email_type_message": "account billing email address",
            },
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()
            )  # pylint: disable=protected-access
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return
        internals.logger.info(
            f"sendgrid_message_id {sendgrid.headers.get('X-Message-Id')}"
        )
        authz.account.billing_email = data.email  # type: ignore
        if not authz.account.save() or not authz.account.update_members():  # type: ignore
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        try:
            services.stripe.create_customer(email=authz.account.billing_email)  # type: ignore
        except:  # pylint: disable=bare-except
            pass
        services.webhook.send(
            event_name=models.WebhookEvent.ACCOUNT_ACTIVITY,
            account=authz.account,
            data={
                "type": "update_billing_email",
                "timestamp": round(time() * 1000),
                "account": authz.account.name,
                "member": authz.member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent,
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
                "old_email": authz.account.primary_email,  # type: ignore
                "new_email": data.email,
                "modifying_email": authz.member.email,  # type: ignore
                "email_type_message": "account primary contact email address",
            },
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()
            )  # pylint: disable=protected-access
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return
        internals.logger.info(
            f"sendgrid_message_id {sendgrid.headers.get('X-Message-Id')}"
        )
        authz.account.primary_email = data.email  # type: ignore
        if not authz.account.save() or not authz.account.update_members():  # type: ignore
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
                "user_agent": authz.user_agent,
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
        authz.account.display = data.name  # type: ignore
        if not authz.account.save() or not authz.account.update_members():  # type: ignore
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
                "user_agent": authz.user_agent,
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
        setattr(authz.account.notifications, event_type, True)  # type: ignore
        if authz.account.save():  # type: ignore
            return authz.account.notifications  # type: ignore
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
        setattr(authz.account.notifications, event_type, False)  # type: ignore
        if authz.account.save():  # type: ignore
            return authz.account.notifications  # type: ignore
    except AttributeError:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


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
    for _webhook in authz.account.webhooks:
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
            }
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
    for webhook in authz.account.webhooks:
        if endpoint == webhook.endpoint:
            found = True
            continue
        webhooks.append(webhook)
    authz.account.webhooks = webhooks
    if found and authz.account.save():
        return True

    return False
