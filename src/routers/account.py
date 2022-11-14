import hashlib
import json
from os import path
from time import time
from datetime import timedelta
from random import random
from secrets import token_urlsafe
from typing import Union

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
import validators
from cachier import cachier

import internals
import models
import services.sendgrid
import services.stripe
import services.aws
import services.helpers

router = APIRouter()


@router.post("/account/register",
    response_model=models.MemberProfile,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    responses={
        208: {"description": "The account is already registered"},
        400: {"description": "The display name was not provided or email address is not valid"},
        409: {"description": "The email address has already been registered"},
        424: {"description": "Email sending errors were logged"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
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
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp", request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP")))
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent", request.headers.get("User-Agent"))
    account = models.MemberAccount(
        name=data.name or ''.join(e for e in data.display.lower() if e.isalnum()),
        display=data.display,
        primary_email=data.primary_email,
        billing_email=data.primary_email,
        api_key=token_urlsafe(nbytes=32),
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
        confirmation_token=hashlib.sha224(bytes(str(random()), 'ascii')).hexdigest(),
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
        except: pass  # pylint: disable=bare-except
        services.sendgrid.upsert_contact(recipient_email=member.email, list_name="members")
        activation_url = f"{internals.DASHBOARD_URL}/login/{member.confirmation_token}"
        sendgrid = services.sendgrid.send_email(
            subject="Trivial Security - Confirmation",
            recipient=member.email,
            template='registrations',
            data={
                "activation_url": activation_url
            },
            bcc="support@trivialsec.com",
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(sendgrid._content.decode())  # pylint: disable=protected-access
            if isinstance(res, dict) and res.get('errors'):
                internals.logger.error(res.get('errors'))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return
        link = models.MagicLink(
            email=member.email,
            magic_token=member.confirmation_token,  # type: ignore
            ip_addr=ip_addr,
            user_agent=user_agent,
            timestamp=round(time() * 1000),
            sendgrid_message_id=sendgrid.headers.get('X-Message-Id')
        )
        if link.save():
            return member
    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.post("/support",
    response_model=models.Support,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        424: {"description": "Email sending errors were logged"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Member Account"],
)
async def support_request(
    request: Request,
    response: Response,
    data: models.SupportRequest,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Generates a support request for the logged in member.
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_401_UNAUTHORIZED
        internals.logger.error("Invalid Authorization")
        return
    try:
        sendgrid = services.sendgrid.send_email(
            subject=f"Support | {data.subject}",
            sender_name=authz.member.account.name,  # type: ignore
            sender=authz.member.email,  # type: ignore
            recipient="support@trivialsec.com",
            template='support',
            data={
                "message": data.message,
                "json": json.dumps(authz.member.dict(), indent=2, default=str, sort_keys=True),  # type: ignore
            }
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(sendgrid._content.decode())  # pylint: disable=protected-access
            if isinstance(res, dict) and res.get('errors'):
                internals.logger.error(res.get('errors'))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return

        support = models.Support(
            member=authz.member,  # type: ignore
            subject=data.subject,
            message=data.message,
            ip_addr=authz.ip_addr,
            user_agent=authz.user_agent,
            timestamp=round(time() * 1000),  # JavaScript support
            sendgrid_message_id=sendgrid.headers.get('X-Message-Id')
        )
        if support.save():
            return support
    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.post("/billing/email",
    response_model=models.MemberAccountRedacted,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "The email address is not valid"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        424: {"description": "Email sending errors were logged"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Member Account"],
)
async def update_billing_email(
    request: Request,
    response: Response,
    data: models.EmailEditRequest,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Updates the billing email address for the logged in members account.
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    if validators.email(data.email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_401_UNAUTHORIZED
        internals.logger.error("Invalid Authorization")
        return
    try:
        sendgrid = services.sendgrid.send_email(
            subject="Change of Billing Email Address notice",
            recipient=authz.account.billing_email,  # type: ignore
            cc=data.email,
            template='updated_email',
            data={
                "old_email": authz.account.billing_email,  # type: ignore
                "new_email": data.email,
                "modifying_email": authz.member.email,  # type: ignore
                "email_type_message": "account billing email address",
            }
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(sendgrid._content.decode())  # pylint: disable=protected-access
            if isinstance(res, dict) and res.get('errors'):
                internals.logger.error(res.get('errors'))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return
        internals.logger.info(f"sendgrid_message_id {sendgrid.headers.get('X-Message-Id')}")
        authz.account.billing_email = data.email  # type: ignore
        if not authz.account.save():  # type: ignore
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        try:
            services.stripe.create_customer(email=authz.account.billing_email)  # type: ignore
        except: pass  # pylint: disable=bare-except
        return authz.account

    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.post("/account/email",
    response_model=models.MemberAccountRedacted,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "The email address is not valid"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        424: {"description": "Email sending errors were logged"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Member Account"],
)
async def update_primary_email(
    request: Request,
    response: Response,
    data: models.EmailEditRequest,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Updates the primary contact email address for the account.
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    if validators.email(data.email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get(
            "http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get(
            "http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_401_UNAUTHORIZED
        internals.logger.error("Invalid Authorization")
        return
    try:
        sendgrid = services.sendgrid.send_email(
            subject="Change of Billing Email Address notice",
            recipient=authz.account.primary_email,  # type: ignore
            cc=data.email,
            template='updated_email',
            data={
                "old_email": authz.account.primary_email,  # type: ignore
                "new_email": data.email,
                "modifying_email": authz.member.email,  # type: ignore
                "email_type_message": "account primary contact email address",
            }
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(sendgrid._content.decode())  # pylint: disable=protected-access
            if isinstance(res, dict) and res.get('errors'):
                internals.logger.error(res.get('errors'))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return
        internals.logger.info(f"sendgrid_message_id {sendgrid.headers.get('X-Message-Id')}")
        authz.account.primary_email = data.email  # type: ignore
        if not authz.account.save():  # type: ignore
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        return authz.account

    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.post("/account/display",
    response_model=models.MemberAccountRedacted,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Member Account"],
)
async def update_account_display_name(
    request: Request,
    response: Response,
    data: models.NameEditRequest,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Updates the display name for the account.
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_401_UNAUTHORIZED
        internals.logger.error("Invalid Authorization")
        return
    try:
        authz.account.display = data.name  # type: ignore
        if not authz.account.save() or not authz.account.update_members():  # type: ignore
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        return authz.account

    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
