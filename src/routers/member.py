import hashlib
import json
from time import time
from datetime import datetime, timedelta, timezone
from random import random
from typing import Union
from secrets import token_urlsafe
from uuid import uuid4

import geocoder
import validators
from user_agents import parse as ua_parser
from fastapi import Header, APIRouter, Response, status, Depends, HTTPException
from starlette.requests import Request
from cachier import cachier
from boto3.dynamodb.conditions import Key
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
from webauthn.helpers.exceptions import (
    # InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)

import internals
import models
import services.aws
import services.sendgrid
import services.stripe
import services.helpers
import services.webhook

router = APIRouter()


@router.get(
    "/validate",
    response_model=models.CheckToken,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION,
    responses={
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
    },
    tags=["CLI"],
)
async def validate_authorization(
    request: Request,
    authorization: str = Header(
        alias="Authorization", title="HMAC-SHA512 Signed Request"
    ),
    x_trivialscan_account: Union[str, None] = Header(
        default=None, alias="X-Trivialscan-Account", title="CLI Client Token hint"
    ),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Checks registration status of the provided account name, client name, and access token (or API key)
    """
    try:
        authz = await internals.auth_required(
            request, authorization, x_trivialscan_account
        )
    except HTTPException:
        event = request.scope.get("aws.event", {})
        authz = internals.Authorization(
            request=request,
            user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
            ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
            account_name=x_trivialscan_account,
        )
    services.webhook.send(
        event_name=models.WebhookEvent.CLIENT_ACTIVITY,
        account=authz.account,
        data={
            "type": "client_info",
            "timestamp": round(time() * 1000),
            "account": authz.account.name,
            "member": authz.member.email if hasattr(authz, "member") else None,
            "client": authz.client.name if hasattr(authz.client, "name") else None,
            "ip_addr": authz.ip_addr,
            "user_agent": authz.user_agent.ua_string,
        },
    )
    return {
        "version": x_trivialscan_version,
        "account": authz.account,
        "client": authz.client if hasattr(authz, "client") else None,
        "member": authz.member if hasattr(authz, "member") else None,
        "session": authz.session if hasattr(authz, "session") else None,
        "authorisation_valid": authz.is_valid,
        "ip_addr": authz.ip_addr,
        "user_agent": authz.user_agent.ua_string,
    }


@router.get(
    "/me",
    response_model=models.MyProfile,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
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
    tags=["Member Profile"],
)
@cachier(
    stale_after=timedelta(seconds=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name,
)
def member_profile(
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Return Member Profile for authorized user
    """
    authz.account.load_billing()
    return models.MyProfile(
        session=authz.session,  # type: ignore
        member=authz.member,  # type: ignore
        account=authz.account,  # type: ignore
    )


@router.get(
    "/sessions",
    response_model=models.MemberSecurity,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No session data available, this is probably an error"},
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
    tags=["Member Profile"],
)
async def member_sessions(
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Return active sessions for the current authorized user
    """
    sessions = [
        models.MemberSessionForList(
            **services.aws.get_dynamodb(  # type: ignore
                table_name=services.aws.Tables.LOGIN_SESSIONS,
                item_key={"session_token": item["session_token"]},
            )
        )
        for item in services.aws.query_dynamodb(
            table_name=services.aws.Tables.LOGIN_SESSIONS,
            IndexName="member_email-index",
            KeyConditionExpression=Key("member_email").eq(authz.member.email),
        )
    ]
    if len(sessions) == 0:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    for session in sessions:
        session.current = session.session_token == authz.session.session_token

    fido_devices = []
    for item in services.aws.query_dynamodb(
        table_name=services.aws.Tables.MEMBER_FIDO,
        IndexName="member_email-index",
        KeyConditionExpression=Key("member_email").eq(authz.member.email),
    ):
        if data := services.aws.get_dynamodb(
            table_name=services.aws.Tables.MEMBER_FIDO,
            item_key={"record_id": item["record_id"]},
        ):
            fido = models.MemberFido(**data)
            if fido.device_id:
                fido_devices.append(
                    models.MemberFidoPublic(**fido.dict())
                )  # TODO: send only the data needed for FIDO, and UI display
                continue
            if fido.created_at < datetime.now(tz=timezone.utc) - timedelta(minutes=5):  # type: ignore
                fido.delete()

    return models.MemberSecurity(sessions=sessions, fido_devices=fido_devices)


@router.get(
    "/members",
    response_model=list[models.MemberProfileForList],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No members, this is probably an error"},
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
    tags=["Member Profile"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name,
)
def list_members(
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Return registered members
    """
    prefix_key = f"{internals.APP_ENV}/accounts/{authz.member.account_name}/members/"
    members: list[models.MemberProfileForList] = []
    prefix_matches = services.aws.list_s3(prefix_key=prefix_key)
    if len(prefix_matches) == 0:
        return []
    for object_path in prefix_matches:
        if not object_path.endswith("profile.json"):
            continue
        if raw := services.aws.get_s3(path_key=object_path):
            members.append(models.MemberProfileForList(**json.loads(raw)))
    if not members:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    for member in members:
        member.current = member.email == authz.member.email
    return members


@router.delete(
    "/revoke/{session_token}",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        204: {"description": "No matching session, was it already revoked?"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        424: {
            "description": "Everything appeared to be correct until actually attempting to revoke the session, probably a race condition with simultaneous revoke attempts"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Profile"],
)
async def revoke_session(
    response: Response,
    session_token: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Revoke an active login session
    """
    session = models.MemberSession(member_email=authz.member.email, session_token=session_token)  # type: ignore
    if not session.load():
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    if not session.delete():
        response.status_code = status.HTTP_424_FAILED_DEPENDENCY
    services.webhook.send(
        event_name=models.WebhookEvent.MEMBER_ACTIVITY,
        account=authz.account,
        data={
            "type": "revoke_session",
            "timestamp": round(time() * 1000),
            "account": authz.account.name,
            "member": authz.member.email,
            "session_token": session_token,
            "ip_addr": authz.ip_addr,
            "user_agent": authz.user_agent.ua_string,
        },
    )


@router.post(
    "/magic-link",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "Not a valid email address"},
        412: {"description": "The email address is not confirmed"},
        424: {"description": "The email address is not registered"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Profile"],
)
async def magic_link(
    request: Request,
    response: Response,
    data: models.MagicLinkRequest,
):
    """
    Creates an email with the magic link for login
    """
    event = request.scope.get("aws.event", {})
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
    if validators.email(data.email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    magic_token = hashlib.sha224(bytes(str(random()), "ascii")).hexdigest()
    login_url = f"{internals.DASHBOARD_URL}/login/{magic_token}"
    try:
        member = models.MemberProfile(email=data.email)
        if member.load():
            if not member.confirmed:
                response.status_code = status.HTTP_412_PRECONDITION_FAILED
                return
            sendgrid_message_id = None
            if not request.headers.get("Postman-Token"):
                sendgrid = services.sendgrid.send_email(
                    recipient=data.email,
                    subject="Trivial Security Magic Link",
                    template="magic_link",
                    data={"magic_link": login_url},
                )
                sendgrid_message_id = sendgrid.headers.get("X-Message-Id")
            link = models.MagicLink(
                email=data.email,
                magic_token=magic_token,
                ip_addr=ip_addr,
                user_agent=user_agent,
                timestamp=round(time() * 1000),
                sendgrid_message_id=sendgrid_message_id,
            )
            if link.save():
                internals.logger.info(
                    f"Magic Link for {member.account_name}"
                )  # pylint: disable=no-member
                return f"/login/{link.magic_token}"

        response.status_code = status.HTTP_424_FAILED_DEPENDENCY
        return

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return


@router.get(
    "/magic-link/{magic_token}",
    response_model=models.LoginResponse,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {
            "description": "The one-time use magic link no longer exists, probably not a bug if it is already used"
        },
        400: {"description": "The email address is not registered"},
        424: {"description": "The User-Agent was invalid"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Profile"],
)
async def login(
    request: Request,
    response: Response,
    magic_token: str,
):
    """
    Login for members with magic link emailed to them
    """
    event = request.scope.get("aws.event", {})
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
    try:
        object_key = f"{internals.APP_ENV}/magic-links/{magic_token}.json"
        ret = services.aws.get_s3(path_key=object_key)
        if not ret:
            internals.logger.info(f'"","","{ip_addr}","{user_agent}",""')
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        link = models.MagicLink(**json.loads(ret))
        if not link:
            internals.logger.info(f'"","","{ip_addr}","{user_agent}",""')
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        member = models.MemberProfile(email=link.email)
        if not member.load():
            response.status_code = status.HTTP_400_BAD_REQUEST
            internals.logger.info(f'"","{link.email}","{ip_addr}","{user_agent}",""')
            return
        internals.logger.info(
            f'"{member.account_name}","{link.email}","{ip_addr}","{user_agent}",""'  # pylint: disable=no-member
        )
        account = models.MemberAccount(name=member.account_name)  # type: ignore pylint: disable=no-member
        if not account.load() or not account.load_billing():
            response.status_code = status.HTTP_400_BAD_REQUEST
            internals.logger.info(f'"","{link.email}","{ip_addr}","{user_agent}",""')
            return
        internals.logger.info(
            f'"{member.account_name}","{link.email}","{ip_addr}","{user_agent}",""'  # pylint: disable=no-member
        )
        if not user_agent:
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            return
        ua = ua_parser(user_agent)
        session_token = hashlib.sha224(
            bytes(
                f"{member.email}{ua.get_browser()}{ua.get_os()}{ua.get_device()}",
                "ascii",
            )
        ).hexdigest()
        session = models.MemberSession(
            member_email=member.email,
            session_token=session_token,
            access_token=token_urlsafe(nbytes=23),
            ip_addr=ip_addr,
            user_agent=user_agent,
            timestamp=round(time() * 1000),
        )  # type: ignore
        session.browser = ua.get_browser()
        session.platform = (
            "Postman"
            if session.browser.startswith("PostmanRuntime")
            else f"{ua.get_os()} {ua.get_device()}"
        )
        if ip_addr:
            geo_ip = geocoder.ip(str(ip_addr))
            session.lat = geo_ip.latlng[0]
            session.lon = geo_ip.latlng[1]
        if not session.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        if member.confirmation_token == magic_token:
            member.confirmed = True
        if member.save() and link.delete():
            services.webhook.send(
                event_name=models.WebhookEvent.MEMBER_ACTIVITY,
                account=account,
                data={
                    "type": "login",
                    "timestamp": round(time() * 1000),
                    "account": account.name,
                    "member": member.email,
                    "session_token": session_token,
                    "ip_addr": ip_addr,
                    "user_agent": user_agent,
                    "browser": session.browser,
                    "platform": session.platform,
                },
            )
            return models.LoginResponse(
                session=session,  # type: ignore
                member=member,  # type: ignore
                account=account,  # type: ignore
            )
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)


@router.post(
    "/member/email",
    response_model=models.AcceptEdit,
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
        409: {"description": "Member already exists with the desired email address"},
        424: {"description": "Email sending errors were logged"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Profile"],
)
async def update_email(
    response: Response,
    data: models.EmailEditRequest,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Updates the login email address for the current logged in member.
    """
    if validators.email(data.email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    if models.MemberProfile(email=data.email).exists():
        response.status_code = status.HTTP_409_CONFLICT
        return
    try:
        token = hashlib.sha224(bytes(str(random()), "ascii")).hexdigest()
        sendgrid = services.sendgrid.send_email(
            subject="Request to Change Email Address",
            recipient=authz.account.primary_email,  # type: ignore
            template="recovery_request",
            data={
                "accept_url": f"{internals.DASHBOARD_URL}/accept/{token}",
                "old_email": authz.member.email,
                "new_email": data.email,
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

        link = models.AcceptEdit(
            account=authz.account,  # type: ignore
            requester=authz.member,  # type: ignore
            accept_token=token,
            old_value=authz.member.email,
            ip_addr=authz.ip_addr,
            new_value=data.email,
            change_model="MemberProfile",
            change_prop="email",
            model_key="email",
            model_value=authz.member.email,
            user_agent=authz.user_agent.ua_string,
            timestamp=round(time() * 1000),  # JavaScript support
            sendgrid_message_id=sendgrid.headers.get("X-Message-Id"),
        )
        if link.save():
            services.webhook.send(
                event_name=models.WebhookEvent.MEMBER_ACTIVITY,
                account=authz.account,
                data={
                    "type": "change_member_email_request",
                    "timestamp": round(time() * 1000),
                    "account": authz.account.name,
                    "member": authz.member.email,
                    "ip_addr": authz.ip_addr,
                    "user_agent": authz.user_agent.ua_string,
                },
            )
            return link
    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


@router.get(
    "/accept/{token}",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        204: {
            "description": "The one-time use accept link no longer exists, probably not a bug if it is already used"
        },
        208: {"description": "This request has already been accepted"},
        424: {
            "description": "Malformed AcceptEdit, this was an issue when the request was originally generated"
        },
        400: {"description": "Unable to save the requested change, check the log"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Profile"],
)
async def accept_token(
    request: Request,
    response: Response,
    token: str,
):
    """
    Login for members with magic link emailed to them
    """
    try:
        event = request.scope.get("aws.event", {})
        ip_addr = (
            event.get("requestContext", {})
            .get("http", {})
            .get(
                "sourceIp",
                request.headers.get(
                    "X-Forwarded-For", request.headers.get("X-Real-IP")
                ),
            )
        )
        user_agent = (
            event.get("requestContext", {})
            .get("http", {})
            .get("userAgent", request.headers.get("User-Agent"))
        )
        link = models.AcceptEdit(accept_token=token)  # type: ignore
        if not link.load():
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        _cls: models.DAL = getattr(models, link.change_model, None)  # type: ignore
        if not _cls:
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            return
        model: models.DAL = _cls(**{link.model_key: link.model_value})  # type: ignore
        if not model:
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            return
        if not hasattr(model, "load"):
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            return
        model.load()
        old_value = getattr(model, link.change_prop)  # type: ignore
        if link.old_value != old_value:
            response.status_code = status.HTTP_208_ALREADY_REPORTED
            return
        setattr(model, link.change_prop, link.new_value)  # type: ignore
        if not model.save():
            response.status_code = status.HTTP_400_BAD_REQUEST
            return
        if link.change_model == "MemberProfile" and link.model_key == "email":
            old_member = models.MemberProfile(email=link.old_value)
            if old_member.load():
                old_account = models.MemberAccount(name=old_member.account_name)  # type: ignore pylint: disable=no-member
                if not old_account.load():
                    response.status_code = status.HTTP_400_BAD_REQUEST
                    return
                old_member.delete()
                services.webhook.send(
                    event_name=models.WebhookEvent.MEMBER_ACTIVITY,
                    account=old_account,
                    data={
                        "type": "change_member_email_confirm",
                        "timestamp": round(time() * 1000),
                        "account": old_account.name,
                        "old_member": link.old_value,
                        "new_member": link.model_value,
                        "ip_addr": ip_addr,
                        "user_agent": user_agent,
                    },
                )
        return link.delete()

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)


@router.post(
    "/member/invite",
    response_model=models.MemberProfileRedacted,
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
        409: {"description": "Member already exists with the desired email address"},
        424: {"description": "Email sending errors were logged"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Profile"],
)
async def send_member_invitation(
    response: Response,
    data: models.MemberInvitationRequest,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Invites a member to join the organisation
    """
    if validators.email(data.email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    try:
        if models.MemberProfile(email=data.email).exists():
            response.status_code = status.HTTP_409_CONFLICT
            return
        member = models.MemberProfile(
            account_name=authz.account.name,
            email=data.email,
            confirmed=False,
            confirmation_token=hashlib.sha224(
                bytes(str(random()), "ascii")
            ).hexdigest(),
            timestamp=round(time() * 1000),  # JavaScript support
        )
        if not member.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return
        services.sendgrid.upsert_contact(
            recipient_email=member.email, list_name="members"
        )
        activation_url = f"{internals.DASHBOARD_URL}/login/{member.confirmation_token}"
        sendgrid = services.sendgrid.send_email(
            subject="Trivial Security | Member Invitation",
            recipient=data.email,
            cc=authz.member.email,
            template="invitations",
            data={
                "email": data.email,
                "invited_by": authz.member.email,
                "activation_url": activation_url,
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
        link = models.MagicLink(
            email=member.email,
            magic_token=member.confirmation_token,
            timestamp=round(time() * 1000),
            sendgrid_message_id=sendgrid.headers.get("X-Message-Id"),
        )  # type: ignore
        if link.save():
            services.webhook.send(
                event_name=models.WebhookEvent.ACCOUNT_ACTIVITY,
                account=authz.account,
                data={
                    "type": "member_invitation",
                    "timestamp": round(time() * 1000),
                    "account": authz.account.name,
                    "member": authz.member.email,
                    "invitee": member.email,
                    "ip_addr": authz.ip_addr,
                    "user_agent": authz.user_agent.ua_string,
                },
            )
            return member
    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


@router.delete(
    "/member/{email}",
    response_model=bool,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "The email address is not valid"},
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
    tags=["Member Profile"],
)
async def delete_member(
    response: Response,
    email: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Deletes a specific MemberProfile within the same account as the authorized requester
    """
    if validators.email(email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return False
    # specifying the account here enforces only deletion of account linked members
    member = models.MemberProfile(email=email, account_name=authz.account.name)
    # returns True if member doesn't exist
    if member.delete():
        services.webhook.send(
            event_name=models.WebhookEvent.ACCOUNT_ACTIVITY,
            account=authz.account,
            data={
                "type": "member_deleted",
                "timestamp": round(time() * 1000),
                "account": authz.account.name,
                "member": authz.member.email,
                "deleted": member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent.ua_string,
            },
        )
        return True


@router.get(
    "/webauthn/register",
    # response_model=models.AcceptEdit,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    responses={
        412: {"description": "The email address is not valid"},
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
    tags=["Member Profile"],
)
async def webauthn_register(
    response: Response,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Webauthn FIDO registration.
    """
    try:
        options = internals.fido.register(authz.member.email)
        record_id = uuid4()
        challenge_b64 = bytes_to_base64url(options.challenge)
        mfa = models.MemberFido(
            record_id=record_id,
            member_email=authz.member.email,
            challenge=challenge_b64,
            created_at=datetime.now(tz=timezone.utc),
        )  # type: ignore
        if mfa.save():
            return {
                "enrollId": record_id,
                "options": json.loads(options_to_json(options)),
            }
    except InvalidRegistrationResponse as ex:
        internals.logger.warning(ex, exc_info=True)
    response.status_code = status.HTTP_412_PRECONDITION_FAILED


@router.post(
    "/webauthn/enroll/{record_id}/{device_name}",
    response_model=models.MemberFidoPublic,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        409: {"description": "The device is already registered"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Profile"],
)
async def webauthn_enroll(
    response: Response,
    data: models.WebauthnEnroll,
    record_id: str,
    device_name: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Complete Webauthn FIDO enrollment
    """
    mfa = models.MemberFido(
        record_id=record_id,
        member_email=authz.member.email,
    )  # type: ignore
    if not mfa.load():
        response.status_code = status.HTTP_404_NOT_FOUND
        return
    registered_devices = set()
    for item in services.aws.query_dynamodb(
        table_name=services.aws.Tables.MEMBER_FIDO,
        IndexName="member_email-index",
        KeyConditionExpression=Key("member_email").eq(authz.member.email),
    ):
        if _data := services.aws.get_dynamodb(
            table_name=services.aws.Tables.MEMBER_FIDO,
            item_key={"record_id": item["record_id"]},
        ):
            fido = models.MemberFido(**_data)
            if fido.device_id:
                registered_devices.add(fido.device_id)
                continue
            if fido.created_at < datetime.now(tz=timezone.utc) - timedelta(minutes=5):  # type: ignore
                fido.delete()
    try:
        credentials = json.dumps(data.dict(), default=str)
        challenge = base64url_to_bytes(mfa.challenge)  # type: ignore
        if result := internals.fido.register_verification(
            credentials, challenge, require_user_verification=False
        ):
            device_id, public_key = result
            mfa.device_id = bytes_to_base64url(device_id)
            mfa.public_key = bytes_to_base64url(public_key)
            mfa.device_name = device_name
            if mfa.device_id in registered_devices:
                return Response(status_code=status.HTTP_409_CONFLICT)
            if not mfa.save():
                response.status_code = status.HTTP_412_PRECONDITION_FAILED
                return
            authz.member.mfa = True
            if authz.member.save():
                return models.MemberFidoPublic(**mfa.dict())

    except InvalidRegistrationResponse as ex:
        internals.logger.warning(ex, exc_info=True)
    response.status_code = status.HTTP_400_BAD_REQUEST


@router.delete(
    "/webauthn/delete/{record_id}",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        204: {"description": "No matching FIDO device, was it already deleted?"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        424: {
            "description": "Everything appeared to be correct until actually attempting to delete the device record, probably a race condition with simultaneous delete attempts"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Member Profile"],
)
async def delete_fido_device(
    response: Response,
    record_id: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Delete a FIDO device
    """
    device = models.MemberFido(member_email=authz.member.email, record_id=record_id)
    if not device.load():
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    if not device.delete():
        response.status_code = status.HTTP_424_FAILED_DEPENDENCY

    services.webhook.send(
        event_name=models.WebhookEvent.MEMBER_ACTIVITY,
        account=authz.account,
        data={
            "type": "delete_fido_device",
            "timestamp": round(time() * 1000),
            "account": authz.account.name,
            "member": authz.member.email,
            "record_id": record_id,
            "ip_addr": authz.ip_addr,
            "user_agent": authz.user_agent.ua_string,
        },
    )

    fido_devices = set()
    for item in services.aws.query_dynamodb(
        table_name=services.aws.Tables.MEMBER_FIDO,
        IndexName="member_email-index",
        KeyConditionExpression=Key("member_email").eq(authz.member.email),
    ):
        if data := services.aws.get_dynamodb(
            table_name=services.aws.Tables.MEMBER_FIDO,
            item_key={"record_id": item["record_id"]},
        ):
            fido = models.MemberFido(**data)
            if fido.device_id:
                fido_devices.add(fido.device_id)
                continue
            if fido.created_at < datetime.now(tz=timezone.utc) - timedelta(minutes=5):  # type: ignore
                fido.delete()

    if len(fido_devices) == 0:
        authz.member.mfa = False
        authz.member.save()
