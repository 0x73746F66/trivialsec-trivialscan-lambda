import contextlib
import hashlib
import json
from time import time
from datetime import datetime, timedelta, timezone
from random import random
from typing import Union
from secrets import token_urlsafe
from uuid import uuid4
from ipaddress import ip_address

import validators
import jwt
import geocoder
from geocoder.location import Location
from user_agents import parse as ua_parser
from fastapi import Header, APIRouter, Response, status, Depends, HTTPException
from starlette.requests import Request
from cachier import cachier
from boto3.dynamodb.conditions import Key
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json,
)
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
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
        203: {
            "description": "Access Controls/Authorization was not checked, only the provided Access Token was checked to be valid according to the authorisation_valid property"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
    },
    tags=["CLI"],
)
async def validate_authorization(
    request: Request,
    authorization: str = Header(
        alias="Authorization", title="Contained JWT", default=""
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
            "client": authz.client.name if hasattr(authz, "client") else None,
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
    if not sessions:
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
                fido_devices.append(models.MemberFidoPublic(**fido.dict()))
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
        return Response(status_code=status.HTTP_204_NO_CONTENT)
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
    ip_addr = None
    with contextlib.suppress(ValueError):
        ip_addr = ip_address(
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
    if not user_agent:
        return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)
    if validators.email(data.email) is not True:  # type: ignore
        return Response(status_code=status.HTTP_400_BAD_REQUEST)

    member = models.MemberProfile(email=data.email)
    if not member.load():
        return Response(status_code=status.HTTP_412_PRECONDITION_FAILED)

    if member.mfa:
        account = models.MemberAccount(name=member.account_name)  # type: ignore pylint: disable=no-member
        if not account.load() or not account.load_billing():
            internals.logger.info(
                f'"magic_link","","{member.email}","{ip_addr}","{user_agent}",""'
            )
            return Response(status_code=status.HTTP_400_BAD_REQUEST)

        fido_devices: list[models.MemberFido] = []
        for item in services.aws.query_dynamodb(
            table_name=services.aws.Tables.MEMBER_FIDO,
            IndexName="member_email-index",
            KeyConditionExpression=Key("member_email").eq(member.email),
        ):
            if data := services.aws.get_dynamodb(
                table_name=services.aws.Tables.MEMBER_FIDO,
                item_key={"record_id": item["record_id"]},
            ):  # type: ignore
                fido = models.MemberFido(**data)  # type: ignore
                if fido.device_id:
                    fido_devices.append(fido)

        if fido_devices:
            try:
                authentication_options = internals.fido.authenticate(
                    [
                        PublicKeyCredentialDescriptor(
                            id=base64url_to_bytes(device.device_id)  # type: ignore
                        )
                        for device in fido_devices
                    ]
                )
                for device in fido_devices:
                    device.challenge = bytes_to_base64url(
                        authentication_options.challenge
                    )
                    device.save()
                response.status_code = status.HTTP_200_OK
                return json.loads(options_to_json(authentication_options))
            except InvalidAuthenticationResponse as err:
                internals.logger.exception(err)

    magic_token = hashlib.sha224(bytes(str(random()), "ascii")).hexdigest()
    login_url = f"{internals.DASHBOARD_URL}/login/{magic_token}"
    try:
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

    except RuntimeError as err:
        internals.logger.exception(err)
        return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    response.status_code = status.HTTP_424_FAILED_DEPENDENCY


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
    response: Response,
    request: Request,
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
    object_key = f"{internals.APP_ENV}/magic-links/{magic_token}.json"
    try:
        ret = services.aws.get_s3(path_key=object_key)
        if not ret:
            internals.logger.info(f'"login","","","{ip_addr}","{user_agent}",""')
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        link = models.MagicLink(**json.loads(ret))
        if not link:
            internals.logger.info(f'"login","","","{ip_addr}","{user_agent}",""')
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        member = models.MemberProfile(email=link.email)
        if not member.load():
            internals.logger.info(
                f'"login","","{link.email}","{ip_addr}","{user_agent}",""'
            )
            return Response(status_code=status.HTTP_400_BAD_REQUEST)
        internals.logger.info(
            f'"login","{member.account_name}","{link.email}","{ip_addr}","{user_agent}",""'  # pylint: disable=no-member
        )
        account = models.MemberAccount(name=member.account_name)  # type: ignore pylint: disable=no-member
        if not account.load() or not account.load_billing():
            internals.logger.info(
                f'"login","","{link.email}","{ip_addr}","{user_agent}",""'
            )
            return Response(status_code=status.HTTP_400_BAD_REQUEST)

    except RuntimeError as err:
        internals.logger.exception(err)
        return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    internals.logger.info(
        f'"login","{member.account_name}","{link.email}","{ip_addr}","{user_agent}",""'  # pylint: disable=no-member
    )
    if not user_agent:
        return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)

    confirmed_registration = False
    try:
        parsed_ua = ua_parser(user_agent)
        internals.logger.info(
            f"Session inputs; {member.email} | {parsed_ua.get_browser()} | {parsed_ua.get_os()} | {parsed_ua.get_device()}"
        )
        session_token = hashlib.sha224(
            bytes(
                f"{member.email}{parsed_ua.get_browser()}{parsed_ua.get_os()}{parsed_ua.get_device()}",
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
        session.browser = parsed_ua.get_browser()
        session.platform = (
            "Postman"
            if session.browser.startswith("PostmanRuntime")
            else f"{parsed_ua.get_os()} {parsed_ua.get_device()}"
        )
        if ip_addr:
            geo_ip: Location = geocoder.ip(str(ip_addr))
            session.lat = geo_ip.lat
            session.lon = geo_ip.lng

        past_sessions = filter(
            lambda past_session: past_session.ip_addr == session.ip_addr,
            [
                models.MemberSessionForList(
                    **services.aws.get_dynamodb(  # type: ignore
                        table_name=services.aws.Tables.LOGIN_SESSIONS,
                        item_key={"session_token": item["session_token"]},
                    )
                )
                for item in services.aws.query_dynamodb(
                    table_name=services.aws.Tables.LOGIN_SESSIONS,
                    IndexName="member_email-index",
                    KeyConditionExpression=Key("member_email").eq(member.email),
                )
            ],
        )

        if not session.save():
            return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        if member.confirmation_token == magic_token:
            member.confirmed = True
            confirmed_registration = True
        if not member.save() or not link.delete():
            return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if not list(past_sessions):
            sendgrid = services.sendgrid.send_email(
                recipient=member.email,
                subject="Login from a new location",
                template="login_location",
                data={
                    "browser": session.browser,
                    "platform": session.platform,
                    "ip_addr": ip_addr,
                    "lon": session.lon,
                    "lat": session.lat,
                },
            )
            if sendgrid._content:  # pylint: disable=protected-access
                res = json.loads(
                    sendgrid._content.decode()  # pylint: disable=protected-access
                )
                if isinstance(res, dict) and res.get("errors"):
                    internals.logger.error(res.get("errors"))
                    return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)

    except RuntimeError as err:
        internals.logger.exception(err)
        return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
    fido_options = None
    fido_devices: list[models.MemberFido] = []
    if not confirmed_registration:
        for item in services.aws.query_dynamodb(
            table_name=services.aws.Tables.MEMBER_FIDO,
            IndexName="member_email-index",
            KeyConditionExpression=Key("member_email").eq(member.email),
        ):
            if data := services.aws.get_dynamodb(
                table_name=services.aws.Tables.MEMBER_FIDO,
                item_key={"record_id": item["record_id"]},
            ):
                fido = models.MemberFido(**data)
                if fido.device_id:
                    fido_devices.append(fido)
                    continue
                if fido.created_at < datetime.now(tz=timezone.utc) - timedelta(minutes=5):  # type: ignore
                    fido.delete()

    try:
        if fido_devices:
            authentication_options = internals.fido.authenticate(
                [
                    PublicKeyCredentialDescriptor(
                        id=base64url_to_bytes(device.device_id)
                    )
                    for device in fido_devices
                    if device.device_id
                ]
            )
            for device in fido_devices:
                device.challenge = bytes_to_base64url(authentication_options.challenge)
                device.save()
            fido_options = json.loads(options_to_json(authentication_options))
    except InvalidAuthenticationResponse as err:
        internals.logger.exception(err)

    bearer_token = None
    if not fido_devices:
        # no MFA just log me in
        bearer_token = jwt.encode(
            payload={
                "iat": datetime.now(tz=timezone.utc),
                "nbf": datetime.now(tz=timezone.utc)
                + timedelta(
                    seconds=3
                ),  # S3 is eventually consistent, give it a few seconds..
                "exp": datetime.now(tz=timezone.utc) + timedelta(days=1),
                "aud": ["urn:trivialsec:authz:api:jwt-bearer"],
                "iss": internals.DASHBOARD_URL,
                "sub": internals.NAMESPACE.hex,
                "acc": account.name,  # this is the only custom claim needed
            },
            key=session.access_token,  # type: ignore
            algorithm="HS256",
            headers={"kid": session_token},
        )
        # SameSite cookie is useful for API only, i.e. Postman testing
        cookie_name = (
            f"__Host-{internals.ORIGIN_HOST}-jwt-bearer"
            if internals.APP_ENV == "Prod"
            else "jwt-bearer"
        )
        response.set_cookie(
            key=cookie_name,
            value=bearer_token,
            expires=datetime.now(tz=timezone.utc) + timedelta(days=1),
            secure=internals.APP_ENV == "Prod",
            httponly=True,
            samesite="strict",
        )

    return models.LoginResponse(
        session=models.MemberSessionRedacted(**session.dict()),
        member=models.MemberProfileRedacted(**member.dict()),
        account=models.MemberAccountRedacted(**account.dict()),
        fido_options=fido_options,
        bearer_token=bearer_token,
    )


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
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    if models.MemberProfile(email=data.email).exists():
        return Response(status_code=status.HTTP_409_CONFLICT)
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
                return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)

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
            return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)
        model: models.DAL = _cls(**{link.model_key: link.model_value})  # type: ignore
        if not model:
            return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)
        if not hasattr(model, "load"):
            return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)
        model.load()
        old_value = getattr(model, link.change_prop)  # type: ignore
        if link.old_value != old_value:
            return Response(status_code=status.HTTP_208_ALREADY_REPORTED)
        setattr(model, link.change_prop, link.new_value)  # type: ignore
        if not model.save():
            return Response(status_code=status.HTTP_400_BAD_REQUEST)
        if link.change_model == "MemberProfile" and link.model_key == "email":
            old_member = models.MemberProfile(email=link.old_value)
            if old_member.load():
                old_account = models.MemberAccount(name=old_member.account_name)  # type: ignore pylint: disable=no-member
                if not old_account.load():
                    return Response(status_code=status.HTTP_400_BAD_REQUEST)
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
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    try:
        if models.MemberProfile(email=data.email).exists():
            return Response(status_code=status.HTTP_409_CONFLICT)
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
            return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
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
                return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)
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
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    member = models.MemberProfile(email=email)
    if not member.load() or member.account_name != authz.account.name:
        return Response(status_code=status.HTTP_403_FORBIDDEN)
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

    return Response(status_code=status.HTTP_412_PRECONDITION_FAILED)


@router.get(
    "/webauthn/register",
    response_model=PublicKeyCredentialCreationOptions,
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
        record_id = uuid4()
        options = internals.fido.register(authz.member.email, record_id)
        mfa = models.MemberFido(
            record_id=record_id,
            member_email=authz.member.email,
            challenge=bytes_to_base64url(options.challenge),
            created_at=datetime.now(tz=timezone.utc),
        )  # type: ignore
        if mfa.save():
            return options
    except InvalidRegistrationResponse as ex:
        internals.logger.warning(ex, exc_info=True)
    response.status_code = status.HTTP_412_PRECONDITION_FAILED


@router.post(
    "/webauthn/enroll/{device_name}",
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
    device_name: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Complete Webauthn FIDO enrollment
    """
    credentials = json.dumps(data.dict(), default=str)
    mfa = models.MemberFido(
        record_id=data.record_id,
        member_email=authz.member.email,
    )  # type: ignore
    if not mfa.load():
        return Response(status_code=status.HTTP_404_NOT_FOUND)
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
        if result := internals.fido.register_verification(
            credentials, base64url_to_bytes(mfa.challenge), require_user_verification=False  # type: ignore
        ):
            mfa.device_id = bytes_to_base64url(result.credential_id)
            mfa.public_key = bytes_to_base64url(result.credential_public_key)
            mfa.device_name = device_name
            if mfa.device_id in registered_devices:
                return Response(status_code=status.HTTP_409_CONFLICT)
            if not mfa.save():
                return Response(status_code=status.HTTP_412_PRECONDITION_FAILED)
            if authz.member.mfa is not True:
                authz.member.mfa = True
                authz.member.save()
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
    device = models.MemberFido(member_email=authz.member.email, record_id=record_id)  # type: ignore
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

    if not fido_devices:
        authz.member.mfa = False
        authz.member.save()


@router.post(
    "/webauthn/login",
    response_model=models.LoginResponse,
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
async def webauthn_verify(
    response: Response, request: Request, data: models.WebauthnLogin
):
    """
    Webauthn FIDO verification
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

    member = models.MemberProfileRedacted(email=data.member_email)  # type: ignore
    if not member.load():
        internals.logger.info(
            f'"login","","{member.email}","{ip_addr}","{user_agent}",""'
        )
        return Response(status_code=status.HTTP_400_BAD_REQUEST)
    account = models.MemberAccount(name=member.account_name)  # type: ignore pylint: disable=no-member
    if not account.load() or not account.load_billing():
        internals.logger.info(
            f'"login","","{member.email}","{ip_addr}","{user_agent}",""'
        )
        return Response(status_code=status.HTTP_400_BAD_REQUEST)

    if not user_agent:
        return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)

    match = False
    success = False
    for item in services.aws.query_dynamodb(
        table_name=services.aws.Tables.MEMBER_FIDO,
        IndexName="member_email-index",
        KeyConditionExpression=Key("member_email").eq(member.email),
    ):
        if _data := services.aws.get_dynamodb(
            table_name=services.aws.Tables.MEMBER_FIDO,
            item_key={"record_id": item["record_id"]},
        ):
            fido = models.MemberFido(**_data)
            if fido.device_id == data.id and fido.challenge and fido.public_key:
                match = True
                try:
                    if success := internals.fido.authenticate_verify(
                        challenge=base64url_to_bytes(fido.challenge),
                        public_key=base64url_to_bytes(fido.public_key),
                        credential_json=json.dumps(data.dict(), default=str),
                    ):
                        break
                except InvalidAuthenticationResponse as ex:
                    internals.logger.warning(ex, exc_info=True)

    parsed_ua = ua_parser(user_agent)
    internals.logger.info(
        f"Session inputs; {member.email} | {parsed_ua.get_browser()} | {parsed_ua.get_os()} | {parsed_ua.get_device()}"
    )
    session_token = hashlib.sha224(
        bytes(
            f"{member.email}{parsed_ua.get_browser()}{parsed_ua.get_os()}{parsed_ua.get_device()}",
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
    session.browser = parsed_ua.get_browser()
    session.platform = (
        "Postman"
        if session.browser.startswith("PostmanRuntime")
        else f"{parsed_ua.get_os()} {parsed_ua.get_device()}"
    )
    if ip_addr:
        geo_ip: Location = geocoder.ip(str(ip_addr))
        session.lat = geo_ip.lat
        session.lon = geo_ip.lng

    past_sessions = filter(
        lambda past_session: past_session.ip_addr == session.ip_addr,
        [
            models.MemberSessionForList(
                **services.aws.get_dynamodb(  # type: ignore
                    table_name=services.aws.Tables.LOGIN_SESSIONS,
                    item_key={"session_token": item["session_token"]},
                )
            )
            for item in services.aws.query_dynamodb(
                table_name=services.aws.Tables.LOGIN_SESSIONS,
                IndexName="member_email-index",
                KeyConditionExpression=Key("member_email").eq(member.email),
            )
        ],
    )
    if not session.save():
        return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    if not match:
        internals.logger.info(
            f'"webauthn_verify","","{member.email}","{ip_addr}","{user_agent}",""'
        )
        return Response(status_code=status.HTTP_403_FORBIDDEN)
    if not success:
        internals.logger.info(
            f'"webauthn_verify","","{member.email}","{ip_addr}","{user_agent}",""'
        )
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    if not list(past_sessions):
        sendgrid = services.sendgrid.send_email(
            recipient=member.email,
            subject="Login from a new location",
            template="login_location",
            data={
                "browser": session.browser,
                "platform": session.platform,
                "ip_addr": ip_addr,
                "lon": session.lon,
                "lat": session.lat,
            },
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(
                sendgrid._content.decode()  # pylint: disable=protected-access
            )
            if isinstance(res, dict) and res.get("errors"):
                internals.logger.error(res.get("errors"))
                return Response(status_code=status.HTTP_424_FAILED_DEPENDENCY)

    bearer_token = jwt.encode(
        payload={
            "iat": datetime.now(tz=timezone.utc),
            "nbf": datetime.now(tz=timezone.utc)
            + timedelta(
                seconds=3
            ),  # S3 is eventually consistent, give it a few seconds..
            "exp": datetime.now(tz=timezone.utc) + timedelta(days=1),
            "aud": ["urn:trivialsec:authz:api:jwt-bearer"],
            "iss": internals.DASHBOARD_URL,
            "sub": internals.NAMESPACE.hex,
            "acc": account.name,  # this is the only custom claim needed
        },
        key=session.access_token,  # type: ignore
        algorithm="HS256",
        headers={"kid": session_token},
    )
    # SameSite cookie is useful for API only, i.e. Postman testing
    cookie_name = (
        f"__Host-{internals.ORIGIN_HOST}-jwt-bearer"
        if internals.APP_ENV == "Prod"
        else "jwt-bearer"
    )
    response.set_cookie(
        key=cookie_name,
        value=bearer_token,
        expires=datetime.now(tz=timezone.utc) + timedelta(days=1),
        secure=internals.APP_ENV == "Prod",
        httponly=True,
        samesite="strict",
    )
    return models.LoginResponse(
        session=models.MemberSessionRedacted(**session.dict()),
        member=models.MemberProfileRedacted(**member.dict()),
        account=models.MemberAccountRedacted(**account.dict()),
        bearer_token=bearer_token,
    )  # type: ignore
