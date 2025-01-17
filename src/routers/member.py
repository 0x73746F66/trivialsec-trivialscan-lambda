import hashlib
import json
from time import time
from datetime import timedelta
from random import random
from typing import Union
from secrets import token_urlsafe

import geocoder
import validators
from user_agents import parse as ua_parser
from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
from pydantic import EmailStr
from cachier import cachier

import internals
import models
import services.aws
import services.sendgrid
import services.stripe
import services.helpers

router = APIRouter()


@router.get(
    "/validate",
    response_model=models.CheckToken,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
    },
    tags=["Debug"],
)
async def validate_authorization(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Checks registration status of the provided account name, client name, and access token (or API key)
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
        account_name=x_trivialscan_account,
    )
    return {
        "version": x_trivialscan_version,
        "account": authz.account,
        "client": authz.client,
        "member": authz.member,
        "session": authz.session,
        "authorisation_valid": authz.is_valid,
        "ip_addr": authz.ip_addr,
        "user_agent": authz.user_agent,
    }


@router.get(
    "/me",
    response_model=models.MemberSessionRedacted,
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
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(
        kw["authorization"]
    )["id"],
)
def member_profile(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Return Member Profile for authorized user
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return

    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return

    authz.session.member.account.load_billing()  # type: ignore
    return authz.session


@router.get(
    "/sessions",
    response_model=list[models.MemberSessionRedacted],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No sesson data available, this is probably an error"},
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
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Return active sessions for the current authorized user
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return

    prefix_key = f"{internals.APP_ENV}/accounts/{authz.member.account.name}/members/{authz.member.email}/sessions/"  # type: ignore
    sessions: list[models.MemberSession] = []
    prefix_matches = services.aws.list_s3(prefix_key=prefix_key)
    if len(prefix_matches) == 0:
        return []
    for object_path in prefix_matches:
        raw = services.aws.get_s3(path_key=object_path)
        if raw:
            sessions.append(models.MemberSession(**json.loads(raw)))
    if not sessions:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    for session in sessions:
        session.current = session.session_token == authz.session.session_token  # type: ignore
    return sessions


@router.get(
    "/members",
    response_model=list[models.MemberProfileRedacted],
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
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(
        kw["authorization"]
    )["id"],
)
def list_members(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Return registered members
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return

    prefix_key = f"{internals.APP_ENV}/accounts/{authz.member.account.name}/members/"  # type: ignore
    members: list[models.MemberProfile] = []
    prefix_matches = services.aws.list_s3(prefix_key=prefix_key)
    if len(prefix_matches) == 0:
        return []
    for object_path in prefix_matches:
        if not object_path.endswith("profile.json"):
            continue
        raw = services.aws.get_s3(path_key=object_path)
        if raw:
            members.append(models.MemberProfile(**json.loads(raw)))
    if not members:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    for member in members:
        member.current = member.email == authz.member.email  # type: ignore
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
    request: Request,
    response: Response,
    session_token: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Revoke an active login session
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return
    session = models.MemberSession(member=authz.member, session_token=session_token).load()  # type: ignore
    if not session:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    if not session.delete():
        response.status_code = status.HTTP_424_FAILED_DEPENDENCY


@router.post(
    "/magic-link",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "Not a valid email address"},
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
        if member := models.MemberProfile(email=data.email).load():
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
                internals.logger.info(f"Magic Link for {member.account.name}")  # type: ignore
                return f"/login/{link.magic_token}"

        response.status_code = status.HTTP_424_FAILED_DEPENDENCY
        return

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return


@router.get(
    "/magic-link/{magic_token}",
    response_model=models.MemberSession,
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
        member = models.MemberProfile(email=link.email).load()
        if not member:
            response.status_code = status.HTTP_400_BAD_REQUEST
            internals.logger.info(f'"","{link.email}","{ip_addr}","{user_agent}",""')
            return
        internals.logger.info(
            f'"{member.account.name}","{link.email}","{ip_addr}","{user_agent}",""'  # type: ignore
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
            member=member,
            session_token=session_token,
            access_token=token_urlsafe(nbytes=32),
            ip_addr=ip_addr,
            user_agent=user_agent,
            timestamp=round(time() * 1000),
        )  # type: ignore
        ua = ua_parser(session.user_agent)
        session.browser = ua.get_browser()
        session.platform = f"{ua.get_os()} {ua.get_device()}"
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
            return session
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
    request: Request,
    response: Response,
    data: models.EmailEditRequest,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Updates the login email address for the current logged in member.
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    if validators.email(data.email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    if models.MemberProfile(email=data.email).exists():
        response.status_code = status.HTTP_409_CONFLICT
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return
    try:
        token = hashlib.sha224(bytes(str(random()), "ascii")).hexdigest()
        sendgrid = services.sendgrid.send_email(
            subject="Request to Change Email Address",
            recipient=authz.member.account.primary_email,  # type: ignore
            template="recovery_request",
            data={
                "accept_url": f"{internals.DASHBOARD_URL}/accept/{token}",
                "old_email": authz.member.email,  # type: ignore
                "new_email": data.email,
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

        link = models.AcceptEdit(
            account=authz.account,  # type: ignore
            requester=authz.member,  # type: ignore
            accept_token=token,
            old_value=authz.member.email,  # type: ignore
            ip_addr=authz.ip_addr,
            new_value=data.email,
            change_model="MemberProfile",
            change_prop="email",
            model_key="email",
            model_value=authz.member.email,  # type: ignore
            user_agent=authz.user_agent,
            timestamp=round(time() * 1000),  # JavaScript support
            sendgrid_message_id=sendgrid.headers.get("X-Message-Id"),
        )
        if link.save():
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
        link = models.AcceptEdit(accept_token=token).load()  # type: ignore
        if not link:
            internals.logger.info(f'"","","{ip_addr}","{user_agent}",""')
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        _cls: models.DAL = getattr(models, link.change_model, None)  # type: ignore
        if not _cls:
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            return
        model: models.DAL = _cls(**{link.model_key: link.model_value}).load()  # type: ignore
        old_value = getattr(model, link.change_prop)  # type: ignore
        if link.old_value != old_value:
            response.status_code = status.HTTP_208_ALREADY_REPORTED
            return
        setattr(model, link.change_prop, link.new_value)  # type: ignore
        if not model.save():
            response.status_code = status.HTTP_400_BAD_REQUEST
            return
        if link.change_model == "MemberProfile" and link.model_key == "email":
            if old_member := models.MemberProfile(email=link.old_value).load():
                old_member.delete()
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
    request: Request,
    response: Response,
    data: models.MemberInvitationRequest,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Invites a member to join the organisation
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
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
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_401_UNAUTHORIZED
        internals.logger.error(internals.ERR_INVALID_AUTHORIZATION)
        return
    try:
        if models.MemberProfile(email=data.email).exists():
            response.status_code = status.HTTP_409_CONFLICT
            return
        member = models.MemberProfile(
            account=authz.account,
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
            cc=authz.member.email,  # type: ignore
            template="invitations",
            data={
                "email": data.email,
                "invited_by": authz.member.email,  # type: ignore
                "activation_url": activation_url,
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
        link = models.MagicLink(
            email=member.email,
            magic_token=member.confirmation_token,  # type: ignore
            timestamp=round(time() * 1000),
            sendgrid_message_id=sendgrid.headers.get("X-Message-Id"),
        )
        if link.save():
            return member
    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


@router.delete(
    "/member/{email}",
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
    request: Request,
    response: Response,
    email: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Deletes a specific MemberProfile within the same account as the authorized requester
    """
    if validators.email(email) is not True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return
    member = models.MemberProfile(email=email).load()
    if not member:
        return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    if authz.account.name != member.account.name:  # type: ignore
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return

    return member.delete()
