import hashlib
import json
from time import time
from random import random
from typing import Union
from secrets import token_urlsafe

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
import validators

import internals
import models
import services.aws
import services.sendgrid

router = APIRouter()


@router.get("/validate",
    response_model=models.CheckToken,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Member Profile"],
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
        account_name=x_trivialscan_account,
    )
    prefix_key = f"{internals.APP_ENV}/accounts/{authz.member.account.name}/members/{authz.member.email}/sessions/"
    sessions = []
    prefix_matches = services.aws.list_s3(prefix_key)
    if len(prefix_matches) == 0:
        return []
    for object_path in prefix_matches:
        raw = services.aws.get_s3(object_path)
        if raw:
            sessions.append(models.MemberSession(**json.loads(raw)))
    return {
        "version": x_trivialscan_version,
        "account": authz.account,
        "client": authz.client,
        "member": authz.member,
        "session": authz.session,
        "sessions": sessions,
        "authorisation_valid": authz.is_valid,
        "ip_addr": authz.ip_addr,
        "user_agent": authz.user_agent,
    }

@router.get("/me",
    response_model=models.MemberProfileRedacted,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Member Profile"],
)
async def member_profile(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Return Member Profile for authorized user
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    return authz.member


@router.get("/sessions",
            response_model=list[models.MemberSessionRedacted],
            response_model_exclude_unset=True,
    response_model_exclude_none=True,
            status_code=status.HTTP_200_OK,
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    prefix_key = f"{internals.APP_ENV}/accounts/{authz.member.account.name}/members/{authz.member.email}/sessions/"
    sessions = []
    prefix_matches = services.aws.list_s3(prefix_key)
    if len(prefix_matches) == 0:
        return []
    for object_path in prefix_matches:
        raw = services.aws.get_s3(object_path)
        if raw:
            sessions.append(models.MemberSession(**json.loads(raw)))
    if not sessions:
        response.status_code = status.HTTP_404_NOT_FOUND
        return []
    return sessions

@router.get("/members",
    response_model=list[models.MemberProfileRedacted],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Member Profile"],
)
async def list_members(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Return registered members
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    prefix_key = f"{internals.APP_ENV}/accounts/{authz.member.account.name}/members/{authz.member.email}/"
    members = []
    prefix_matches = services.aws.list_s3(prefix_key)
    if len(prefix_matches) == 0:
        return []
    for object_path in prefix_matches:
        if not object_path.endswith("profile.json"):
            continue
        raw = services.aws.get_s3(object_path)
        if raw:
            internals.logger.info(raw)
            members.append(models.MemberProfile(**json.loads(raw)))
    if not members:
        response.status_code = status.HTTP_404_NOT_FOUND
        return []
    return members

@router.delete("/revoke/{session_token}",
            status_code=status.HTTP_202_ACCEPTED,
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return
    session = models.MemberSession(member=authz.member, session_token=session_token).load()
    if not session:
        response.status_code = status.HTTP_404_NOT_FOUND
        return
    if not session.delete():
        response.status_code = status.HTTP_424_FAILED_DEPENDENCY

@router.post("/magic-link",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Member Profile"],
)
async def magic_link(
    request: Request,
    response: Response,
    data: models.MagicLinkRequest,
):
    """
    Creates an email with the magic link for login

    Return codes:
        422 The prodided values are not acceptable or not sent
        424 The email address is not registered
        503 An exception was encountered and logged
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp", request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP")))
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent", request.headers.get("User-Agent"))
    if validators.email(data.email) is not True:
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        return
    magic_token = hashlib.sha224(bytes(f'{random()}{user_agent}{ip_addr}', 'ascii')).hexdigest()
    login_url = f"{internals.DASHBOARD_URL}/login/{magic_token}"
    try:
        if member := models.MemberProfile(email=data.email).load():
            sendgrid = services.sendgrid.send_email(
                recipient=data.email,
                subject="Trivial Security Magic Link",
                template='magic_link',
                data={
                    "magic_link": login_url
                }
            )
            link = models.MagicLink(
                email=data.email,
                magic_token=magic_token,
                ip_addr=ip_addr,
                user_agent=user_agent,
                timestamp=round(time() * 1000),
                sendgrid_message_id=sendgrid.headers.get('X-Message-Id')
            )
            if link.save():
                internals.logger.info(f"Magic Link for {member.account.name}")
                return f"/login/{link.magic_token}"

        response.status_code = status.HTTP_424_FAILED_DEPENDENCY
        return

    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        internals.logger.exception(err)
        return

@router.get("/magic-link/{magic_token}",
    response_model=models.MemberSession,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Member Profile"],
)
async def login(
    request: Request,
    response: Response,
    magic_token: str,
):
    """
    Login for members with magic link emailed to them

    Return codes:
        406 The prodided values are not acceptable or not sent
        424 The email address is not registered
        500 An unexpected and unhandled request path occurred
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp", request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP")))
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent", request.headers.get("User-Agent"))
    try:
        object_key = f"{internals.APP_ENV}/magic-links/{magic_token}.json"
        ret = services.aws.get_s3(object_key)
        if not ret:
            response.status_code = status.HTTP_406_NOT_ACCEPTABLE
            internals.logger.info(
                f'"","","{ip_addr}","{user_agent}",""'
            )
            return
        link = models.MagicLink(**json.loads(ret))
        if not link:
            response.status_code = status.HTTP_404_NOT_FOUND
            internals.logger.info(
                f'"","","{ip_addr}","{user_agent}",""'
            )
            return
        member = models.MemberProfile(email=link.email).load()
        if not member:
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            internals.logger.info(
                f'"","{link.email}","{ip_addr}","{user_agent}",""'
            )
            return
        internals.logger.info(
            f'"{member.account.name}","{link.email}","{ip_addr}","{user_agent}",""'
        )
        session_token = hashlib.sha224(bytes(f'{member.email}{ip_addr}{user_agent}', 'ascii')).hexdigest()
        session = models.MemberSession(
            member=member,
            session_token=session_token,
            access_token=token_urlsafe(nbytes=32),
            ip_addr=ip_addr,
            user_agent=user_agent,
            timestamp=round(time() * 1000),
        )
        if not session.save():
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            return
        if member.confirmation_token == magic_token:
            member.confirmed = True
        if member.save():
            return session
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)

@router.post("/member/email",
    # response_model=models.Support,
    # response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Member Account"],
)
async def update_email(
    request: Request,
    response: Response,
    data: models.SupportRequest,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Updates the email address for the logged in member.
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        internals.logger.error("Invalid Authorization")
        return
    try:
        sendgrid = services.sendgrid.send_email(
            subject="Request to Change Email Address",
            recipient=authz.member.account.primary_email,
            template='recovery_request',
            data={
                "accept_url": f"{internals.DASHBOARD_URL}/accept/{hashlib.sha224(bytes(f'{random()}', 'ascii')).hexdigest()}",
                "old_email": authz.member.email,
                "new_email": data.email,
            }
        )
        if sendgrid._content:  # pylint: disable=protected-access
            res = json.loads(sendgrid._content.decode())  # pylint: disable=protected-access
            if isinstance(res, dict) and res.get('errors'):
                internals.logger.error(res.get('errors'))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return

        # support = models.Support(
        #     member=authz.member,
        #     subject=data.subject,
        #     message=data.message,
        #     ip_addr=ip_addr,
        #     user_agent=user_agent,
        #     timestamp=round(time() * 1000),  # JavaScript support
        #     sendgrid_message_id=sendgrid.headers.get('X-Message-Id')
        # )
        # if support.save():
        #     return support
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
