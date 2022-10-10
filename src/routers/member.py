import hashlib
import json
from time import time
from random import random
from typing import Union
from secrets import token_urlsafe

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
import validators

import utils
import models

router = APIRouter()


@router.get("/validate",
    response_model=models.CheckToken,
    response_model_exclude_unset=True,
    status_code=status.HTTP_202_ACCEPTED,
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
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.Authorization(
        authorization_header=authorization,
        request_url=request.url,
        user_agent=user_agent,
        ip_addr=ip_addr,
        account_name=x_trivialscan_account,
    )

    return {
        "version": x_trivialscan_version,
        "account_name": x_trivialscan_account,
        "account": authz.account,
        "client": authz.client,
        "member": authz.member,
        "session": authz.session,
        "authorisation_valid": authz.is_valid,
        "registered": utils.is_registered(
            account_name=x_trivialscan_account,
            trivialscan_client=None if not authz.client else authz.client.name,
        ),
        "ip_addr": ip_addr,
        "user_agent": user_agent,
    }

@router.get("/me",
    response_model=models.MemberProfile,
    response_model_exclude_unset=True,
    status_code=status.HTTP_200_OK,
)
async def member_profile(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
):
    """
    Return Member Profile for authorized user
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.Authorization(
        authorization_header=authorization,
        request_url=request.url,
        user_agent=user_agent,
        ip_addr=ip_addr,
        account_name=x_trivialscan_account,
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    return authz.member

@router.get("/sessions",
    response_model=list[models.MemberSession],
    response_model_exclude_unset=True,
    status_code=status.HTTP_200_OK,
)
async def member_sessions(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
):
    """
    Return active sessions for the current authorized user
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.Authorization(
        authorization_header=authorization,
        request_url=request.url,
        user_agent=user_agent,
        ip_addr=ip_addr,
        account_name=x_trivialscan_account,
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return
    sessions = utils.load_sessions(authz.member.account.name, authz.member.email)
    if not sessions:
        response.status_code = status.HTTP_404_NOT_FOUND
        return []
    return sessions

@router.post("/magic-link",
    status_code=status.HTTP_202_ACCEPTED
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
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if validators.email(data.email) is not True:
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        return
    magic_token = hashlib.sha224(bytes(f'{random()}{user_agent}{ip_addr}', 'ascii')).hexdigest()
    login_url = f"{utils.DASHBOARD_URL}/login/{magic_token}"
    try:
        if member := utils.load_member(data.email):
            sendgrid = utils.send_email(
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
            if utils.save_magic_link(link):
                utils.logger.info(f"Magic Link for {member.account.name}")
                return f"/login/{link.magic_token}"

        response.status_code = status.HTTP_424_FAILED_DEPENDENCY
        return

    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return

@router.get("/magic-link/{magic_token}",
    response_model=models.MemberSession,
    response_model_exclude_unset=True,
    status_code=status.HTTP_200_OK
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
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    try:
        object_key = f"{utils.APP_ENV}/magic-links/{magic_token}.json"
        ret = utils.get_s3(utils.STORE_BUCKET, object_key)
        if not ret:
            response.status_code = status.HTTP_406_NOT_ACCEPTABLE
            utils.logger.info(
                f'"","","{ip_addr}","{user_agent}",""'
            )
            return
        link = models.MagicLink(**json.loads(ret))
        if not link:
            response.status_code = status.HTTP_404_NOT_FOUND
            utils.logger.info(
                f'"","","{ip_addr}","{user_agent}",""'
            )
            return
        member = utils.load_member(link.email)
        if not member:
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            utils.logger.info(
                f'"","{link.email}","{ip_addr}","{user_agent}",""'
            )
            return
        utils.logger.info(
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
        if not utils.save_member_session(session):
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            return
        if member.confirmation_token == magic_token:
            member.confirmed = True
        if utils.save_member(member):
            return session
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        utils.logger.exception(err)
