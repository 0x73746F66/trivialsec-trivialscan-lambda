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
    user_agent = event.get("requestContext", {}).get(
        "http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.HMAC(
        authorization_header=authorization,
        request_url=str(request.url),
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","{ip_addr}","{user_agent}","{x_trivialscan_version}"'
    )
    access_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    return {
        "version": x_trivialscan_version,
        "account_name": x_trivialscan_account,
        "client_name": authz.id,
        "authorisation_valid": False if not access_token else authz.validate(access_token),
        "registered": utils.is_registered(
            account_name=x_trivialscan_account,
            trivialscan_client=authz.id,
        ),
        "ip_address": ip_addr,
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
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.HMAC(
        authorization_header=authorization,
        request_url=str(request.url),
    )
    access_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    if not access_token or not authz.validate(access_token):
        response.status_code = status.HTTP_403_FORBIDDEN
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    return utils.load_member(authz.id)

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
            object_key = f"{utils.APP_ENV}/magic-links/{magic_token}.json"
            link = models.MagicLink(
                email=data.email,
                magic_token=magic_token,
                ip_addr=ip_addr,
                user_agent=user_agent,
                timestamp=round(time() * 1000),
                sendgrid_message_id=sendgrid.headers.get('X-Message-Id')
            )
            if utils.store_s3(
                utils.STORE_BUCKET,
                object_key,
                json.dumps(link.dict(), default=str),
                storage_class=utils.StorageClass.STANDARD_IA
            ):
                utils.logger.info(f"Magic Link for {member.account.name}")
                return

        response.status_code = status.HTTP_424_FAILED_DEPENDENCY
        return

    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return

@router.get("/magic-link/{magic_token}",
    response_model=models.MemberProfile,
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
    utils.logger.info(
        f'"","","{ip_addr}","{user_agent}",""'
    )

    try:
        object_key = f"{utils.APP_ENV}/magic-links/{magic_token}.json"
        ret = utils.get_s3(utils.STORE_BUCKET, object_key)
        if not ret:
            response.status_code = status.HTTP_406_NOT_ACCEPTABLE
            return
        link = models.MagicLink(**json.loads(ret))
        member = utils.load_member(link.email)
        if not member:
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            return
        member.access_token = token_urlsafe(nbytes=32)
        if utils.save_member(member):
            return member
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        utils.logger.exception(err)
