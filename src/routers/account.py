import hashlib
import json
from os import path
from time import time
from random import random
from secrets import token_urlsafe
from typing import Union, List

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
import validators

import utils
import models

router = APIRouter()


@router.get("/clients",
    response_model=List[models.Client],
    response_model_exclude_unset=True,
    status_code=status.HTTP_200_OK,
)
async def retrieve_clients(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your clients
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

    object_keys = []
    data = []
    prefix_key = path.join(utils.APP_ENV, "accounts", x_trivialscan_account, "client-tokens")
    try:
        object_keys = utils.list_s3(
            bucket_name=utils.STORE_BUCKET,
            prefix_key=prefix_key,
        )

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        utils.logger.exception(err)
        return []

    if not object_keys:
        response.status_code = status.HTTP_404_NOT_FOUND
        return []

    for object_key in object_keys:
        if not object_key.endswith(".json"):
            continue
        try:
            ret = utils.get_s3(
                bucket_name=utils.STORE_BUCKET,
                path_key=object_key,
            )
            if not ret:
                continue
            item = json.loads(ret)
            if isinstance(item, dict):
                data.append(item)
        except RuntimeError as err:
            utils.logger.exception(err)
            continue

    return data

@router.post("/claim/{client_name}",
    response_model=models.Client,
    response_model_exclude_unset=True,
    status_code=status.HTTP_201_CREATED,
)
async def claim_client(
    request: Request,
    response: Response,
    client_name: str,
    client_info: models.ClientInfo,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Generates an access token for provided *NEW* client name.
    Client names must be unique, if the coresponding registration token was lost a new client and token must be created.
    """
    try:
        event = request.scope.get("aws.event", {})
        ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
        user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
        if not authorization:
            response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return
        if validators.email(client_name) is True:
            utils.logger.warning(f"Email {client_name} can not be used for client name")
            response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            return
        # api_key Auth
        authz = utils.Authorization(
            raw_body=request._body.decode("utf8"),  # pylint: disable=protected-access
            authorization_header=authorization,
            request_url=request.url,
            user_agent=user_agent,
            ip_addr=ip_addr,
            method="POST",
        )
        utils.logger.warning(f"Validating Authorization {authz.is_valid}")
        if not authz.is_valid:
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            utils.logger.error("Invalid Authorization")
            return
        if utils.is_registered(authz.account.name, client_name):
            response.status_code = status.HTTP_409_CONFLICT
            return

        client = models.Client(
            account=authz.account,
            client_info=client_info,
            name=client_name,
            cli_version=x_trivialscan_version,
            access_token=token_urlsafe(nbytes=32),
            ip_addr=ip_addr,
            user_agent=user_agent,
            timestamp=round(time() * 1000), # JavaScript support
        )
        if utils.save_client(client):
            return client
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.post("/account/register",
    response_model=models.MemberProfile,
    response_model_exclude_unset=True,
    status_code=status.HTTP_201_CREATED
)
async def account_register(
    request: Request,
    response: Response,
    data: models.AccountRegistration,
):
    """
    Registers an new account

    Return codes:
        422 The prodided values are not acceptable or not sent
        409 The email address has already been registered
        208 The account is already registered
        503 An exception was encountered and logged
        500 An unexpected and unhandled request path occurred
    """
    event = request.scope.get("aws.event", {})
    if not data.display:
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        return
    if validators.email(data.primary_email) is not True:
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        return
    if utils.member_exists(data.primary_email):
        response.status_code = status.HTTP_409_CONFLICT
        return
    account = models.MemberAccount(
        name=data.name or ''.join(e for e in data.display.lower() if e.isalnum()),
        display=data.display,
        primary_email=data.primary_email,
        billing_email=data.primary_email,
        api_key=token_urlsafe(nbytes=32),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
        user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent"),
        timestamp = round(time() * 1000),  # JavaScript support
    )
    if not account.name:
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        return
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not ip_addr or not user_agent:
        utils.logger.warning(f"ip_addr {ip_addr} user_agent {user_agent}")
    member = models.MemberProfile(
        account=account,
        email=account.primary_email,
        confirmed=False,
        confirmation_token=hashlib.sha224(bytes(f'{random()}{user_agent}{ip_addr}', 'ascii')).hexdigest(),
        ip_addr=ip_addr,
        user_agent=user_agent,
        timestamp=account.timestamp,
    )
    try:
        if utils.is_registered(account.name):
            response.status_code = status.HTTP_208_ALREADY_REPORTED
            return
        if not utils.save_member(member):
            response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            return
        if not utils.save_account(account):
            response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            return
        utils.upsert_contact(recipient_email=member.email, list_name="members")
        activation_url = f"{utils.DASHBOARD_URL}/register/{member.confirmation_token}"
        sendgrid = utils.send_email(
            subject="Trivial Security - Confirmation",
            recipient=member.email,
            template='registrations',
            data={
                "activation_url": activation_url
            }
        )
        link = models.MagicLink(
            email=member.email,
            magic_token=member.confirmation_token,
            ip_addr=ip_addr,
            user_agent=user_agent,
            timestamp=round(time() * 1000),
            sendgrid_message_id=sendgrid.headers.get('X-Message-Id')
        )
        if utils.save_magic_link(link):
            return member
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.post("/support",
    response_model=models.Support,
    response_model_exclude_unset=True,
    status_code=status.HTTP_202_ACCEPTED,
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
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get(
        "http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get(
        "http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.Authorization(
        raw_body=request._body.decode("utf8"),  # pylint: disable=protected-access
        authorization_header=authorization,
        request_url=request.url,
        user_agent=user_agent,
        ip_addr=ip_addr,
        method="POST",
    )
    if not authz.is_valid:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        utils.logger.error("Invalid Authorization")
        return
    try:
        sendgrid = utils.send_email(
            subject=f"Support | {data.subject}",
            sender_name=authz.member.account.name,
            sender=authz.member.email,
            recipient="support@trivialsec.com",
            template='support',
            data={
                "message": data.message,
                "json": json.dumps(authz.member.dict(), indent=2, default=str, sort_keys=True),
            }
        )
        if sendgrid._content:
            res = json.loads(sendgrid._content.decode())
            if isinstance(res, dict) and res.get('errors'):
                utils.logger.error(res.get('errors'))
                response.status_code = status.HTTP_424_FAILED_DEPENDENCY
                return

        support = models.Support(
            member=authz.member,
            subject=data.subject,
            message=data.message,
            ip_addr=ip_addr,
            user_agent=user_agent,
            timestamp=round(time() * 1000),  # JavaScript support
            sendgrid_message_id=sendgrid.headers.get('X-Message-Id')
        )
        if utils.save_support(support):
            return support
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
