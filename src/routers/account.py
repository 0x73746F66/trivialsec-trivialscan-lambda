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
    response_model=List[models.ClientOut],
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
    user_agent = event.get("requestContext", {}).get(
        "http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.HMAC(
        authorization_header=authorization,
        request_url=str(request.url),
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","","{ip_addr}","{user_agent}"'
    )
    access_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not access_token:
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_401_UNAUTHORIZED
            return
        if not authz.validate(access_token):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

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
            if item.get("access_token"):
                del item["access_token"]

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
    x_trivialscan_account: Union[str, None] = Header(default=None),
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
        utils.logger.info(
            f'"{x_trivialscan_account}","{client_name}","{ip_addr}","{user_agent}","{x_trivialscan_version}"'
        )
        if not authorization:
            response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return
        if not x_trivialscan_account or not client_name:
            response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            return
        if utils.is_registered(x_trivialscan_account, client_name):
            response.status_code = status.HTTP_409_CONFLICT
            return
        # api_key Auth
        authz = utils.HMAC(
            raw_body=request._body.decode("utf8"),  # pylint: disable=protected-access
            authorization_header=authorization,
            request_url=str(request.url),
            method="POST",
        )
        access_token = utils.retrieve_token(
            account_name=x_trivialscan_account,
            client_name=authz.id,
        )
        if not access_token:
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_401_UNAUTHORIZED
            return
        if not authz.validate(access_token):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return
        object_key = f"{utils.APP_ENV}/accounts/{x_trivialscan_account}/client-tokens/{client_name}.json"
        client = models.Client(
            **client_info.dict(),
            name=client_name,
            cli_version=x_trivialscan_version,
            access_token = token_urlsafe(nbytes=32),
            ip_addr = ip_addr,
            user_agent = user_agent,
            timestamp=round(time() * 1000),  # JavaScript support
        )
        if utils.store_s3(
            utils.STORE_BUCKET,
            object_key,
            json.dumps(client.dict(), default=str),
            storage_class=utils.StorageClass.STANDARD
        ):
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
    utils.logger.warning(f"ip_addr {ip_addr}")
    utils.logger.warning(f"user_agent {user_agent}")
    member = models.MemberProfile(
        account=account,
        email=account.primary_email,
        ip_addr=ip_addr,
        user_agent=user_agent,
        timestamp=account.timestamp
    )
    try:
        if utils.is_registered(account.name):
            response.status_code = status.HTTP_208_ALREADY_REPORTED
            return
        object_key = f"{utils.APP_ENV}/accounts/{account.name}/members/{account.primary_email}/profile.json"
        if not utils.store_s3(
            utils.STORE_BUCKET,
            object_key,
            json.dumps(member.dict(), default=str),
            storage_class=utils.StorageClass.STANDARD
        ):
            response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            return
        member.confirmation_token = hashlib.sha224(bytes(f'{random()}{user_agent}{ip_addr}', 'ascii')).hexdigest()
        object_key = f"{utils.APP_ENV}/accounts/{account.name}/registration.json"
        if utils.store_s3(
            utils.STORE_BUCKET,
            object_key,
            json.dumps(account.dict(), default=str),
            storage_class=utils.StorageClass.STANDARD
        ):
            utils.upsert_contact(recipient_email=member.email, list_name="members")
            activation_url = f"{utils.DASHBOARD_URL}/register/{member.confirmation_token}"
            utils.send_email(
                subject="Trivial Security - Confirmation",
                recipient=member.email,
                template='registrations',
                data={
                    "activation_url": activation_url
                }
            )
            return member
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
