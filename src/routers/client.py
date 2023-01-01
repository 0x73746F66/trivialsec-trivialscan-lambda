import json
from os import path
from time import time
from datetime import timedelta
from secrets import token_urlsafe
from typing import Union

from fastapi import Header, APIRouter, Response, status, Depends
import validators
from cachier import cachier

import internals
import models
import services.sendgrid
import services.stripe
import services.aws
import services.helpers

router = APIRouter()


@router.post(
    "/claim/{client_name}",
    response_model=models.Client,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"description": "The client name must not be an email address"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        409: {"description": "This client name has already been registered"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Client", "CLI"],
)
async def claim_client(
    response: Response,
    client_name: str,
    client_info: models.ClientInfo,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Generates an access token for provided *NEW* client name.
    Client names must be unique, if the corresponding registration token was lost a new client and token must be created.
    """
    # api_key Auth
    if validators.email(client_name) is True:  # type: ignore
        internals.logger.warning(f"Email {client_name} can not be used for client name")
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    try:
        if models.Client(account=authz.account, name=client_name).exists():  # type: ignore
            response.status_code = status.HTTP_409_CONFLICT
            return

        client = models.Client(
            account=authz.account,
            client_info=client_info,
            name=client_name,
            cli_version=x_trivialscan_version,
            access_token=token_urlsafe(nbytes=32),
            ip_addr=authz.ip_addr,
            user_agent=authz.user_agent,
            timestamp=round(time() * 1000),  # JavaScript support
        )
        if client.save():
            return client
    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


@router.post(
    "/auth/{client_name}",
    response_model=models.CheckToken,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"description": "The client name must not be an email address"},
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
    tags=["Client", "CLI"],
)
async def auth_client(
    response: Response,
    client_name: str,
    client_info: models.ClientInfo,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Authenticates the generated access token and client
    """
    if validators.email(client_name) is True:  # type: ignore
        internals.logger.warning(f"Email {client_name} can not be used for client name")
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    try:
        authz.client.client_info = client_info  # type: ignore
        authz.client.cli_version = x_trivialscan_version  # type: ignore
        authz.client.ip_addr = authz.ip_addr  # type: ignore
        authz.client.user_agent = authz.user_agent  # type: ignore
        if authz.client.save():  # type: ignore
            return {
                "client": authz.client,
                "authorisation_valid": authz.is_valid,
            }
    except RuntimeError as err:
        internals.logger.exception(err)

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


@router.get(
    "/clients",
    response_model=list[models.ClientRedacted],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No client name exists for this account"},
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
    tags=["Member Account", "Client"],
)
@cachier(
    stale_after=timedelta(seconds=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name,
)
def retrieve_clients(
    response: Response,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a collection of your clients
    """
    object_keys = []
    data = []
    try:
        prefix_key = path.join(internals.APP_ENV, "accounts", authz.account.name, "client-tokens")  # type: ignore
        object_keys = services.aws.list_s3(prefix_key=prefix_key)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return []

    if not object_keys:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    for object_key in object_keys:
        if not object_key.endswith(".json"):
            continue
        try:
            ret = services.aws.get_s3(path_key=object_key)
            if not ret:
                continue
            item = json.loads(ret)
            if isinstance(item, dict):
                data.append(item)
        except RuntimeError as err:
            internals.logger.exception(err)
            continue

    return data


@router.get(
    "/activate/{client_name}",
    response_model=models.ClientRedacted,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "Client name does not exists for this account"},
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
    tags=["Member Account", "Client"],
)
async def activate_client(
    response: Response,
    client_name: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Activate a activated client
    """
    client = models.Client(account=authz.account, name=client_name).load()  # type: ignore
    if not client:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    if client.active is not True:
        client.active = True
        if not client.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return

    return client


@router.get(
    "/deactivated/{client_name}",
    response_model=models.ClientRedacted,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "Client name does not exists for this account"},
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
    tags=["Member Account", "Client"],
)
async def deactivated_client(
    response: Response,
    client_name: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Deactivate a client
    """
    client = models.Client(account=authz.account, name=client_name).load()  # type: ignore
    if not client:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    if client.active is not False:
        client.active = False
        if not client.save():
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return

    return client


@router.delete(
    "/client/{client_name}",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        400: {"description": "The client name cannot be an email address"},
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
    tags=["Member Account", "Client"],
)
async def delete_client(
    response: Response,
    client_name: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Deletes a specific MemberProfile within the same account as the authorized requester
    """
    if validators.email(client_name) is True:  # type: ignore
        response.status_code = status.HTTP_400_BAD_REQUEST
        return
    client = models.Client(account=authz.account, name=client_name).load()  # type: ignore
    if not client:
        return Response(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    if authz.account.name != client.account.name:  # type: ignore
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return

    return client.delete()
