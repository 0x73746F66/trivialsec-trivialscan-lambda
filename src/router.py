import logging
import json
from secrets import token_urlsafe
from typing import Union

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request

import utils

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
router = APIRouter()

@router.get("/", status_code=status.HTTP_202_ACCEPTED)
async def check_token_registration(
    request: Request,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
    x_forwarded_for: Union[str, None] = Header(
        default=None, include_in_schema=False),
):
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    object_key = f"/{utils.APP_ENV}/{x_trivialscan_account}/client-tokens/{x_trivialscan_client}"
    register_token = utils.get_s3(
        utils.STORE_BUCKET,
        object_key,
    )
    return {
        "account": x_trivialscan_account,
        "client": x_trivialscan_client,
        "token": x_trivialscan_token,
        "register_token": register_token,
        "registered": register_token == x_trivialscan_token,
        "ip_address": ip_addr,
        "version": utils.__trivialscan_version__,
        "x_forwarded_for": x_forwarded_for,
    }

@router.post("/register/{client_name}", status_code=status.HTTP_200_OK)
async def register_client(
    request: Request,
    response: Response,
    client_name: str,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_forwarded_for: Union[str, None] = Header(default=None, include_in_schema=False),
):
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")

    logger.info(
        f'"{x_trivialscan_account}","{client_name}","{utils.__trivialscan_version__}","{x_forwarded_for}","{ip_addr}"'
    )

    object_key = f"/{utils.APP_ENV}/{x_trivialscan_account}/client-tokens/{client_name}"
    register_token = utils.get_s3(
        utils.STORE_BUCKET,
        object_key,
    )
    if register_token is not None:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"message": f"client {client_name} already registered"}

    register_token = token_urlsafe(nbytes=32)
    try:
        if utils.store_s3(
            utils.STORE_BUCKET,
            object_key,
            register_token,
            StorageClass='STANDARD_IA'
        ):
            return {"token": register_token}
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return err
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.post("/store", status_code=status.HTTP_200_OK)
async def save(
    request: Request,
    response: Response,
):
    json_str = await request.body()
    try:
        data = await request.json()
    except json.decoder.JSONDecodeError:
        _, json_bytes = json_str.split(b"\r\n\r\n")
        json_str = "\n".join(json_bytes.decode().splitlines()[:-1])
        data = json.loads(json_str)

    account_name = data["config"]["account_name"]
    registration_token = data["config"]["token"]
    result_id = token_urlsafe(56)
    object_key = f"/{utils.APP_ENV}/{account_name}/results/{registration_token}/{result_id}"
    results_url = f"https://dashboard.trivialsec.com/result/{result_id}"
    try:
        if utils.store_s3(
            utils.STORE_BUCKET,
            object_key,
            json_str,
            StorageClass='STANDARD_IA'
        ):
            return {"results_url": results_url}
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return err
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
