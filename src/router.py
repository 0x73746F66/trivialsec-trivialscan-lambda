import logging
import json
from os import path
from secrets import token_urlsafe
from typing import Union

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request

import utils

logger = logging.getLogger("uvicorn.default")
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
    """
    Checks registration status of the provided account name, client name, and registration token
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    return {
        "account": x_trivialscan_account,
        "client": x_trivialscan_client,
        "token": x_trivialscan_token,
        "registered": utils.is_registered(
            account_name=x_trivialscan_account,
            trivialscan_client=x_trivialscan_client,
            provided_token=x_trivialscan_token
        ),
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
    """
    Generates an account registration token for provided *NEW* client name.
    Client names must be unique, if the coresponding registration token was lost a new client and token must be created.
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    logger.info(
        f'"{x_trivialscan_account}","{client_name}","{utils.__trivialscan_version__}","{x_forwarded_for}","{ip_addr}"'
    )
    object_key = f"{utils.APP_ENV}/{x_trivialscan_account}/client-tokens/{client_name}"
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
        logger.exception(err)
        return err
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.get("/summary/{report_hash}", status_code=status.HTTP_200_OK)
async def retrieve_summary(
    response: Response,
    report_hash: str,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
):
    """

    """
    if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
        response.status_code = status.HTTP_403_FORBIDDEN
        return

    summary_key = path.join(utils.APP_ENV, x_trivialscan_account, "results", x_trivialscan_token, report_hash, "summary.json")
    try:
        ret = utils.get_s3(
            bucket_name=utils.STORE_BUCKET,
            path_key=summary_key,
        )
        if not ret:
            response.status_code = status.HTTP_404_NOT_FOUND
            return
        data = json.loads(ret)
        if data.get("config").get("token"):
            del data["config"]["token"]
        if data.get("config").get("dashboard_api_url"):
            del data["config"]["dashboard_api_url"]
        return data

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        logger.exception(err)
        return err

@router.get("/reports", status_code=status.HTTP_200_OK)
async def retrieve_reports(
    response: Response,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
):
    """

    """
    if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
        response.status_code = status.HTTP_403_FORBIDDEN
        return

    summary_keys = []
    data = []
    prefix_key = path.join(utils.APP_ENV, x_trivialscan_account, "results", x_trivialscan_token)
    try:
        summary_keys = utils.list_s3(
            bucket_name=utils.STORE_BUCKET,
            prefix_key=prefix_key,
        )
        if not summary_keys:
            response.status_code = status.HTTP_404_NOT_FOUND
            return

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        logger.exception(err)
        return err

    for summary_key in summary_keys:
        try:
            ret = utils.get_s3(
                bucket_name=utils.STORE_BUCKET,
                path_key=summary_key,
            )
            if not ret:
                response.status_code = status.HTTP_404_NOT_FOUND
                return
            item = json.loads(ret)
            if item.get("config"):
                del item["config"]
            if item.get("flags"):
                del item["flags"]
            data.append(item)
        except RuntimeError as err:
            logger.exception(err)
            continue

    return data

@router.get("/host/{hostname}", status_code=status.HTTP_200_OK)
async def retrieve_host(
    response: Response,
    hostname: str,
    port: int = 443,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
):
    if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
        response.status_code = status.HTTP_403_FORBIDDEN
        return

    host_key = path.join(utils.APP_ENV, "hosts", hostname, str(port), "latest.json")
    try:
        ret = utils.get_s3(
            bucket_name=utils.STORE_BUCKET,
            path_key=host_key,
        )
        if not ret:
            response.status_code = status.HTTP_404_NOT_FOUND
            return

        return json.loads(ret)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        logger.exception(err)
        return err

@router.get("/certificate/{sha1_fingerprint}", status_code=status.HTTP_200_OK)
async def retrieve_certificate(
    response: Response,
    sha1_fingerprint: str,
    include_pem: bool = False,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
):
    if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
        response.status_code = status.HTTP_403_FORBIDDEN
        return

    pem_key = path.join(utils.APP_ENV, "certificates", f"{sha1_fingerprint}.pem")
    cert_key = path.join(utils.APP_ENV, "certificates", f"{sha1_fingerprint}.json")
    try:
        ret = utils.get_s3(
            bucket_name=utils.STORE_BUCKET,
            path_key=cert_key,
        )
        if not ret:
            response.status_code = status.HTTP_404_NOT_FOUND
            return
        if include_pem:
            ret["pem"] = utils.get_s3(
                bucket_name=utils.STORE_BUCKET,
                path_key=pem_key,
            )

        return json.loads(ret)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        logger.exception(err)
        return err

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

    try:
        account_name = data["config"]["account_name"]
        client_name = data["config"]["client_name"]
        registration_token = data["config"]["token"]
        if not utils.is_registered(account_name, client_name, registration_token):
            response.status_code = status.HTTP_403_FORBIDDEN
            return
        del data["config"]["token"]
        if data.get("config").get("dashboard_api_url"):
            del data["config"]["dashboard_api_url"]
        utils.store_public(data)
        result_id = token_urlsafe(56)
        summary_key = path.join(utils.APP_ENV, account_name, "results", registration_token, result_id, "summary.json")
        dashboard_api_url = utils.DASHBOARD_API_URL if not data.get("config").get("dashboard_api_url") else data["config"]["dashboard_api_url"]
        results_url = f"{dashboard_api_url}/result/{result_id}"
        if utils.store_s3(
            bucket_name=utils.STORE_BUCKET,
            path_key=summary_key,
            value=utils.make_summary(data),
            StorageClass='STANDARD_IA'
        ):
            return {"results_url": results_url}
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.exception(err)
        return err
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
