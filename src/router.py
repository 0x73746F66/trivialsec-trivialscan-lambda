import json
from os import path
from secrets import token_urlsafe
from typing import Union
from enum import Enum

from fastapi import Header, APIRouter, Response, File, UploadFile, status
from starlette.requests import Request

import utils

class ReportType(str, Enum):
    HOST = "host"
    CERTIFICATE = "certificate"
    REPORT = "report"
    EVALUATIONS = "evaluations"

router = APIRouter()

@router.get("/check-token", status_code=status.HTTP_202_ACCEPTED)
async def check_token_registration(
    request: Request,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Checks registration status of the provided account name, client name, and registration token
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    utils.logger.info(
        f'"{x_trivialscan_account}","{x_trivialscan_client}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    return {
        "account": x_trivialscan_account,
        "client": x_trivialscan_client,
        "provided_token": x_trivialscan_token,
        "registered": utils.is_registered(
            account_name=x_trivialscan_account,
            trivialscan_client=x_trivialscan_client,
            provided_token=x_trivialscan_token
        ),
        "ip_address": ip_addr,
        "version": x_trivialscan_version,
        "user_agent": user_agent,
    }

@router.post("/register/{client_name}", status_code=status.HTTP_200_OK)
async def register_client(
    request: Request,
    response: Response,
    client_name: str,
    strict_identity: bool = True,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Generates an account registration token for provided *NEW* client name.
    Client names must be unique, if the coresponding registration token was lost a new client and token must be created.
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    utils.logger.info(
        f'"{x_trivialscan_account}","{client_name}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    if not x_trivialscan_account or not client_name:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    try:
        data = await request.json()
        utils.logger.debug(data)
        if isinstance(data, str):
            data = json.loads(data)
    except json.decoder.JSONDecodeError:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    try:
        if utils.is_reserved(x_trivialscan_account, client_name):
            response.status_code = status.HTTP_403_FORBIDDEN
            return {"message": f"client {client_name} already registered"}
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    object_key = f"{utils.APP_ENV}/{x_trivialscan_account}/client-tokens/{client_name}"
    data["register_token"] = token_urlsafe(nbytes=32)
    data["ip_addr"] = ip_addr
    data["user_agent"] = user_agent
    data["cli_version"] = x_trivialscan_version
    data["strict_identity"] = strict_identity
    try:
        if utils.store_s3(
            utils.STORE_BUCKET,
            object_key,
            json.dumps(data, default=str),
            StorageClass='STANDARD_IA'
        ):
            return {"token": data["register_token"]}
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return err

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.get("/summary/{report_hash}", status_code=status.HTTP_200_OK)
async def retrieve_summary(
    request: Request,
    response: Response,
    report_hash: str,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """

    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    utils.logger.info(
        f'"{x_trivialscan_account}","{x_trivialscan_client}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    try:
        if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

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
        utils.logger.exception(err)
        return err

@router.get("/report/{report_hash}", status_code=status.HTTP_200_OK)
async def retrieve_report(
    request: Request,
    response: Response,
    report_hash: str,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """

    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    utils.logger.info(
        f'"{x_trivialscan_account}","{x_trivialscan_client}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    try:
        if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    summary_key = path.join(utils.APP_ENV, x_trivialscan_account, "results", x_trivialscan_token, report_hash, "summary.json")
    evaluations_key = path.join(utils.APP_ENV, x_trivialscan_account, "results", x_trivialscan_token, report_hash, "evaluations.json")
    try:
        ret = utils.get_s3(
            bucket_name=utils.STORE_BUCKET,
            path_key=summary_key,
        )
        if not ret:
            response.status_code = status.HTTP_404_NOT_FOUND
            return
        data = json.loads(ret)
        ret = utils.get_s3(
            bucket_name=utils.STORE_BUCKET,
            path_key=evaluations_key,
        )
        if not ret:
            response.status_code = status.HTTP_404_NOT_FOUND
            return

        data["evaluations"] = json.loads(ret)
        return data

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        utils.logger.exception(err)
        return err

@router.get("/reports", status_code=status.HTTP_200_OK)
async def retrieve_reports(
    request: Request,
    response: Response,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """

    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    utils.logger.info(
        f'"{x_trivialscan_account}","{x_trivialscan_client}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    try:
        if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

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
            return []

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        utils.logger.exception(err)
        return err

    for summary_key in summary_keys:
        if not summary_key.endswith("summary.json"):
            continue
        try:
            ret = utils.get_s3(
                bucket_name=utils.STORE_BUCKET,
                path_key=summary_key,
            )
            if not ret:
                response.status_code = status.HTTP_404_NOT_FOUND
                return []
            item = json.loads(ret)
            if item.get("config"):
                del item["config"]
            if item.get("flags"):
                del item["flags"]
            data.append(item)
        except RuntimeError as err:
            utils.logger.exception(err)
            continue

    return data

@router.get("/host/{hostname}", status_code=status.HTTP_200_OK)
async def retrieve_host(
    request: Request,
    response: Response,
    hostname: str,
    port: int = 443,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    utils.logger.info(
        f'"{x_trivialscan_account}","{x_trivialscan_client}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    try:
        if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

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
        utils.logger.exception(err)
        return err

@router.get("/certificate/{sha1_fingerprint}", status_code=status.HTTP_200_OK)
async def retrieve_certificate(
    request: Request,
    response: Response,
    sha1_fingerprint: str,
    include_pem: bool = False,
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    utils.logger.info(
        f'"{x_trivialscan_account}","{x_trivialscan_client}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    try:
        if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

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
        utils.logger.exception(err)

@router.post("/store/{report_type}", status_code=status.HTTP_200_OK)
async def store(
    request: Request,
    response: Response,
    report_type: ReportType,
    files: list[UploadFile] = File(...),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_client: Union[str, None] = Header(default=None),
    x_trivialscan_token: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    utils.logger.info(
        f'"{x_trivialscan_account}","{x_trivialscan_client}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    try:
        if not utils.is_registered(x_trivialscan_account, x_trivialscan_client, x_trivialscan_token):
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return err

    file = files[0]
    contents = await file.read()
    if file.filename.endswith(".json"):
        contents = json.loads(contents.decode())
    if isinstance(contents, dict):
        if contents.get("config", {}).get("token"):
            del contents["config"]["token"]
        if contents.get("config", {}).get("dashboard_api_url"):
            del contents["config"]["dashboard_api_url"]

    if report_type is ReportType.REPORT:
        result_token = token_urlsafe(56)
        path_prefix = path.join(x_trivialscan_token, result_token)
        if utils.store_summary(report=contents, path_prefix=path_prefix):
            return {"results_uri": f"/result/{result_token}"}

    if report_type is ReportType.EVALUATIONS:
        result_token = file.filename.replace(".json", "")
        path_prefix = path.join(x_trivialscan_token, result_token)
        if utils.store_evaluations(report=contents, account_name=x_trivialscan_account, path_prefix=path_prefix):
            return {"results_uri": f"/result/{result_token}"}

    if report_type is ReportType.HOST:
        return {"ok": utils.store_host(report=contents)}

    if report_type is ReportType.CERTIFICATE and file.filename.endswith(".json"):
        return {"ok": utils.store_certificate(report=contents)}

    if report_type is ReportType.CERTIFICATE and file.filename.endswith(".pem"):
        return {"ok": utils.store_certificate_pem(pem=contents, sha1_fingerprint=file.filename.replace(".pem", ""))}

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
