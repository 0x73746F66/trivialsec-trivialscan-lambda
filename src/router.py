import json
from os import path
from secrets import token_urlsafe
from typing import Union, List

from fastapi import Header, APIRouter, Response, File, UploadFile, status
from starlette.requests import Request

import utils
import models

router = APIRouter()

@router.get(
    "/check-token",
    response_model=models.CheckToken,
    response_model_exclude_unset=True,
    status_code=status.HTTP_202_ACCEPTED,
)
async def check_token_registration(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Checks registration status of the provided account name, client name, and registration token
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.HMAC(
        authorization_header=authorization,
        request_url=str(request.url),
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    registration_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    return {
        "version": x_trivialscan_version,
        "account_name": x_trivialscan_account,
        "client_name": authz.id,
        "authorisation_valid": authz.validate(registration_token),
        "registered": utils.is_registered(
            account_name=x_trivialscan_account,
            trivialscan_client=authz.id,
        ),
        "ip_address": ip_addr,
        "user_agent": user_agent,
    }

@router.get("/summary/{report_id}",
    response_model=models.ReportSummary,
    response_model_exclude_unset=True,
    status_code=status.HTTP_200_OK,
)
async def retrieve_summary(
    request: Request,
    response: Response,
    report_id: str,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Retrieves a summary of a Trivial Scanner report for the provided report identiffier
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"results_uri": "missing authorization"}
    authz = utils.HMAC(
        authorization_header=authorization,
        request_url=str(request.url),
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    registration_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not registration_token or not authz.validate(registration_token):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return {"results_uri": "invalid authorization"}
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    summary_key = path.join(utils.APP_ENV, "accounts", x_trivialscan_account, "results", report_id, "summary.json")
    try:
        ret = utils.get_s3(
            bucket_name=utils.STORE_BUCKET,
            path_key=summary_key,
        )
        if not ret:
            response.status_code = status.HTTP_404_NOT_FOUND
            return
        data = json.loads(ret)
        data["results_uri"] = f'/result/{report_id}/summary'
        if data.get("config").get("token"):
            del data["config"]["token"]
        if data.get("config").get("dashboard_api_url"):
            del data["config"]["dashboard_api_url"]
        return data

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        utils.logger.exception(err)
        return err

@router.get("/report/{report_id}",
    response_model=models.EvaluationReport,
    response_model_exclude_unset=True,
    status_code=status.HTTP_200_OK,
)
async def retrieve_report(
    request: Request,
    response: Response,
    report_id: str,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Retrieves a full Trivial Scanner report for the provided report identiffier
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.HMAC(
        authorization_header=authorization,
        request_url=str(request.url),
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    registration_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not registration_token or not authz.validate(registration_token):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    summary_key = path.join(utils.APP_ENV, "accounts", x_trivialscan_account, "results", report_id, "summary.json")
    evaluations_key = path.join(utils.APP_ENV, "accounts", x_trivialscan_account, "results", report_id, "evaluations.json")
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
        data["results_uri"] = f'/result/{report_id}/summary'
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

@router.get("/reports",
    response_model=List[models.ReportSummary],
    response_model_exclude_unset=True,
    status_code=status.HTTP_200_OK,
)
async def retrieve_reports(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing a summary of each
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.HMAC(
        authorization_header=authorization,
        request_url=str(request.url),
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    registration_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not registration_token or not authz.validate(registration_token):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    summary_keys = []
    data = []
    prefix_key = path.join(utils.APP_ENV, "accounts", x_trivialscan_account, "results")
    try:
        summary_keys = utils.list_s3(
            bucket_name=utils.STORE_BUCKET,
            prefix_key=prefix_key,
        )

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        utils.logger.exception(err)
        return []

    if not summary_keys:
        response.status_code = status.HTTP_404_NOT_FOUND
        return []

    for summary_key in summary_keys:
        if not summary_key.endswith("summary.json"):
            continue
        try:
            ret = utils.get_s3(
                bucket_name=utils.STORE_BUCKET,
                path_key=summary_key,
            )
            if not ret:
                continue
            item = json.loads(ret)
            if item.get("config"):
                del item["config"]
            if item.get("flags"):
                del item["flags"]
            item["results_uri"] = f'/result/{summary_key.split("/")[-2]}/summary'
            data.append(item)
        except RuntimeError as err:
            utils.logger.exception(err)
            continue

    return data

@router.get("/host/{hostname}",
    response_model=models.Host,
    response_model_exclude_unset=True,
    status_code=status.HTTP_200_OK,
)
async def retrieve_host(
    request: Request,
    response: Response,
    hostname: str,
    port: int = 443,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Retrieves TLS data on any hostname, providing an optional port number
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.HMAC(
        authorization_header=authorization,
        request_url=str(request.url),
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    registration_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not registration_token or not authz.validate(registration_token):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
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

@router.get("/certificate/{sha1_fingerprint}",
    response_model=models.Certificate,
    response_model_exclude_unset=True,
    status_code=status.HTTP_200_OK,
)
async def retrieve_certificate(
    request: Request,
    response: Response,
    sha1_fingerprint: str,
    include_pem: bool = False,
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Retrieves TLS Certificate data by SHA1 fingerprint, optionally provides the PEM encoded certificate
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    authz = utils.HMAC(
        authorization_header=authorization,
        request_url=str(request.url),
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    registration_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not registration_token or not authz.validate(registration_token):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
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
    report_type: models.ReportType,
    files: list[UploadFile] = File(...),
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Stores various client report data generated by Trivial Scanner CLI
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return

    file = files[0]
    contents = await file.read()
    authz = utils.HMAC(
        raw_body=contents.decode("utf8"),
        authorization_header=authorization,
        request_url=str(request.url),
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","{x_trivialscan_version}","{ip_addr}","{user_agent}"'
    )
    registration_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not registration_token or not authz.validate(registration_token):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    if file.filename.endswith(".json"):
        contents = json.loads(contents.decode("utf8"))
    if isinstance(contents, dict):
        if contents.get("config", {}).get("token"):
            del contents["config"]["token"]
        if contents.get("config", {}).get("dashboard_api_url"):
            del contents["config"]["dashboard_api_url"]

    if report_type is models.ReportType.REPORT:
        contents["version"] = x_trivialscan_version
        result_token = token_urlsafe(56)
        if utils.store_summary(report=contents, path_prefix=result_token):
            return {"results_uri": f"/result/{result_token}/summary"}

    if report_type is models.ReportType.EVALUATIONS:
        result_token = file.filename.replace(".json", "")
        if utils.store_evaluations(report=contents, account_name=x_trivialscan_account, path_prefix=result_token):
            return {"results_uri": f"/result/{result_token}"}

    if report_type is models.ReportType.HOST:
        return {"ok": utils.store_host(report=contents)}

    if report_type is models.ReportType.CERTIFICATE and file.filename.endswith(".json"):
        return {"ok": utils.store_certificate(report=contents)}

    if report_type is models.ReportType.CERTIFICATE and file.filename.endswith(".pem"):
        return {"ok": utils.store_certificate_pem(pem=contents, sha1_fingerprint=file.filename.replace(".pem", ""))}

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
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
        if utils.is_registered(x_trivialscan_account, client_name):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return {"message": f"client {client_name} already registered"}
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    object_key = f"{utils.APP_ENV}/accounts/{x_trivialscan_account}/client-tokens/{client_name}"
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
