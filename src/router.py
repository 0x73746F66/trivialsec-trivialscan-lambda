import hashlib
import json
from os import path
from time import time
from random import random
from secrets import token_urlsafe
from typing import Union, List

from fastapi import Header, APIRouter, Response, File, UploadFile, status
from starlette.requests import Request
import validators

import utils
import models

router = APIRouter()

@router.get(
    "/validate",
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
        "authorisation_valid": authz.validate(access_token),
        "registered": utils.is_registered(
            account_name=x_trivialscan_account,
            trivialscan_client=authz.id if authz.id not in utils.RESERVED_CLIENTS else None,
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
        f'"{x_trivialscan_account}","{authz.id}","{ip_addr}","{user_agent}",'
    )
    access_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not access_token or not authz.validate(access_token):
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
        f'"{x_trivialscan_account}","{authz.id}","{ip_addr}","{user_agent}",'
    )
    access_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not access_token or not authz.validate(access_token):
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
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing a summary of each
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
        if not access_token or not authz.validate(access_token):
            response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
            response.status_code = status.HTTP_403_FORBIDDEN
            return
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return {"message": utils.GENERIC_SECURITY_MESSAGE}

    summary_keys = []
    data = []
    prefix_key = path.join(utils.APP_ENV, "accounts",
                           x_trivialscan_account, "results")
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
        f'"{x_trivialscan_account}","{authz.id}","{ip_addr}","{user_agent}",'
    )
    access_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not access_token or not authz.validate(access_token):
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
        f'"{x_trivialscan_account}","{authz.id}","{ip_addr}","{user_agent}",'
    )
    access_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not access_token or not authz.validate(access_token):
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
        method="POST",
    )
    utils.logger.info(
        f'"{x_trivialscan_account}","{authz.id}","{ip_addr}","{user_agent}","{x_trivialscan_version}"'
    )
    access_token = utils.retrieve_token(
        account_name=x_trivialscan_account,
        client_name=authz.id,
    )
    try:
        if not access_token or not authz.validate(access_token):
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
        report_id = token_urlsafe(56)
        if utils.store_summary(report=contents, path_prefix=report_id):
            return {"results_uri": f"/result/{report_id}/summary"}

    if report_type is models.ReportType.EVALUATIONS:
        report_id = file.filename.replace(".json", "")
        if utils.store_evaluations(report=contents, account_name=x_trivialscan_account, path_prefix=report_id):
            return {"results_uri": f"/result/{report_id}"}

    if report_type is models.ReportType.HOST:
        return {"ok": utils.store_host(report=contents)}

    if report_type is models.ReportType.CERTIFICATE and file.filename.endswith(".json"):
        return {"ok": utils.store_certificate(report=contents)}

    if report_type is models.ReportType.CERTIFICATE and file.filename.endswith(".pem"):
        return {"ok": utils.store_certificate_pem(pem=contents, sha1_fingerprint=file.filename.replace(".pem", ""))}

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


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
        if client_name in utils.RESERVED_CLIENTS or utils.is_registered(x_trivialscan_account, client_name):
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
    member = models.MemberProfile(
        account=account,
        email=account.primary_email,
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
        user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent"),
        timestamp = account.timestamp
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
        object_key = f"{utils.APP_ENV}/accounts/{account.name}/registration.json"
        if utils.store_s3(
            utils.STORE_BUCKET,
            object_key,
            json.dumps(account.dict(), default=str),
            storage_class=utils.StorageClass.STANDARD
        ):
            utils.upsert_contact(recipient_email=member.email, list_name="members")
            return member
    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.post("/magic-link",
    status_code=status.HTTP_202_ACCEPTED
)
async def magic_link (
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
        500 An unexpected and unhandled request path occurred
    """
    event = request.scope.get("aws.event", {})
    ip_addr = event.get("requestContext", {}).get("http", {}).get("sourceIp")
    user_agent = event.get("requestContext", {}).get("http", {}).get("userAgent")
    if validators.email(data.email) is not True:
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        return
    magic_token = hashlib.sha224(bytes(f'{random()}{user_agent}{ip_addr}', 'ascii')).hexdigest()
    login_url = f"https://scanner.trivialsec.com/login/{magic_token}"
    try:
        if member := utils.load_member(data.email):
            sendgrid = utils.send_email(
                recipient=data.email,
                subject="Trivial Security login",
                template='magic_link',
                data={
                    "magic_link": login_url
                }
            )
            object_key = f"{utils.APP_ENV}/accounts/{member.account.name}/members/{member.email}/magic-link.json"
            link = models.MagicLink(
                magic_token=magic_token,
                ip_addr=ip_addr,
                user_agent=user_agent,
                timestamp=round(time() * 1000),
                sendgrid=sendgrid.__dict__
            )
            if not utils.store_s3(
                utils.STORE_BUCKET,
                object_key,
                json.dumps(link.dict(), default=str),
                storage_class=utils.StorageClass.STANDARD_IA
            ):
                response.status_code = status.HTTP_406_NOT_ACCEPTABLE
                return

        else:
            response.status_code = status.HTTP_424_FAILED_DEPENDENCY
            return

    except RuntimeError as err:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        utils.logger.exception(err)
        return

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
