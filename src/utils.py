import logging
import json
from os import getenv, path
from copy import deepcopy

import boto3
from retry.api import retry
from botocore.exceptions import (
    CapacityNotAvailableError,
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    ReadTimeoutError,
)

__trivialscan_version__ = "3.0.0rc6"

APP_ENV = getenv("APP_ENV", "Dev")
APP_NAME = getenv("APP_NAME", "trivialscan-lambda")
STORE_BUCKET = getenv("STORE_BUCKET", "trivialscan-dashboard-store")
DASHBOARD_API_URL = "https://dashboard.trivialsec.com"
logger = logging.getLogger("uvicorn.default")
ssm_client = boto3.client(service_name="ssm")
s3_client = boto3.client(service_name="s3")

def object_exists(bucket_name: str, file_path: str, **kwargs):
    try:
        content = s3_client.head_object(Bucket=bucket_name, Key=file_path, **kwargs)
        return content.get("ResponseMetadata", None) is not None
    except ClientError:
        pass
    return False

@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def get_ssm(parameter: str, default=None, **kwargs) -> str:
    logger.info(f"requesting secret {parameter}")
    try:
        response = ssm_client.get_parameter(Name=parameter, **kwargs)
        return (
            default
            if not isinstance(response, dict)
            else response.get("Parameter", {}).get("Value", default)
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.warning(f"The requested secret {parameter} was not found")
        elif err.response["Error"]["Code"] == "InvalidRequestException":
            logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "InvalidParameterException":
            logger.warning(f"The request had invalid params: {err}")
    return default

@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def store_ssm(parameter: str, value:str, **kwargs) -> bool:
    logger.info(f"storing secret {parameter}")
    try:
        response = ssm_client.put_parameter(Name=parameter, Value=value, **kwargs)
        return (
            False
            if not isinstance(response, dict)
            else response.get("Version") is not None
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "ParameterAlreadyExists":
            logger.warning(f"The secret {parameter} already exists")
        elif err.response["Error"]["Code"] == "InternalServerError":
            logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "TooManyUpdates":
            logger.warning(err, exc_info=True)
            raise RuntimeError("Please throttle your requests to continue using this service") from err
        elif err.response["Error"]["Code"] == "ParameterLimitExceeded":
            logger.warning(err, exc_info=True)
            raise RuntimeError("Platform is exhausted and unable to respond, please try again soon") from err
    return False

@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def get_s3(bucket_name: str, path_key: str, default=None, **kwargs) -> str:
    logger.info(f"requesting bucket {bucket_name} object key {path_key}")
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=path_key, **kwargs)
        return response["Body"].read().decode("utf8")

    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchKey":
            logger.warning(f"The requested bucket {bucket_name} object key {path_key} was not found")
        elif err.response["Error"]["Code"] == "InvalidObjectState":
            logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "InvalidParameterException":
            logger.warning(f"The request had invalid params: {err}")
    return default

@retry(
    (
        ConnectionClosedError,
        ReadTimeoutError,
        ConnectTimeoutError,
        CapacityNotAvailableError,
    ),
    tries=3,
    delay=1.5,
    backoff=1,
)
def store_s3(bucket_name: str, path_key: str, value:str, **kwargs) -> bool:
    logger.info(f"storing bucket {bucket_name} object key {path_key}")
    try:
        response = s3_client.put_object(Bucket=bucket_name, Key=path_key, Body=value, **kwargs)
        return (
            False
            if not isinstance(response, dict)
            else response.get("ETag") is not None
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "ParameterAlreadyExists":
            logger.warning(f"The object bucket {bucket_name} key {path_key} already exists")
        elif err.response["Error"]["Code"] == "InternalServerError":
            logger.warning(f"The request was invalid due to: {err}")
        elif err.response["Error"]["Code"] == "TooManyUpdates":
            logger.warning(err, exc_info=True)
            raise RuntimeError("Please throttle your requests to continue using this service") from err
        elif err.response["Error"]["Code"] == "ParameterLimitExceeded":
            logger.warning(err, exc_info=True)
            raise RuntimeError("Platform is exhausted and unable to respond, please try again soon") from err
    return False

def is_registered(account_name: str, trivialscan_client: str, provided_token: str) -> str:
    object_key = f"{APP_ENV}/{account_name}/client-tokens/{trivialscan_client}"
    register_token = get_s3(
        bucket_name=STORE_BUCKET,
        path_key=object_key,
    )
    return register_token == provided_token

def store_public(report: dict) -> str:
    for _query in report["results"]["queries"]:
        query = deepcopy(_query)
        if "error" in query:
            continue
        certificates = set()
        del query["evaluations"]
        for certdata in _query.get("tls", {}).get("certificates", []):
            certificates.add(certdata["sha1_fingerprint"])
            cert_key = path.join(APP_ENV, "certificates", f"{certdata['sha1_fingerprint']}.json")
            certcopy = deepcopy(certdata)
            del certcopy["pem"]
            logger.info(f"Storing {cert_key}")
            store_s3(
                bucket_name=STORE_BUCKET,
                path_key=cert_key,
                value=json.dumps(certcopy, default=str),
                StorageClass="STANDARD_IA"
            )
            pem_key = path.join(APP_ENV, "certificates", f"{certdata['sha1_fingerprint']}.pem")
            logger.info(f"Storing {pem_key}")
            store_s3(
                bucket_name=STORE_BUCKET,
                path_key=pem_key,
                value=certdata["pem"],
                StorageClass="STANDARD_IA"
            )

        query["tls"]["certificates"] = sorted(list(certificates))
        host_key = path.join(APP_ENV, "hosts", query["transport"]["hostname"], str(query["transport"]["port"]), f"{query['last_updated']}.json")
        store_s3(
            bucket_name=STORE_BUCKET,
            path_key=host_key,
            value=json.dumps(query, default=str),
            StorageClass="STANDARD_IA"
        )
    return

def make_summary(report: dict) -> str:
    data = deepcopy(report["results"])
    data["config"] = report["config"]
    data["flags"] = report["flags"]
    data["score"] = 0
    data["results"] = {
        "pass": 0,
        "info": 0,
        "warn": 0,
        "fail": 0,
    }
    del data["queries"]
    certificates = set()
    for _query in report["results"]["queries"]:
        query = _query["transport"]
        for evaluation in _query.get("evaluations", []):
            for res in ["pass", "info", "warn", "fail"]:
                if evaluation["result_level"] == res:
                    data["results"][res] += 1
            if "score" in evaluation:
                data["score"] += evaluation["score"]
        if "error" in _query:
            query["error"] = _query["error"]

        for certdata in _query.get("tls", {}).get("certificates", []):
            certificates.add(certdata["sha1_fingerprint"])

    data["certificates"] = sorted(list(certificates))
    return json.dumps(data, default=str)
