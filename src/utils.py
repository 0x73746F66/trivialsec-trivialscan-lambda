import logging
import json
from os import getenv, path
from copy import deepcopy
from datetime import datetime

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
logger = logging.getLogger()
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
        else:
            logger.exception(err)
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
        else:
            logger.exception(err)
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
def list_s3(bucket_name: str, prefix_key: str, **kwargs) -> str:
    """
    params:
    - bucket_name: s3 bucket with target contents
    - prefix_key: pattern to match in s3
    """
    logger.info(f"requesting bucket {bucket_name} key prefix {prefix_key}")
    keys = []
    next_token = ''
    base_kwargs = {
        'Bucket': bucket_name,
        'Prefix': prefix_key,
    }
    base_kwargs.update(kwargs)
    while next_token is not None:
        args = base_kwargs.copy()
        if next_token != '':
            args.update({'ContinuationToken': next_token})
        try:
            results = s3_client.list_objects_v2(**args)

        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchBucket":
                logger.error(f"The requested bucket {bucket_name} was not found")
            elif err.response["Error"]["Code"] == "InvalidObjectState":
                logger.error(f"The request was invalid due to: {err}")
            elif err.response["Error"]["Code"] == "InvalidParameterException":
                logger.error(f"The request had invalid params: {err}")
            else:
                logger.exception(err)
            return
        for item in results.get('Contents', []):
            k = item.get('Key')
            if k[-1] != '/':
                keys.append(k)
        next_token = results.get('NextContinuationToken')

    return keys

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
        else:
            logger.exception(err)
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
        else:
            logger.exception(err)
    return False

def is_registered(account_name: str, trivialscan_client: str, provided_token: str) -> bool:
    if not provided_token:
        return False
    object_key = f"{APP_ENV}/{account_name}/client-tokens/{trivialscan_client}"
    register_token = get_s3(
        bucket_name=STORE_BUCKET,
        path_key=object_key,
    )
    return register_token == provided_token

def store_summary(report: dict, path_prefix: str) -> bool:
    account_name = report["config"].get("account_name")
    try:
        summary_key = path.join(APP_ENV, account_name, "results", path_prefix, "summary.json")
        if store_s3(
            bucket_name=STORE_BUCKET,
            path_key=summary_key,
            value=json.dumps(report, default=str),
            StorageClass='STANDARD_IA'
        ):
            return True
    except RuntimeError as err:
        logger.exception(err)
        return False

def store_evaluations(report: list, account_name: str, path_prefix: str) -> bool:
    try:
        evaluations_key = path.join(APP_ENV, account_name, "results", path_prefix, "evaluations.json")
        if store_s3(
            bucket_name=STORE_BUCKET,
            path_key=evaluations_key,
            value=json.dumps(report, default=str),
            StorageClass='STANDARD_IA'
        ):
            return True
    except RuntimeError as err:
        logger.exception(err)
        return False

def store_host(report: dict) -> bool:
    host_key = path.join(APP_ENV, "hosts", report["transport"]["hostname"], str(report["transport"]["port"]), "latest.json")
    if not store_s3(
        bucket_name=STORE_BUCKET,
        path_key=host_key,
        value=json.dumps(report, default=str),
        StorageClass="STANDARD_IA"
    ):
        return False
    scan_date = datetime.fromisoformat(report["last_updated"]).strftime("%Y%m%d")
    host_key2 = path.join(APP_ENV, "hosts", report["transport"]["hostname"], str(report["transport"]["port"]), report["transport"]["peer_address"], f"{scan_date}.json")
    return store_s3(
        bucket_name=STORE_BUCKET,
        path_key=host_key2,
        value=json.dumps(report, default=str),
        StorageClass="STANDARD_IA"
    )

def store_certificate(report: dict) -> bool:
    cert_key = path.join(APP_ENV, "certificates", f"{report['sha1_fingerprint']}.json")
    logger.info(f"Storing {cert_key}")
    return store_s3(
        bucket_name=STORE_BUCKET,
        path_key=cert_key,
        value=json.dumps(report, default=str),
        StorageClass="STANDARD_IA"
    )

def store_certificate_pem(pem: str, sha1_fingerprint: str) -> bool:
    pem_key = path.join(APP_ENV, "certificates", f"{sha1_fingerprint}.pem")
    logger.info(f"Storing {pem_key}")
    return store_s3(
        bucket_name=STORE_BUCKET,
        path_key=pem_key,
        value=pem,
        StorageClass="STANDARD_IA"
    )
