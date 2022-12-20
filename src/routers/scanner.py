import json
from time import time
from typing import Union

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request

import internals
import models
import services.helpers
import services.aws

router = APIRouter()


@router.get(
    "/monitor/{hostname}",
    response_model=models.ScannerRecord,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        402: {
            "description": "Quota has been exhausted, no more monitoring is possible. Upgrade the account or stop monitoring another host"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Scanner"],
)
async def enable_monitoring(
    request: Request,
    response: Response,
    hostname: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Adds and enables host monitoring
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return
    changed = False
    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        quotas = services.helpers.get_quotas(
            account=authz.account,  # type: ignore
            scanner_record=scanner_record,
        )
        if quotas.monitoring.get(models.Quota.USED, 0) >= quotas.monitoring.get(
            models.Quota.TOTAL, 0
        ):
            response.status_code = status.HTTP_402_PAYMENT_REQUIRED
            return scanner_record

        found = False
        for _host in scanner_record.monitored_targets:
            if _host.hostname == hostname:
                changed = _host.enabled is False
                found = True
                _host.enabled = True
        if not found:
            changed = True
            scanner_record.monitored_targets.append(
                models.MonitorHostname(
                    hostname=hostname,
                    enabled=True,
                    timestamp=round(time() * 1000),  # JavaScript support
                )
            )
    else:
        changed = True
        scanner_record = models.ScannerRecord(account=authz.account)  # type: ignore
        scanner_record.monitored_targets.append(
            models.MonitorHostname(
                hostname=hostname,
                enabled=True,
                timestamp=round(time() * 1000),  # JavaScript support
            )
        )
    if changed:
        scanner_record.save()

    return scanner_record


@router.get(
    "/deactivate/{hostname}",
    response_model=models.ScannerRecord,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
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
    tags=["Scanner"],
)
async def deactivate_monitoring(
    request: Request,
    response: Response,
    hostname: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Adds and enables host monitoring
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return
    changed = False
    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        found = False
        for _host in scanner_record.monitored_targets:
            if _host.hostname == hostname:
                found = True
                changed = _host.enabled is True
                _host.enabled = False

        if not found:
            changed = True
            scanner_record.monitored_targets.append(
                models.MonitorHostname(
                    hostname=hostname,
                    enabled=False,
                    timestamp=round(time() * 1000),  # JavaScript support
                )
            )
    else:
        changed = True
        scanner_record = models.ScannerRecord(account=authz.account)  # type: ignore
        scanner_record.monitored_targets.append(
            models.MonitorHostname(
                hostname=hostname,
                enabled=False,
                timestamp=round(time() * 1000),  # JavaScript support
            )
        )

    if changed:
        scanner_record.save()

    return scanner_record


@router.get(
    "/queue/{hostname}",
    response_model=bool,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
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
    tags=["Scanner"],
)
async def queue_hostname(
    request: Request,
    response: Response,
    hostname: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Adds a host for on-demand scanning
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return

    queue_name = f"{internals.APP_ENV.lower()}-reconnaissance"
    return services.aws.store_sqs(
        queue_name=queue_name,
        message_body=json.dumps(
            {
                "hostname": hostname,
                "port": 443,
                "type": models.ScanRecordType.ONDEMAND,
            },
            default=str,
        ),
        deduplicate=False,
        http_paths=["/"],
        account=authz.account.name,  # type: ignore
        queued_by=authz.member.email,  # type: ignore
        queued_timestamp=round(time() * 1000),  # JavaScript support
    )
