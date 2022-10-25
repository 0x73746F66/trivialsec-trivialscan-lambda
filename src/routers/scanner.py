from time import time
from typing import Union

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request

import internals
import models
import services.helpers

router = APIRouter()


@router.get("/monitor/{hostname}",
            # response_model=models.Monitor,
            # response_model_exclude_unset=True,
            # response_model_exclude_none=True,
            status_code=status.HTTP_200_OK,
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get(
            "http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get(
            "http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return
    changed = False
    if monitor := models.Monitor(account=authz.account).load():  # type: ignore
        quotas = services.helpers.get_quotas(
            account=authz.account,  # type: ignore
            load_passive=False,
            load_active=False,
        )
        if quotas.monitoring.get(models.Quota.USED, 0) >= quotas.monitoring.get(models.Quota.TOTAL, 0):
            response.status_code = status.HTTP_402_PAYMENT_REQUIRED
            return monitor

        found = False
        for _host in monitor.targets:
            if _host.hostname == hostname:
                changed = _host.enabled is False
                found = True
                _host.enabled = True
        if not found:
            changed = True
            monitor.targets.append(models.MonitorHostname(
                hostname=hostname,
                enabled=True,
                timestamp=round(time() * 1000),  # JavaScript support
            ))
    else:
        changed = True
        monitor = models.Monitor(account=authz.account)
        monitor.targets.append(models.MonitorHostname(
            hostname=hostname,
            enabled=True,
            timestamp=round(time() * 1000),  # JavaScript support
        ))
    if changed:
        monitor.save()

    return monitor


@router.get("/deactivate/{hostname}",
            response_model=models.Monitor,
            response_model_exclude_unset=True,
            response_model_exclude_none=True,
            status_code=status.HTTP_200_OK,
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get(
            "http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get(
            "http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return
    changed = False
    if monitor := models.Monitor(account=authz.account).load():  # type: ignore
        found = False
        for _host in monitor.targets:
            if _host.hostname == hostname:
                found = True
                changed = _host.enabled is True
                _host.enabled = False

        if not found:
            changed = True
            monitor.targets.append(models.MonitorHostname(
                hostname=hostname,
                enabled=False,
                timestamp=round(time() * 1000),  # JavaScript support
            ))
    else:
        changed = True
        monitor = models.Monitor(account=authz.account)
        monitor.targets.append(models.MonitorHostname(
            hostname=hostname,
            enabled=False,
            timestamp=round(time() * 1000),  # JavaScript support
        ))

    if changed:
        monitor.save()

    return monitor
