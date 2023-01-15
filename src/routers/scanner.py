import json
from time import time

from fastapi import APIRouter, Response, status, Depends
import validators

import internals
import models
import services.helpers
import services.aws
import services.webhook

router = APIRouter()


@router.get(
    "/config",
    response_model=list[models.MonitorHostname],
    status_code=status.HTTP_200_OK,
    responses={
        204: {
            "description": "New accounts have no data, if this occurs after adding a host to be monitored this response code indicates an urgent issue"
        },
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
async def scanner_config(
    response: Response,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Fetches host monitoring configuration
    """
    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        return scanner_record.monitored_targets
    response.status_code = status.HTTP_204_NO_CONTENT


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
        406: {"description": "Invalid Hostname"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Scanner"],
)
async def enable_monitoring(
    response: Response,
    hostname: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Adds and enables host monitoring
    """
    if validators.email(f"nobody@{hostname}") is not True:
        response.status_code = status.HTTP_406_NOT_ACCEPTABLE
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
        for target in scanner_record.monitored_targets:
            if target.hostname == hostname:
                changed = target.enabled is False
                found = True
                target.enabled = True
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
        services.webhook.send(
            event_name=models.WebhookEvent.SCANNER_CONFIGURATIONS,
            account=authz.account,
            data={
                "hostname": hostname,
                "type": "configuration",
                "status": "update",
                "values": {"enabled": True},
                "account": authz.account.name,
                "member": authz.member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent,
            },
        )

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
        406: {"description": "Invalid Hostname"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Scanner"],
)
async def deactivate_monitoring(
    response: Response,
    hostname: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Adds and enables host monitoring
    """
    if validators.email(f"nobody@{hostname}") is not True:
        response.status_code = status.HTTP_406_NOT_ACCEPTABLE
        return
    changed = False
    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        found = False
        for target in scanner_record.monitored_targets:
            if target.hostname == hostname:
                found = True
                changed = target.enabled is True
                target.enabled = False

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
        services.webhook.send(
            event_name=models.WebhookEvent.SCANNER_CONFIGURATIONS,
            account=authz.account,
            data={
                "hostname": hostname,
                "type": "configuration",
                "status": "update",
                "values": {"enabled": False},
                "account": authz.account.name,
                "member": authz.member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent,
            },
        )

    return scanner_record


@router.get(
    "/queue/{hostname}",
    response_model=bool,
    status_code=status.HTTP_200_OK,
    responses={
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        406: {"description": "Invalid Hostname"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Scanner"],
)
async def queue_hostname(
    response: Response,
    hostname: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Adds a host for on-demand scanning
    """
    if validators.email(f"nobody@{hostname}") is not True:
        response.status_code = status.HTTP_406_NOT_ACCEPTABLE
        return
    queue_name = f"{internals.APP_ENV.lower()}-reconnaissance"
    queued_timestamp = round(time() * 1000)  # JavaScript support
    services.aws.store_sqs(
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
        queued_timestamp=queued_timestamp,  # JavaScript support
    )
    services.webhook.send(
        event_name=models.WebhookEvent.HOSTED_SCANNER,
        account=authz.account,
        data={
            "hostname": hostname,
            "port": 443,
            "http_paths": ["/"],
            "type": models.ScanRecordType.ONDEMAND,
            "status": "queued",
            "account": authz.account.name,
            "member": authz.member.email,
            "queued_timestamp": queued_timestamp,
            "ip_addr": authz.ip_addr,
            "user_agent": authz.user_agent,
        },
    )
    return True


@router.delete(
    "/config/{hostname}",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        204: {"description": "No matching host, was it already removed?"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        406: {"description": "Invalid Hostname"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Scanner"],
)
async def delete_config(
    response: Response,
    hostname: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Deletes a host monitoring configuration
    """
    if validators.email(f"nobody@{hostname}") is not True:
        response.status_code = status.HTTP_406_NOT_ACCEPTABLE
        return
    changed = False
    monitored_targets = []
    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        for target in scanner_record.monitored_targets:
            if target.hostname == hostname:
                changed = True
                continue
            monitored_targets.append(target)

    if changed:
        scanner_record.monitored_targets = monitored_targets
        scanner_record.save()
        services.webhook.send(
            event_name=models.WebhookEvent.SCANNER_CONFIGURATIONS,
            account=authz.account,
            data={
                "hostname": hostname,
                "type": "configuration",
                "status": "deleted",
                "account": authz.account.name,
                "member": authz.member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent,
            },
        )
    else:
        response.status_code = status.HTTP_204_NO_CONTENT
        return

    return scanner_record


@router.post(
    "/config",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        204: {"description": "Nothing changed, was it already updated?"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        404: {"description": "No parameters to change were provided"},
        406: {"description": "Invalid Hostname"},
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Scanner"],
)
async def update_config(
    response: Response,
    data: models.ConfigUpdateRequest,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Deletes a host monitoring configuration
    """
    if validators.email(f"nobody@{data.hostname}") is not True:
        response.status_code = status.HTTP_406_NOT_ACCEPTABLE
        return
    changed = False
    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        for target in scanner_record.monitored_targets:
            if target.hostname != data.hostname:
                continue
            if data.enabled is not None:
                target.enabled = data.enabled
                changed = True
            if data.http_paths:
                target.path_names.sort(key=str.lower)
                data.http_paths.sort(key=str.lower)
                if target.path_names != data.http_paths:
                    target.path_names = data.http_paths
                    changed = True
            if data.ports:
                target.ports.sort(key=int)
                data.ports.sort(key=int)
                if data.ports != target.ports:
                    target.ports = data.ports
                    changed = True

    if changed:
        scanner_record.save()
        services.webhook.send(
            event_name=models.WebhookEvent.SCANNER_CONFIGURATIONS,
            account=authz.account,
            data={
                "hostname": data.hostname,
                "type": "configuration",
                "status": "update",
                "values": data,
                "account": authz.account.name,
                "member": authz.member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent,
            },
        )
    else:
        response.status_code = status.HTTP_204_NO_CONTENT
        return

    return scanner_record
