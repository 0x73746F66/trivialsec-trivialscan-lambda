import json
from os import path
from typing import Union
from datetime import datetime, timedelta

from fastapi import Header, Query, APIRouter, Response, status
from starlette.requests import Request
from cachier import cachier

import internals
import models
import services.aws
import services.helpers

router = APIRouter()


@router.get(
    "/hosts",
    response_model=list[models.Host],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
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
    tags=["Hostname"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(
        kw["authorization"]
    )["id"],
)
def retrieve_hosts(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a distinct list of hosts and ports, optionally returning the latest host
    full record
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

    scanner_record = models.ScannerRecord(account=authz.account).load()  # type: ignore
    if not scanner_record:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    seen = set()
    data = []
    for report in scanner_record.history:
        for host in report.targets or []:
            target = f"{host.transport.hostname}:{host.transport.port}"
            if target not in seen:
                seen.add(target)
                data.append(host)

    if not data:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return data


@router.get(
    "/host/{hostname}",
    response_model=models.Host,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
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
    tags=["Hostname"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(
        kw["authorization"]
    )["id"]
    + str(kw.get("port", ""))
    + str(kw.get("last_updated", "")),
)
def retrieve_host(
    request: Request,
    response: Response,
    hostname: str,
    port: Union[int, None] = Query(
        default=None,
        description="defaults to 443 when not searching by date, otherwise leaving the port empty returns first found on date regardless of port",
    ),
    last_updated: Union[datetime, None] = Query(
        default=None,
        description="Return the result for specific date rather than the latest (default) Host information. Represented in ISO 8601 format; 2008-09-15T15:53:00+05:00",
    ),
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves TLS data on any hostname, providing an optional port number
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

    prefix_key = path.join(internals.APP_ENV, "hosts", hostname)
    if last_updated:
        object_key = None
        scan_date = last_updated.strftime("%Y%m%d")  # type: ignore
        if port:
            prefix_key = path.join(prefix_key, str(port))
        matches = services.aws.list_s3(prefix_key=prefix_key)
        for match in matches:
            if match.endswith("latest.json"):
                continue
            if match.endswith(f"{scan_date}.json"):
                object_key = match
                break
        if not object_key:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
    else:
        if not port:
            port = 443
        object_key = path.join(prefix_key, str(port), "latest.json")
    try:
        ret = services.aws.get_s3(object_key)
        if not ret:
            return Response(status_code=status.HTTP_204_NO_CONTENT)

        return json.loads(ret)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
    return
