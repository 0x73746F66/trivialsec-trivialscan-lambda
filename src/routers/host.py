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


@router.get("/hosts",
    response_model=list[models.Host],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]+str(kw.get("return_details"))
    )
def retrieve_hosts(
    request: Request,
    response: Response,
    return_details: bool = False,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a distinct list of hosts and ports, optionally returning the latest host
    full record
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    path_keys = []
    data = []
    prefix_key = path.join(internals.APP_ENV, "accounts", authz.account.name, "results")  # type: ignore
    try:
        path_keys = services.aws.list_s3(prefix_key)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return []

    if not path_keys:
        internals.logger.warning(f"No reports for {prefix_key}")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    seen = set()
    for object_key in path_keys:
        if not object_key.endswith("summary.json"):
            continue
        ret = services.aws.get_s3(object_key)
        if not ret:
            continue
        item = json.loads(ret)
        if not isinstance(item, dict):
            continue
        report = models.FullReport(**item)
        for target in report.targets or []:
            if target not in seen:
                seen.add(target)
                hostname, port = target.split(":")
                tspt = models.HostTransport(hostname=hostname, port=port)  # type: ignore
                host = models.Host(transport=tspt)  # type: ignore
                if return_details:
                    host.load()
                data.append(host)

    if not data:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return data


@router.get("/host/{hostname}",
    response_model=models.Host,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]+str(kw.get("port",""))+str(kw.get("last_updated",""))
    )
def retrieve_host(
    request: Request,
    response: Response,
    hostname: str,
    port: Union[int, None] = Query(default=None, description="defaults to 443 when not searching by date, otherwise leaving the port empty returns first found on date regardless of port"),
    last_updated: Union[datetime, None] = Query(default=None, description="Return the result for specific date rather than the latest (default) Host information"),
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves TLS data on any hostname, providing an optional port number
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
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
