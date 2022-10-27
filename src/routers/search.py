from typing import Union

from dns import rdatatype
from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
from tldextract.tldextract import TLDExtract

import internals
import models
import services.helpers

router = APIRouter()


@router.get("/host/{hostname}",
            # response_model=models.Monitor,
            # response_model_exclude_unset=True,
            # response_model_exclude_none=True,
            status_code=status.HTTP_200_OK,
            tags=["Search"],
            )
async def search_hostname(
    request: Request,
    response: Response,
    hostname: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Search matching hostname, returning exact matches and knowm (scanned, if any) subdomains
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
    answer = None
    for resolve_type in [rdatatype.A, rdatatype.AAAA, rdatatype.CNAME]:
        answer = services.helpers.dns_query(hostname, resolve_type=resolve_type)
        if answer:
            break
    if not answer:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    targets = []
    tldext = TLDExtract(cache_dir="/tmp")(f"http://{hostname}")
    found = False
    apex_found = False
    if monitor := models.Monitor(account=authz.account).load():  # type: ignore
        for target in monitor.targets:
            if target.hostname == hostname:
                found = True
                targets.append({
                    "hostname": hostname,
                    "monitoring": target.enabled,
                })
                continue
            if target.hostname == tldext.registered_domain:
                apex_found = True
                targets.append({
                    "hostname": hostname,
                    "monitoring": target.enabled,
                })
                continue
            if target.hostname.endswith(tldext.registered_domain):
                targets.append({
                    "hostname": target.hostname,
                    "monitoring": target.enabled,
                })
    if not found:
        targets.append({
            "hostname": hostname,
            "monitoring": False,
        })
    if not apex_found:
        targets.append({
            "hostname": tldext.registered_domain,
            "monitoring": False,
        })
    return targets
