from typing import Union
from datetime import datetime
import json

from dns import rdatatype
from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
from tldextract.tldextract import TLDExtract

import internals
import models
import services.helpers
import services.aws

router = APIRouter()


@router.get("/host/{hostname}",
            response_model=list[models.SearchHostname],
            response_model_exclude_unset=True,
            response_model_exclude_none=True,
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
    apex_found = hostname == tldext.registered_domain
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


@router.get("/ip/{ip_addr}",
            response_model=list[models.SearchIP],
            response_model_exclude_unset=True,
            response_model_exclude_none=True,
            status_code=status.HTTP_200_OK,
            tags=["Search"],
            )
async def search_ipaddr(
    request: Request,
    response: Response,
    ip_addr: str,
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

    scans_map = {}
    prefix_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/results/"  # type: ignore
    matches = services.aws.list_s3(prefix_key=prefix_key)
    for match in matches:
        if not match.endswith("summary.json"):
            continue
        report_id, _ = match.replace(prefix_key, '').split("/")  # type: ignore
        if report := models.ReportSummary(report_id=report_id, account_name=authz.account.name).load():  # type: ignore
            for hostname in report.targets or []:
                scans_map.setdefault(hostname, {"reports": []})
                scans_map[hostname]['reports'].append(report_id)

    history_raw = services.aws.get_s3(f"{internals.APP_ENV}/accounts/{authz.account.name}/scan-history.json")  # type: ignore
    if not history_raw:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    scans_map: dict[str, dict[str, list[str]]] = json.loads(history_raw)

    domain_map = {}
    prefix_key = f"{internals.APP_ENV}/hosts/"
    matches = services.aws.list_s3(prefix_key=prefix_key)
    for match in matches:
        if match.endswith("latest.json"):
            continue
        _, _, hostname, port, peer_address, scan_date = match.split("/")
        target = f"{hostname}:{port}"
        if peer_address == ip_addr:
            domain_map.setdefault(hostname, {'timestamps': set(), 'ports': set(), 'reports': set(), "monitoring": False})
            timestamp = datetime.strptime(scan_date.replace('.json', ''), "%Y%m%d").timestamp()*1000
            domain_map[hostname]['timestamps'].add(timestamp)
            domain_map[hostname]['ports'].add(port)
            if target in scans_map:
                domain_map[hostname]['reports'].update(scans_map[target]['reports'])

    if not domain_map:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    if monitor := models.Monitor(account=authz.account).load():  # type: ignore
        for target in monitor.targets:
            if target.hostname in domain_map:
                domain_map[target.hostname]["monitoring"] = target.enabled

    results: list[models.SearchIP] = []
    for host, data in domain_map.items():
        results.append(models.SearchIP(
            ip_addr=ip_addr,
            hostname=host,
            ports=data['ports'],
            reports=data['reports'],
            last_scanned=max(data['timestamps']),
            monitoring=data["monitoring"],
        ))

    return results
