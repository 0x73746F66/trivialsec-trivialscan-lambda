from typing import Union
from datetime import datetime
import json

from dns import rdatatype
from fastapi import Header, APIRouter, Response, status
from pydantic import IPvAnyAddress
from starlette.requests import Request
from tldextract.tldextract import TLDExtract

import internals
import models
import services.helpers
import services.aws

router = APIRouter()


@router.get("/host/{hostname}",
            response_model=list[models.SearchResult],
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
    scans_map = {}
    resolved_ip: list[str] = [ip.split(' ').pop() for ip in answer.rrset.to_rdataset().to_text().splitlines()]
    tldext = TLDExtract(cache_dir="/tmp")(f"http://{hostname}")
    if history_raw := services.aws.get_s3(f"{internals.APP_ENV}/accounts/{authz.account.name}/scan-history.json"):  # type: ignore
        scans_map: dict[str, dict[str, list[str]]] = json.loads(history_raw)
    domain_map = {}
    domain_map[hostname] = {
        'timestamps': set(),
        'resolved_ip': set(resolved_ip),
        'ip_addr': set(),
        "monitoring": False,
        'ports': set(),
        'reports': set(),
    }
    if tldext.registered_domain != hostname:
        domain_map[tldext.registered_domain] = {
            'timestamps': set(),
            'ip_addr': set(),
            "monitoring": False,
            'ports': set(),
            'reports': set(),
        }
    prefix_key = f"{internals.APP_ENV}/hosts/"
    matches = services.aws.list_s3(prefix_key=prefix_key)
    for match in matches:
        if match.endswith("latest.json"):
            continue
        _, _, host, port, peer_address, scan_date = match.split("/")
        fq_target = f"{hostname}:{port}"
        if hostname == host:
            timestamp = datetime.strptime(scan_date.replace('.json', ''), "%Y%m%d").timestamp()*1000
            domain_map[hostname]['timestamps'].add(timestamp)
            domain_map[hostname]['ip_addr'].add(peer_address)
            domain_map[hostname]['ports'].add(port)
            if fq_target in scans_map:
                domain_map[hostname]['reports'].update(scans_map[fq_target]['reports'])
        fq_target = f"{tldext.registered_domain}:{port}"
        if tldext.registered_domain == host:
            timestamp = datetime.strptime(scan_date.replace('.json', ''), "%Y%m%d").timestamp()*1000
            domain_map[tldext.registered_domain]['timestamps'].add(timestamp)
            domain_map[tldext.registered_domain]['ip_addr'].add(peer_address)
            domain_map[tldext.registered_domain]['ports'].add(port)
            if fq_target in scans_map:
                domain_map[tldext.registered_domain]['reports'].update(scans_map[fq_target]['reports'])

    if monitor := models.Monitor(account=authz.account).load():  # type: ignore
        for target in monitor.targets:
            if target.hostname in domain_map or target.hostname.endswith(tldext.registered_domain):
                domain_map.setdefault(target.hostname, {'timestamps': set(), 'ip_addr': set(), 'ports': set(), 'reports': set(), "monitoring": False})
                domain_map[target.hostname]["monitoring"] = target.enabled
                fq_target = f"{target.hostname}:443"
                if fq_target in scans_map:
                    domain_map[target.hostname]['ports'].add(443)
                    domain_map[target.hostname]['reports'].update(scans_map[fq_target]['reports'])
                for record in target.history:
                    fq_target = f"{target.hostname}:{record.port}"
                    if fq_target in scans_map:
                        domain_map[target.hostname]['timestamps'].add(record.date_checked.timestamp()*1000)
                        domain_map[target.hostname]['ports'].add(record.port)
                        domain_map[target.hostname]['reports'].update(scans_map[fq_target]['reports'])

    if not domain_map:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    results: list[models.SearchResult] = []
    for host, data in domain_map.items():
        results.append(models.SearchResult(
            ip_addr=data['ip_addr'],
            resolved_ip=data.get('resolved_ip', []),
            hostname=host,
            ports=data.get('ports', []),
            reports=data.get('reports', []),
            last_scanned=None if not data.get('timestamps') else max(data['timestamps']),
            monitoring=data["monitoring"],
        ))  # type: ignore

    return results

@router.get("/ip/{ip_addr}",
            response_model=list[models.SearchResult],
            response_model_exclude_unset=True,
            response_model_exclude_none=True,
            status_code=status.HTTP_200_OK,
            tags=["Search"],
            )
async def search_ipaddr(
    request: Request,
    response: Response,
    ip_addr: IPvAnyAddress,
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

    if history_raw := services.aws.get_s3(f"{internals.APP_ENV}/accounts/{authz.account.name}/scan-history.json"):  # type: ignore
        scans_map: dict[str, dict[str, list[str]]] = json.loads(history_raw)

    domain_map = {}
    prefix_key = f"{internals.APP_ENV}/hosts/"
    matches = services.aws.list_s3(prefix_key=prefix_key)
    for match in matches:
        if match.endswith("latest.json"):
            continue
        _, _, hostname, port, peer_address, scan_date = match.split("/")
        target = f"{hostname}:{port}"
        if peer_address == str(ip_addr):
            domain_map.setdefault(hostname, {'timestamps': set(), 'ports': set(), 'reports': set(), "monitoring": False})
            timestamp = datetime.strptime(scan_date.replace('.json', ''), "%Y%m%d").timestamp()*1000
            domain_map[hostname]['timestamps'].add(timestamp)
            domain_map[hostname]['ports'].add(port)
            if target in scans_map:
                domain_map[hostname]['reports'].update(scans_map[target]['reports'])

    if monitor := models.Monitor(account=authz.account).load():  # type: ignore
        for target in monitor.targets:
            if target.hostname in domain_map:
                domain_map[target.hostname]["monitoring"] = target.enabled

    if not domain_map:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    results: list[models.SearchResult] = []
    for host, data in domain_map.items():
        results.append(models.SearchResult(
            ip_addr=[ip_addr],
            resolved_ip=data.get('resolved_ip', []),
            hostname=host,
            ports=data['ports'],
            reports=data['reports'],
            last_scanned=max(data['timestamps']),
            monitoring=data["monitoring"],
        ))  # type: ignore

    return results
