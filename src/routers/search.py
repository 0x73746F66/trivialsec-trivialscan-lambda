import json
import socket
from typing import Union
from datetime import datetime

from fastapi import Header, APIRouter, Response, status
from pydantic import IPvAnyAddress
from starlette.requests import Request
from tldextract.tldextract import TLDExtract

import internals
import models
import services.helpers
import services.aws

router = APIRouter()


@router.get(
    "/host/{hostname}",
    response_model=list[models.SearchResult],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No search results matching this query"},
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

    resolved_ip = services.helpers.retrieve_ip_for_host(hostname)
    if len(resolved_ip) == 0:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    scanner_record = models.ScannerRecord(account=authz.account).load()  # type: ignore
    tldext = TLDExtract(cache_dir=internals.CACHE_DIR)(f"http://{hostname}")
    domain_map = {}
    domain_map[hostname] = {
        "timestamps": set(),
        "resolved_ip": set(resolved_ip),
        "ip_addr": set(),
        "monitoring": False,
        "ports": set(),
        "reports": set(),
    }
    if tldext.registered_domain != hostname:
        domain_map[tldext.registered_domain] = {
            "timestamps": set(),
            "ip_addr": set(),
            "monitoring": False,
            "ports": set(),
            "reports": set(),
        }
    prefix_key = f"{internals.APP_ENV}/hosts/"
    matches = services.aws.list_s3(prefix_key=prefix_key)
    for match in matches:
        if match.endswith("latest.json"):
            continue
        _, _, host, port, peer_address, scan_date = match.split("/")

        if hostname == host:
            timestamp = (
                datetime.strptime(scan_date.replace(".json", ""), "%Y%m%d").timestamp()
                * 1000
            )
            domain_map[hostname]["timestamps"].add(timestamp)
            domain_map[hostname]["ip_addr"].add(peer_address)
            domain_map[hostname]["ports"].add(int(port))
            if scanner_record:
                domain_map[hostname]["reports"].update([report.report_id for report in scanner_record.history if hostname in [host.transport.hostname for host in report.targets]])  # type: ignore

        elif tldext.registered_domain == host:
            timestamp = (
                datetime.strptime(scan_date.replace(".json", ""), "%Y%m%d").timestamp()
                * 1000
            )
            domain_map[tldext.registered_domain]["timestamps"].add(timestamp)
            domain_map[tldext.registered_domain]["ip_addr"].add(peer_address)
            domain_map[tldext.registered_domain]["ports"].add(int(port))
            if scanner_record:
                domain_map[tldext.registered_domain]["reports"].update([report.report_id for report in scanner_record.history if tldext.registered_domain in [host.transport.hostname for host in report.targets]])  # type: ignore

    if scanner_record:
        for report in scanner_record.history:
            for host in report.targets:  # type: ignore
                if hostname == host.transport.hostname:
                    domain_map.setdefault(
                        hostname,
                        {
                            "timestamps": set(),
                            "ip_addr": set(),
                            "ports": set(),
                            "reports": set(),
                            "monitoring": False,
                        },
                    )
                    domain_map[hostname]["timestamps"].add(report.date.timestamp() * 1000)  # type: ignore
                    domain_map[hostname]["ip_addr"].add(
                        str(host.transport.peer_address)
                    )
                    domain_map[hostname]["ports"].add(int(host.transport.port))
                    domain_map[hostname]["reports"].add(report.report_id)
                elif host.transport.hostname.endswith(tldext.registered_domain):
                    domain_map.setdefault(
                        host.transport.hostname,
                        {
                            "timestamps": set(),
                            "ip_addr": set(),
                            "ports": set(),
                            "reports": set(),
                            "monitoring": False,
                        },
                    )
                    domain_map[host.transport.hostname]["timestamps"].add(report.date.timestamp() * 1000)  # type: ignore
                    domain_map[host.transport.hostname]["ip_addr"].add(
                        str(host.transport.peer_address)
                    )
                    domain_map[host.transport.hostname]["ports"].add(
                        int(host.transport.port)
                    )
                    domain_map[host.transport.hostname]["reports"].add(report.report_id)

        for target in scanner_record.monitored_targets:
            if target.hostname in domain_map:
                domain_map[target.hostname]["monitoring"] = target.enabled

        for target in scanner_record.queue_targets:
            if target.hostname in domain_map:
                domain_map[target.hostname]["queued_timestamp"] = target.timestamp
                domain_map[target.hostname]["queue_status"] = "Queued"
                if target.scan_timestamp:
                    domain_map[target.hostname]["queue_status"] = "Processing"

    results: list[models.SearchResult] = []
    for host, data in domain_map.items():
        results.append(
            models.SearchResult(
                ip_addr=data["ip_addr"],
                resolved_ip=data.get(
                    "resolved_ip", services.helpers.retrieve_ip_for_host(host)
                ),
                hostname=host,
                ports=data.get("ports", []),
                reports=data.get("reports", []),
                last_scanned=None
                if not data.get("timestamps")
                else max(data["timestamps"]),
                monitoring=data["monitoring"],
                queue_status=data.get("queue_status"),
                queued_timestamp=data.get("queued_timestamp"),
            )
        )  # type: ignore

    return results


@router.get(
    "/ip/{ip_addr}",
    response_model=list[models.SearchResult],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No search results matching this query"},
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

    scans_map = {}
    prefix_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/results/"  # type: ignore
    matches = services.aws.list_s3(prefix_key=prefix_key)
    for match in matches:
        if not match.endswith("summary.json"):
            continue
        report_id, _ = match.replace(prefix_key, "").split("/")  # type: ignore
        report = None
        if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
            for summary in scanner_record.history:
                if summary.report_id == report_id:
                    report = summary
                    break
        if report:
            for host in report.targets:  # type: ignore
                scans_map.setdefault(host.transport.hostname, {"reports": []})  # type: ignore
                scans_map[host.transport.hostname]["reports"].append(report_id)  # type: ignore

    if history_raw := services.aws.get_s3(path_key=f"{internals.APP_ENV}/accounts/{authz.account.name}/scan-history.json"):  # type: ignore
        scans_map: dict[str, dict[str, list[str]]] = json.loads(history_raw)

    rdns = None
    try:
        rdns = socket.getnameinfo((str(ip_addr), 0), 0)[0]
    except:
        pass  # pylint: disable=bare-except
    domain_map = {}
    if rdns:
        domain_map.setdefault(
            rdns,
            {
                "timestamps": set(),
                "resolved_ip": services.helpers.retrieve_ip_for_host(rdns),
                "ports": set(),
                "reports": set(),
                "monitoring": False,
            },
        )
    prefix_key = f"{internals.APP_ENV}/hosts/"
    matches = services.aws.list_s3(prefix_key=prefix_key)
    for match in matches:
        if match.endswith("latest.json"):
            continue
        _, _, hostname, port, peer_address, scan_date = match.split("/")
        target = f"{hostname}:{port}"
        if peer_address == str(ip_addr):
            domain_map.setdefault(
                hostname,
                {
                    "timestamps": set(),
                    "ports": set(),
                    "reports": set(),
                    "monitoring": False,
                },
            )
            timestamp = (
                datetime.strptime(scan_date.replace(".json", ""), "%Y%m%d").timestamp()
                * 1000
            )
            domain_map[hostname]["timestamps"].add(timestamp)
            domain_map[hostname]["ports"].add(int(port))
            if target in scans_map:
                domain_map[hostname]["reports"].update(scans_map[target]["reports"])

    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        for target in scanner_record.monitored_targets:
            if target.hostname in domain_map:
                domain_map[target.hostname]["monitoring"] = target.enabled

    if not domain_map:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    results: list[models.SearchResult] = []
    for host, data in domain_map.items():
        results.append(
            models.SearchResult(
                ip_addr=[] if data.get("resolved_ip") else [ip_addr],
                resolved_ip=data.get(
                    "resolved_ip", services.helpers.retrieve_ip_for_host(host)
                ),
                hostname=host,
                ports=data["ports"],
                reports=data["reports"],
                last_scanned=None
                if not data.get("timestamps")
                else max(data["timestamps"]),
                monitoring=data["monitoring"],
            )
        )  # type: ignore

    return results
