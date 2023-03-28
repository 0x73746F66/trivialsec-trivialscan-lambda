import contextlib
import socket
from datetime import datetime

import validators
from fastapi import APIRouter, Response, status, Depends
from fastapi.responses import RedirectResponse
from pydantic import IPvAnyAddress
from tldextract.tldextract import TLDExtract

import internals
import models
import services.helpers
import services.aws

router = APIRouter()


@router.get(
    "/any/{query}",
    response_model=list[models.SearchResult],
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
    tags=["Search"],
)
async def search_any(
    query: str,
    _: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Search hostname or ip address, returning exact matches and known (scanned, if any) subdomains
    """
    if validators.ipv4(query) or validators.ipv6(query):  # type: ignore
        return RedirectResponse(
            url=f"/search/ip/{query}", status_code=status.HTTP_303_SEE_OTHER
        )
    return RedirectResponse(
        url=f"/search/host/{query}", status_code=status.HTTP_303_SEE_OTHER
    )


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
    hostname: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Search matching hostname, returning exact matches and knowm (scanned, if any) subdomains
    """
    resolved_ip = services.helpers.retrieve_ip_for_host(hostname)
    if len(resolved_ip) == 0:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    domain_map = {
        hostname: {
            "timestamps": set(),
            "resolved_ip": set(resolved_ip),
            "ip_addr": set(),
            "monitoring": False,
            "ports": set(),
            "reports": set(),
        }
    }
    tldext = TLDExtract(cache_dir=internals.CACHE_DIR)(f"http://{hostname}")
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
    scanner_record = models.ScannerRecord(account_name=authz.account.name)  # type: ignore
    scanner_record.load(load_history=True)
    for match in matches:
        if match.endswith("latest.json"):
            continue
        _, _, host, port, peer_address, scan_date = match.split("/")

        if host in [tldext.registered_domain, hostname] or host.endswith(
            f".{tldext.registered_domain}"
        ):
            timestamp = (
                datetime.strptime(scan_date.replace(".json", ""), "%Y%m%d").timestamp()
                * 1000
            )
            domain_map.setdefault(
                host,
                {
                    "timestamps": set(),
                    "ip_addr": set(),
                    "monitoring": False,
                    "ports": set(),
                    "reports": set(),
                },
            )
            domain_map[host]["timestamps"].add(timestamp)
            domain_map[host]["ip_addr"].add(peer_address)
            domain_map[host]["ports"].add(int(port))
            if scanner_record.history:
                domain_map[host]["reports"].update(
                    [
                        report.report_id
                        for report in scanner_record.history
                        if host in [host.transport.hostname for host in report.targets]
                    ]
                )

    for target in scanner_record.monitored_targets:
        if target.hostname in domain_map:
            domain_map[target.hostname]["monitoring"] = target.enabled

    results: list[models.SearchResult] = []
    for host, data in domain_map.items():
        exists = False
        for port in data.get("ports", [443]) or [443]:
            if exists := services.aws.object_exists(
                file_path=f"{internals.APP_ENV}/hosts/{host}/{port}/latest.json"
            ):
                break
        results.append(
            models.SearchResult(
                ip_addr=data["ip_addr"],
                resolved_ip=data.get(
                    "resolved_ip", services.helpers.retrieve_ip_for_host(host)
                ),
                hostname=host,
                ports=data.get("ports", []),
                reports=data.get("reports", []),
                last_scanned=max(data["timestamps"])
                if data.get("timestamps")
                else None,
                monitoring=data["monitoring"],
                queue_status=data.get("queue_status"),
                queued_timestamp=data.get("queued_timestamp"),
                scanned=exists,
            )
        )

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
    ip_addr: IPvAnyAddress,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Search matching hostname, returning exact matches and knowm (scanned, if any) subdomains
    """
    rdns = None
    with contextlib.suppress(Exception):
        rdns = socket.getnameinfo((str(ip_addr), 0), 0)[0]
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

    scanner_record = models.ScannerRecord(account_name=authz.account.name)  # type: ignore
    if scanner_record.load(load_history=True):
        for target in scanner_record.monitored_targets:
            if target.hostname in domain_map:
                domain_map[target.hostname]["monitoring"] = target.enabled

    if not domain_map:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    results: list[models.SearchResult] = [
        models.SearchResult(
            ip_addr=[] if data.get("resolved_ip") else [ip_addr],
            resolved_ip=data.get(
                "resolved_ip", services.helpers.retrieve_ip_for_host(host)
            ),
            hostname=host,
            ports=data["ports"],
            reports=data["reports"],
            last_scanned=max(data["timestamps"]) if data.get("timestamps") else None,
            monitoring=data["monitoring"],
        )  # type: ignore
        for host, data in domain_map.items()
    ]
    return results
