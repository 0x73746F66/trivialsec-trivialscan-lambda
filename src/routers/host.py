import json
from os import path
from typing import Union
from datetime import datetime, timedelta

from fastapi import Query, APIRouter, Response, status, Depends
from cachier import cachier
from tldextract import TLDExtract

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
    hash_params=lambda _, kw: kw["authz"].account.name,
)
def retrieve_hosts(
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a distinct list of hosts and ports, optionally returning the latest host
    full record
    """
    scanner_record = models.ScannerRecord(account=authz.account)  # type: ignore
    if not scanner_record.load():
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    seen = set()
    data = []
    for report in scanner_record.history:
        for host in report.targets or []:
            target = f"{host.transport.hostname}:{host.transport.port}"
            if target not in seen:
                seen.add(target)
                data.append(host)
    return data or Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/host/{hostname}",
    response_model=models.HostResponse,
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
    stale_after=timedelta(seconds=1),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name
    + str(kw.get("hostname", ""))
    + str(kw.get("port", ""))
    + str(kw.get("last_updated", "")),
)
def retrieve_host(
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
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves TLS data on any hostname, providing an optional port number
    """
    prefix_key = f"{internals.APP_ENV}/hosts/"
    versions = ["latest"]
    related_domains = set()
    tld = TLDExtract(cache_dir=internals.CACHE_DIR)(f"http://{hostname}")
    if tld.registered_domain != hostname:
        related_domains.add(tld.registered_domain)

    matches = services.aws.list_s3(prefix_key=prefix_key)
    for match in matches:
        if match.endswith("latest.json"):
            if f".{tld.registered_domain}/" in match:
                related = match.split("/")[2]
                if related != hostname:
                    related_domains.add(related)
            continue
        if f"/{hostname}/" not in match:
            continue
        try:
            _port, _ip, date, *_ = (
                match.replace(".json", "")
                .replace(f"{prefix_key}{hostname}/", "")
                .split("/")
            )
            versions.append(f"{_port}/{date}/{_ip}")
        except ValueError:
            print(match)

    if last_updated:
        object_key = None
        scan_date = last_updated.strftime("%Y%m%d")
        if port:
            prefix_key = path.join(prefix_key, str(port))
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
        object_key = path.join(prefix_key, hostname, str(port), "latest.json")

    try:
        ret = services.aws.get_s3(object_key)
        if not ret:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        host = models.Host(**json.loads(ret))
        reports = []
        scanner_record = models.ScannerRecord(account=authz.account)  # type: ignore
        if scanner_record.load():
            for target in scanner_record.monitored_targets:
                if target.hostname == hostname:
                    host.monitoring_enabled = target.enabled
            for record in scanner_record.history:
                reports.extend(
                    record
                    for _host in record.targets
                    if (
                        _host.transport.hostname == hostname
                        and _host.transport.port == port
                    )
                )
        return models.HostResponse(
            host=host,
            versions=versions,
            reports=sorted(reports, key=lambda x: x.date, reverse=True),  # type: ignore
            external_refs={
                "AlienVault OTX": f"https://otx.alienvault.com/indicator/domain/{hostname}",
                "HypeStat": f"https://hypestat.com/info/{hostname}",
                "VirusTotal": f"https://www.virustotal.com/gui/domain/{hostname}/detection.json",
                "Threat Intelligence Platform": f"https://threatintelligenceplatform.com/report/{hostname}",
                "ViewDNS": f"https://viewdns.info/reversewhois/?q={hostname}",
                "TrustScam": f"https://trustscam.com/{hostname}",
                "URLScan": f"https://urlscan.io/search/#page.domain%3A{hostname}",
                "Layered Domains App": f"https://dmns.app/domains?q={hostname}",
                "Whoisology": f"https://whoisology.com/{hostname}",
                "archive.org": f"http://web.archive.org/web/*/{hostname}",
                "Google Cache": f"https://webcache.googleusercontent.com/search?q=cache:{hostname}",
                "Shodan": f"https://www.shodan.io/domain/{hostname}",
                "DomainIQ": f"https://www.domainiq.com/snapshot_history?data={hostname}",
                "Moonsearch": f"https://moonsearch.com/report/{hostname}.html",
                "BuiltWith": f"https://builtwith.com/{hostname}",
                "DNSlytics": f"https://dnslytics.com/domain/{hostname}",
                "Webmaster Tips": f"https://www.wmtips.com/tools/info/{hostname}",
                "Robtex": f"https://www.robtex.com/dns-lookup/{hostname}",
                "Domain Codex": f"https://www.domaincodex.com/search.php?q={hostname}",
                "Website Informer": f"https://website.informer.com/{hostname}",
                "Similarweb": f"https://www.similarweb.com/website/{hostname}/",
                "Moz": f"https://moz.com/domain-analysis?site={hostname}",
                "SpyFu": f"https://www.spyfu.com/overview/domain?query={hostname}",
                "Linkody Backlinks": f"http://bc.linkody.com/en/seo-tools/free-backlink-checker/{hostname}",
                "Censys": f"https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=100&virtual_hosts=INCLUDE&q={hostname}",
                "SecurityTrails": f"https://securitytrails.com/list/apex_domain/{hostname}",
                "Blacklight": f"https://themarkup.org/blacklight?url={hostname}",
                "LeakIX": f"https://leakix.net/domain/{hostname}",
                "Intelligence X": f"https://intelx.io/?s={hostname}",
            },
            related_domains=list(related_domains),
        )

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
