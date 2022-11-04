import re
from typing import Union, Any

from dns import resolver, rdatatype
from dns.exception import DNSException, Timeout as DNSTimeoutError
from tldextract.tldextract import TLDExtract
from pydantic import IPvAnyAddress

import models
import internals


def get_quotas(
        account: models.MemberAccount,
        load_monitoring: bool = True,
        load_passive: bool = True,
        load_active: bool = True,
    ) -> models.AccountQuotas:
    active = 0
    passive = 0
    monitoring = 0
    if load_monitoring:
        if monitor := models.Monitor(account=account).load():  # type: ignore
            monitoring = sum(1 if item.enabled else 0 for item in monitor.targets)
    if load_passive:
        pass # TODO
    if load_active:
        pass  # TODO

    new_only = True
    unlimited_monitoring = False
    unlimited_scans = False
    monitoring_total = 1
    passive_total = 1
    active_total = 0
    if sub := models.SubscriptionAddon().load(account.name):  # type: ignore
        unlimited_scans = True
    if sub := models.SubscriptionBasics().load(account.name):  # type: ignore
        monitoring_total = 1 if not sub.metadata else sub.metadata.get("monitoring", 1)
        passive_total = 1 if not sub.metadata else sub.metadata.get("managed_passive", 1)
        active_total = 0 if not sub.metadata else sub.metadata.get("managed_active", 0)
    elif sub := models.SubscriptionPro().load(account.name):  # type: ignore
        monitoring_total = 10 if not sub.metadata else sub.metadata.get("monitoring", 10)
        passive_total = 500 if not sub.metadata else sub.metadata.get("managed_passive", 500)
        active_total = 50 if not sub.metadata else sub.metadata.get("managed_active", 50)
        new_only = False
    elif sub := models.SubscriptionEnterprise().load(account.name):  # type: ignore
        monitoring_total = 50 if not sub.metadata else sub.metadata.get("monitoring", 50)
        passive_total = 1000 if not sub.metadata else sub.metadata.get("managed_passive", 1000)
        active_total = 100 if not sub.metadata else sub.metadata.get("managed_active", 100)
        new_only = False
    elif sub := models.SubscriptionUnlimited().load(account.name):  # type: ignore
        unlimited_scans = True
        unlimited_monitoring = True

    if unlimited_monitoring:
        monitoring_total = None
    if unlimited_scans:
        passive_total = None
        active_total = None
        new_only = False

    return models.AccountQuotas(
        unlimited_monitoring=unlimited_monitoring,
        unlimited_scans=unlimited_scans,
        monitoring={
            models.Quota.PERIOD: "Daily",
            models.Quota.TOTAL: monitoring_total,
            models.Quota.USED: monitoring,
        },
        passive={
            models.Quota.PERIOD: "Only new hosts" if new_only else "Daily",
            models.Quota.TOTAL: passive_total,
            models.Quota.USED: passive,
        },
        active={
            models.Quota.PERIOD: "Daily",
            models.Quota.TOTAL: active_total,
            models.Quota.USED: active,
        },
    )


def parse_authorization_header(authorization_header: str) -> dict[str, str]:
    auth_param_re = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
    auth_param_re = re.compile(r"^\s*" + auth_param_re + r"\s*$")
    unesc_quote_re = re.compile(r'(^")|([^\\]")')
    scheme, pairs_str = authorization_header.split(None, 1)
    parsed_header = {"scheme": scheme}
    pairs = []
    if pairs_str:
        for pair in pairs_str.split(","):
            if not pairs or auth_param_re.match(pairs[-1]):  # type: ignore
                pairs.append(pair)
            else:
                pairs[-1] = pairs[-1] + "," + pair
        if not auth_param_re.match(pairs[-1]):  # type: ignore
            raise ValueError('Malformed auth parameters')
    for pair in pairs:
        (key, value) = pair.strip().split("=", 1)
        # For quoted strings, remove quotes and backslash-escapes.
        if value.startswith('"'):
            value = value[1:-1]
            if unesc_quote_re.search(value):
                raise ValueError("Unescaped quote in quoted-string")
            value = re.compile(r"\\.").sub(lambda m: m.group(0)[1], value)
        parsed_header[key] = value
    return parsed_header


def dns_query(domain_name: str, try_apex: bool = False, resolve_type: rdatatype.RdataType = rdatatype.A) -> Union[resolver.Answer, None]:
    answer = None
    dns_resolver = resolver.Resolver(configure=True)
    internals.logger.info(f"Trying to resolve {resolve_type} for {domain_name}")

    try:
        answer = dns_resolver.resolve(domain_name, resolve_type)
    except (resolver.NoAnswer, resolver.NXDOMAIN):
        internals.logger.warning(f"get_dns {resolve_type} for {domain_name} DNS NoAnswer")
    except DNSTimeoutError:
        internals.logger.warning(f"get_dns {resolve_type} for {domain_name} DNS Timeout")
    except DNSException as ex:
        internals.logger.warning(ex, exc_info=True)
    except ConnectionResetError:
        internals.logger.warning(f"get_dns {resolve_type} for {domain_name} Connection reset by peer")
    except ConnectionError:
        internals.logger.warning(f"get_dns {resolve_type} for {domain_name} Name or service not known")

    tldext = TLDExtract(cache_dir=internals.CACHE_DIR)(f"http://{domain_name}")
    if not answer and try_apex and tldext.registered_domain != domain_name:
        return dns_query(tldext.registered_domain, try_apex=try_apex, resolve_type=resolve_type)
    if not answer:
        return None
    return answer

def retrieve_ip_for_host(hostname: str) -> list[IPvAnyAddress]:
    results = set()
    domains_to_check = set()
    domains_to_check.add(hostname)
    if answer := dns_query(hostname, resolve_type=rdatatype.CNAME):
        try:
            domains_to_check.add(answer.rrset.to_rdataset().to_text().split(' ').pop()[:-1])  # type: ignore
        except: pass  # pylint: disable=bare-except
    for domain in domains_to_check:
        for resolve_type in [rdatatype.A, rdatatype.AAAA]:
            if answer := dns_query(domain, resolve_type=resolve_type):
                results.update(ip.split(' ').pop() for ip in answer.rrset.to_rdataset().to_text().splitlines())  # type: ignore
    return list(results)

def host_scanning_status(
        account: models.MemberAccount,
        hostname: str
    ) -> Union[dict[str, Any], None]:
    response = {
        'monitoring': False,
        'queued_timestamp': None,
        'queue_status': None,
    }
    if monitor := models.Monitor(account=account).load():  # type: ignore
        for target in monitor.targets:
            if target.hostname == hostname:
                response['monitoring'] = target.enabled
    if queue := models.Queue(account=account).load():  # type: ignore
        for target in queue.targets:
            if target.hostname == hostname:
                response["queued_timestamp"] = target.timestamp
                response["queue_status"] = "Queued"
                if target.scan_timestamp:
                    response["queue_status"] = "Processing"

    return response
