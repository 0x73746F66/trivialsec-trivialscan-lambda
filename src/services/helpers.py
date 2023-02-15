import contextlib
import re
from typing import Union
from datetime import datetime, timezone

from dns import resolver, rdatatype
from dns.exception import DNSException, Timeout as DNSTimeoutError
from tldextract.tldextract import TLDExtract
from pydantic import IPvAnyAddress

import config
import models
import internals
import models.stripe
import services.stripe

MONITORING_HOSTS_CE = 3
ONDEMAND_HOSTS_CE = 1


def get_quotas(
    account: models.MemberAccount,
    scanner_record: models.ScannerRecord,
) -> models.AccountQuotas:
    seen_hosts = set()
    monitoring_hosts = set()
    if len(scanner_record.monitored_targets or []) > 0:
        monitoring_hosts = {
            item.hostname for item in scanner_record.monitored_targets if item.enabled
        }
    ondemand_hosts = set()
    if len(scanner_record.history or []) > 0:
        for report in scanner_record.history:
            for host in report.targets:
                seen_hosts.add(host.transport.hostname)
            if not report.date or report.date < datetime.now(timezone.utc).replace(
                day=1, minute=0, second=0, microsecond=0
            ):
                continue
            if report.type == models.ScanRecordType.ONDEMAND:
                for host in report.targets:
                    ondemand_hosts.add(f"{host.transport.hostname}_{report.report_id}")

    new_only = False
    unlimited_monitoring = False
    unlimited_scans = False
    monitoring_hosts_day = MONITORING_HOSTS_CE
    ondemand_hosts_month = ONDEMAND_HOSTS_CE

    product = None
    if account.billing_client_id:
        if customer := services.stripe.get_customer(account.billing_client_id):
            if (
                subscription_id := customer.get("invoice", {})
                .get("subscription", {})
                .get("id")
            ):
                if subscription := services.stripe.get_subscription(subscription_id):
                    for item in subscription["items"]["data"]:
                        product = services.stripe.PRODUCT_MAP.get(
                            item["price"]["product"]
                        )
                        if product == services.stripe.Product.UNLIMITED_RESCANS:
                            unlimited_scans = True
                        if product == services.stripe.Product.UNLIMITED:
                            unlimited_scans = True
                            unlimited_monitoring = True

    if not product:
        product = services.stripe.Product.COMMUNITY_EDITION
    if stripe_product := services.stripe.get_product(product):
        if product == services.stripe.Product.COMMUNITY_EDITION:
            monitoring_hosts_day = (
                int(
                    stripe_product.get("metadata", {}).get(
                        "monitoring_hosts_day", MONITORING_HOSTS_CE
                    )
                )
                if stripe_product.get("metadata")
                else MONITORING_HOSTS_CE
            )
            new_only = True

        elif product == services.stripe.Product.PROFESSIONAL:
            monitoring_hosts_day = (
                int(
                    stripe_product.get("metadata", {}).get(
                        "monitoring_hosts_day", MONITORING_HOSTS_CE
                    )
                )
                if stripe_product.get("metadata")
                else MONITORING_HOSTS_CE
            )
            ondemand_hosts_month = (
                int(
                    stripe_product.get("metadata", {}).get(
                        "ondemand_hosts_month", ONDEMAND_HOSTS_CE
                    )
                )
                if stripe_product.get("metadata")
                else ONDEMAND_HOSTS_CE
            )

        elif product == services.stripe.Product.ENTERPRISE:
            monitoring_hosts_day = (
                int(
                    stripe_product.get("metadata", {}).get(
                        "monitoring_hosts_day", MONITORING_HOSTS_CE
                    )
                )
                if stripe_product.get("metadata")
                else MONITORING_HOSTS_CE
            )
            ondemand_hosts_month = (
                int(
                    stripe_product.get("metadata", {}).get(
                        "ondemand_hosts_month", ONDEMAND_HOSTS_CE
                    )
                )
                if stripe_product.get("metadata")
                else ONDEMAND_HOSTS_CE
            )

    return models.AccountQuotas(
        seen_hosts=list(seen_hosts),
        monitoring_hosts=list(monitoring_hosts),
        unlimited_monitoring=unlimited_monitoring,
        unlimited_scans=unlimited_scans,
        monitoring={
            models.Quota.PERIOD: "Daily",
            models.Quota.TOTAL: monitoring_hosts_day,
            models.Quota.USED: len(monitoring_hosts),
        },
        ondemand={
            models.Quota.PERIOD: "Once per host" if new_only else "Monthly",
            models.Quota.TOTAL: max(monitoring_hosts_day, 1)
            if new_only
            else ondemand_hosts_month,
            models.Quota.USED: len(ondemand_hosts),
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
            if not pairs or auth_param_re.match(pairs[-1]):
                pairs.append(pair)
            else:
                pairs[-1] = f"{pairs[-1]},{pair}"
        if not auth_param_re.match(pairs[-1]):
            raise ValueError("Malformed auth parameters")
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


def dns_query(
    domain_name: str,
    try_apex: bool = False,
    resolve_type: rdatatype.RdataType = rdatatype.A,
) -> Union[resolver.Answer, None]:
    answer = None
    dns_resolver = resolver.Resolver(configure=True)
    internals.logger.info(f"Trying to resolve {resolve_type} for {domain_name}")

    try:
        answer = dns_resolver.resolve(domain_name, resolve_type)
    except (resolver.NoAnswer, resolver.NXDOMAIN):
        internals.logger.warning(
            f"get_dns {resolve_type} for {domain_name} DNS NoAnswer"
        )
    except DNSTimeoutError:
        internals.logger.warning(
            f"get_dns {resolve_type} for {domain_name} DNS Timeout"
        )
    except DNSException as ex:
        internals.logger.warning(ex, exc_info=True)
    except ConnectionResetError:
        internals.logger.warning(
            f"get_dns {resolve_type} for {domain_name} Connection reset by peer"
        )
    except ConnectionError:
        internals.logger.warning(
            f"get_dns {resolve_type} for {domain_name} Name or service not known"
        )

    tldext = TLDExtract(cache_dir=internals.CACHE_DIR)(f"http://{domain_name}")
    if not answer and try_apex and tldext.registered_domain != domain_name:
        return dns_query(
            tldext.registered_domain, try_apex=try_apex, resolve_type=resolve_type
        )
    return answer or None


def retrieve_ip_for_host(hostname: str) -> list[IPvAnyAddress]:
    results = set()
    domains_to_check = {hostname}
    if answer := dns_query(hostname, resolve_type=rdatatype.CNAME):
        with contextlib.suppress(Exception):
            domains_to_check.add(answer.rrset.to_rdataset().to_text().split(" ").pop()[:-1])  # type: ignore
    for domain in domains_to_check:
        for resolve_type in [rdatatype.A, rdatatype.AAAA]:
            if answer := dns_query(domain, resolve_type=resolve_type):
                results.update(ip.split(" ").pop() for ip in answer.rrset.to_rdataset().to_text().splitlines())  # type: ignore
    return list(results)


def load_descriptions(
    report: Union[models.FullReport, dict, None],
    evaluations: Union[list[Union[models.EvaluationItem, dict]], None] = None,
) -> list[models.EvaluationItem]:
    report_date = None
    report_evaluations: list[models.EvaluationItem] = []
    if isinstance(evaluations, list) and len(evaluations) > 0:
        if isinstance(evaluations[0], dict):
            report_evaluations = [models.EvaluationItem(**evaluation) for evaluation in evaluations]  # type: ignore
        if isinstance(evaluations[0], models.EvaluationItem):
            report_evaluations = evaluations  # type: ignore
    if isinstance(report, dict):
        report_date = report.get("date")
        report_evaluations = [
            models.EvaluationItem(**evaluation)
            for evaluation in report.get("evaluations", []) or []
        ]
    elif isinstance(report, models.FullReport):
        report_date = report.date
        report_evaluations = report.evaluations or []

    for item in report_evaluations:
        if report_date and not item.observed_at:
            item.observed_at = report_date
        if item.cvss2:
            item.references.append(models.ReferenceItem(name=f"CVSSv2 {item.cvss2}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=({item.cvss2})"))  # type: ignore
        if item.cvss3:
            item.references.append(models.ReferenceItem(name=f"CVSSv3.1 {item.cvss3}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?version=3.1&vector={item.cvss3}"))  # type: ignore
        if item.cve:
            for cve in item.cve:
                item.references.append(models.ReferenceItem(name=cve.upper(), url=f"https://nvd.nist.gov/vuln/detail/{cve}"))  # type: ignore
                gsd = cve.upper().replace("CVE", "GSD")
                item.references.append(models.ReferenceItem(name=gsd, url=f"https://gsd.id/{gsd}"))  # type: ignore
                item.references.append(models.ReferenceItem(name=gsd, type=models.ReferenceType.JSON, url=f"https://api.gsd.id/{gsd}"))  # type: ignore

        item.description = config.get_rule_desc(f"{item.group_id}.{item.rule_id}")
        item.recommendation = config.get_rule_recommendation(
            f"{item.group_id}.{item.rule_id}"
        )
        for group in item.compliance or []:
            if (
                config.pcidss4
                and group.compliance == models.ComplianceName.PCI_DSS
                and group.version == "4.0"
            ):
                pci4_items = []
                for compliance in group.items or []:
                    compliance.description = (
                        config.pcidss4.requirements.get(compliance.requirement, "")
                        if compliance.requirement
                        else None
                    )
                    pci4_items.append(compliance)
                group.items = pci4_items
            if (
                config.pcidss3
                and group.compliance == models.ComplianceName.PCI_DSS
                and group.version == "3.2.1"
            ):
                pci3_items = []
                for compliance in group.items or []:
                    compliance.description = (
                        config.pcidss3.requirements.get(compliance.requirement, "")
                        if compliance.requirement
                        else None
                    )
                    pci3_items.append(compliance)
                group.items = pci3_items
            if group.compliance in [
                models.ComplianceName.NIST_SP800_131A,
                models.ComplianceName.FIPS_140_2,
            ]:
                group.items = None

        if config.mitre_attack:
            for threat in item.threats or []:
                for tactic in config.mitre_attack.tactics:
                    if tactic.id == threat.tactic_id:
                        threat.tactic_description = tactic.description
                for data_source in config.mitre_attack.data_sources:
                    if data_source.id == threat.data_source_id:
                        threat.data_source_description = data_source.description
                for mitigation in config.mitre_attack.mitigations:
                    if mitigation.id == threat.mitigation_id:
                        threat.mitigation_description = mitigation.description
                for technique in config.mitre_attack.techniques:
                    if technique.id == threat.technique_id:
                        threat.technique_description = technique.description
                    for sub_technique in technique.sub_techniques or []:
                        if sub_technique.id == threat.sub_technique_id:
                            threat.sub_technique_description = sub_technique.description

    return report_evaluations
