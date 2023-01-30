import re
from typing import Union

from dns import resolver, rdatatype
from dns.exception import DNSException, Timeout as DNSTimeoutError
from tldextract.tldextract import TLDExtract
from pydantic import IPvAnyAddress

import config
import models
import models.stripe
import internals


def get_quotas(
    account: models.MemberAccount,
    scanner_record: models.ScannerRecord,
) -> models.AccountQuotas:
    active = 0
    passive = 0
    monitoring = 0
    if len(scanner_record.monitored_targets or []) > 0:  # type: ignore
        monitoring = sum(
            1 if item.enabled else 0 for item in scanner_record.monitored_targets
        )
    if len(scanner_record.history or []) > 0:  # type: ignore
        passive = sum(
            1 if item.is_passive and item.type == models.ScanRecordType.ONDEMAND else 0
            for item in scanner_record.history
        )
        active = sum(
            1
            if not item.is_passive and item.type == models.ScanRecordType.ONDEMAND
            else 0
            for item in scanner_record.history
        )

    new_only = True
    unlimited_monitoring = False
    unlimited_scans = False
    monitoring_total = 1
    passive_total = 1
    active_total = 0
    if sub := models.stripe.SubscriptionAddon().load(account.name):  # type: ignore
        unlimited_scans = True
    if sub := models.stripe.SubscriptionBasics().load(account.name):  # type: ignore
        monitoring_total = 1 if not sub.metadata else sub.metadata.get("monitoring", 1)
        passive_total = (
            1 if not sub.metadata else sub.metadata.get("managed_passive", 1)
        )
        active_total = 0 if not sub.metadata else sub.metadata.get("managed_active", 0)
    elif sub := models.stripe.SubscriptionPro().load(account.name):  # type: ignore
        monitoring_total = (
            10 if not sub.metadata else sub.metadata.get("monitoring", 10)
        )
        passive_total = (
            500 if not sub.metadata else sub.metadata.get("managed_passive", 500)
        )
        active_total = (
            50 if not sub.metadata else sub.metadata.get("managed_active", 50)
        )
        new_only = False
    elif sub := models.stripe.SubscriptionEnterprise().load(account.name):  # type: ignore
        monitoring_total = (
            50 if not sub.metadata else sub.metadata.get("monitoring", 50)
        )
        passive_total = (
            1000 if not sub.metadata else sub.metadata.get("managed_passive", 1000)
        )
        active_total = (
            100 if not sub.metadata else sub.metadata.get("managed_active", 100)
        )
        new_only = False
    elif sub := models.stripe.SubscriptionUnlimited().load(account.name):  # type: ignore
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
    if not answer:
        return None
    return answer


def retrieve_ip_for_host(hostname: str) -> list[IPvAnyAddress]:
    results = set()
    domains_to_check = set()
    domains_to_check.add(hostname)
    if answer := dns_query(hostname, resolve_type=rdatatype.CNAME):
        try:
            domains_to_check.add(answer.rrset.to_rdataset().to_text().split(" ").pop()[:-1])  # type: ignore
        except:
            pass  # pylint: disable=bare-except
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
                        None
                        if not compliance.requirement
                        else config.pcidss4.requirements.get(compliance.requirement, "")
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
                        None
                        if not compliance.requirement
                        else config.pcidss3.requirements.get(compliance.requirement, "")
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
