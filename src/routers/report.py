import json
from os import path
from secrets import token_urlsafe
from typing import Union
from datetime import timedelta
from time import time

from fastapi import Header, APIRouter, Response, File, UploadFile, status, Depends
from cachier import cachier
from pusher import Pusher
from boto3.dynamodb.conditions import Key

import internals
import models
import config
import services.aws
import services.helpers
import services.sendgrid
import services.webhook
from config.sets import ALERT_DETAIL

router = APIRouter()


@router.get(
    "/reports",
    response_model=list[models.ReportSummary],
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
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(seconds=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name,
)
def retrieve_reports(
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing a summary of each
    """
    scanner_record = models.ScannerRecord(account_name=authz.account.name)  # type: ignore
    if scanner_record.load(load_history=True):
        summaries = []
        for summary in scanner_record.history:
            if models.FullReport(
                account_name=authz.account.name, report_id=summary.report_id
            ).exists():
                summaries.append(summary)
            else:
                services.aws.delete_dynamodb(
                    item_key={"report_id": summary.report_id},
                    table_name=services.aws.Tables.REPORT_HISTORY,
                )
        return sorted(summaries, key=lambda x: x.date, reverse=True)  # type: ignore

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/summary/{report_id}",
    response_model=models.ReportSummary,
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
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(hours=1),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name + kw.get("report_id"),
)
def retrieve_summary(
    report_id: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a summary of a Trivial Scanner report for the provided report identifier
    """
    if report := models.ReportSummary(
        **services.aws.get_dynamodb(  # type: ignore
            table_name=services.aws.Tables.REPORT_HISTORY,
            item_key={"report_id": report_id},
        )
    ):
        if authz.account.name != report.account_name:
            return Response(status_code=status.HTTP_401_UNAUTHORIZED)
        return report

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/report/{report_id}",
    response_model=models.FullReport,
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
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(minutes=15),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name + str(kw.get("report_id")),
)
def retrieve_full_report(
    report_id: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a full Trivial Scanner report for the provided report identifier
    """
    report = models.FullReport(report_id=report_id, account_name=authz.account.name)  # type: ignore
    if not report.load():
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    report.evaluations = services.helpers.load_descriptions(report)
    scanner_record = models.ScannerRecord(account_name=authz.account.name)  # type: ignore
    if scanner_record.load():
        for host in report.targets:  # pylint: disable=not-an-iterable
            for target in scanner_record.monitored_targets:  # type: ignore
                if target.hostname == host.transport.hostname:
                    host.monitoring_enabled = target.enabled

    return report


@router.post(
    "/store/{report_type}",
    status_code=status.HTTP_201_CREATED,
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        412: {
            "description": "When uploading a detailed report, the summary must first be sent"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Scan Reports", "CLI"],
)
async def store(
    response: Response,
    report_type: models.ReportType,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
    x_trivialscan_version: Union[str, None] = Header(default=None),
    files: list[UploadFile] = File(...),
):
    """
    Stores various client report data generated by Trivial Scanner CLI
    """
    file = files[0]
    data = {}
    contents = await file.read()
    if file.filename.endswith(".json"):
        data: dict = json.loads(contents.decode("utf8"))
    if isinstance(data, dict):
        data["version"] = data.get("version", x_trivialscan_version)
        if "token" in data.get("config", {}):
            del data["config"]["token"]
        if "dashboard_api_url" in data.get("config", {}):
            del data["config"]["dashboard_api_url"]

    if report_type is models.ReportType.REPORT:
        data["report_id"] = token_urlsafe(32)
        data["results_uri"] = f'/result/{data["report_id"]}/detail'
        client = models.Client(account_name=authz.account.name, name=data.get("client_name"))  # type: ignore
        client_info = client.client_info if client.load() else None
        report = models.ReportSummary(
            type=models.ScanRecordType.SELF_MANAGED,
            category=models.ScanRecordCategory.RECONNAISSANCE,
            is_passive=True,
            client=client_info,
            **data,
        )
        scanner_record = models.ScannerRecord(account_name=authz.account.name)  # type: ignore
        if not scanner_record.load(load_history=True):
            scanner_record = models.ScannerRecord(account_name=authz.account.name)  # type: ignore
        scanner_record.history.append(report)
        if scanner_record.save():
            services.webhook.send(
                event_name=models.WebhookEvent.SELF_HOSTED_UPLOADS,
                account=authz.account,
                data={
                    "type": models.ScanRecordType.SELF_MANAGED,
                    "status": "report",
                    "timestamp": round(time() * 1000),
                    "account": authz.account.name,
                    "client": authz.client.name,
                    "report_id": report.report_id,
                    "ip_addr": authz.ip_addr,
                    "user_agent": authz.user_agent.ua_string,
                },
            )
            return {"results_uri": data["results_uri"]}

    if report_type is models.ReportType.EVALUATIONS:
        full_report = models.FullReport(**data)
        if not full_report:
            return Response(status_code=status.HTTP_412_PRECONDITION_FAILED)
        if full_report.client_name:
            client = models.Client(account_name=authz.account.name, name=full_report.client_name)  # type: ignore
            if client.load():
                full_report.client = client.client_info
        items = []
        certs = {cert.sha1_fingerprint: cert for cert in full_report.certificates}  # type: ignore pylint: disable=not-an-iterable
        for _item in data["evaluations"]:
            item = models.EvaluationItem(
                generator=full_report.generator,
                version=full_report.version,
                account_name=authz.account.name,
                client_name=full_report.client_name,
                report_id=full_report.report_id,
                observed_at=full_report.date,
                rule_id=_item["rule_id"],
                group=_item["group"],
                group_id=_item["group_id"],
                key=_item["key"],
                name=_item["name"],
                result_value=_item.get("result_value"),
                result_label=_item["result_label"],
                result_text=_item["result_text"],
                result_level=_item["result_level"],
                score=_item["score"],
                description=_item.get(
                    "description",
                    config.get_rule_desc(f"{_item['rule_id']}.{_item['group_id']}"),
                ),
                metadata=_item.get("metadata", {}),
                cve=_item.get("cve", []) or [],
                cvss2=_item.get("cvss2", []) or [],
                cvss3=_item.get("cvss3", []) or [],
                references=[
                    models.ReferenceItem(name=ref["name"], url=ref["url"])
                    for ref in _item.get("references", []) or []
                ],
                compliance=[
                    models.ComplianceGroup(
                        compliance=comp["compliance"],
                        version=comp["version"],
                        items=[
                            models.ComplianceItem(**item)
                            for item in comp.get("items", [])
                        ],
                    )
                    for comp in _item["compliance"]
                ],
                threats=[
                    models.ThreatItem(**threat) for threat in _item.get("threats", [])
                ],
                transport=models.HostTransport(**_item["transport"]),
                certificate=certs.get(_item.get("metadata", {}).get("sha1_fingerprint"))
                if _item.get("group") == "certificate"
                else None,
                recommendation=None,
            )
            items.append(item)

        full_report.evaluations = items
        if full_report.save():
            pusher_client = Pusher(
                app_id=services.aws.get_ssm(
                    f"/{internals.APP_ENV}/{internals.APP_NAME}/Pusher/app-id"
                ),
                key=services.aws.get_ssm(
                    f"/{internals.APP_ENV}/{internals.APP_NAME}/Pusher/key"
                ),
                secret=services.aws.get_ssm(
                    f"/{internals.APP_ENV}/{internals.APP_NAME}/Pusher/secret",
                    WithDecryption=True,
                ),
                cluster="ap4",
                ssl=True,
                json_encoder=internals.JSONEncoder,
            )
            internals.logger.info("Push result")
            pusher_client.trigger(
                full_report.account_name,
                "trivial-scanner-status",
                {
                    "status": "Complete",
                    "client_name": full_report.client_name,
                    "generator": full_report.generator,
                    "version": full_report.version,
                    "report_id": full_report.report_id,
                    "targets": [
                        {
                            "transport": {
                                "hostname": _target.transport.hostname,
                                "port": _target.transport.port,
                            }
                        }
                        for _target in full_report.targets  # type: ignore pylint: disable=not-an-iterable
                    ],
                    "date": full_report.date,
                    "results": full_report.results,
                    "certificates": [cert.sha1_fingerprint for cert in full_report.certificates],  # type: ignore pylint: disable=not-an-iterable
                    "results_uri": full_report.results_uri,
                    "type": models.ScanRecordType.SELF_MANAGED,
                    "category": models.ScanRecordCategory.RECONNAISSANCE,
                    "is_passive": full_report.is_passive,
                    "client": authz.client.client_info.dict(),  # type: ignore
                },
            )
            services.webhook.send(
                event_name=models.WebhookEvent.REPORT_CREATED,
                account=authz.account,
                data={
                    "report_id": full_report.report_id,
                    "timestamp": round(time() * 1000),
                    "account": authz.account.name,
                    "client": authz.client.name,
                    "ip_addr": authz.ip_addr,
                    "user_agent": authz.user_agent.ua_string,
                },
            )
            if authz.account.notifications.self_hosted_uploads:  # type: ignore
                internals.logger.info("Emailing result")
                first_hostname = full_report.targets[
                    0
                ].transport.hostname  # pylint: disable=unsubscriptable-object
                first_port = full_report.targets[
                    0
                ].transport.port  # pylint: disable=unsubscriptable-object
                suffix = ""
                if len(full_report.targets) > 1:
                    suffix = f" +{len(full_report.targets)} hosts"
                email_subject = f"Customer-managed scanner upload {first_hostname}:{first_port}{suffix}"
                sendgrid = services.sendgrid.send_email(
                    subject=email_subject,
                    recipient=authz.account.primary_email,  # type: ignore
                    template="scan_completed",
                    data={
                        "hostname": first_hostname,
                        "port": first_port,
                        "results_uri": full_report.results_uri,
                        "score": full_report.score,
                        "pass_result": full_report.results.get("pass", 0),  # type: ignore
                        "info_result": full_report.results.get("info", 0),  # type: ignore
                        "warn_result": full_report.results.get("warn", 0),  # type: ignore
                        "fail_result": full_report.results.get("fail", 0),  # type: ignore
                    },
                )
                if sendgrid._content:  # pylint: disable=protected-access
                    res = json.loads(
                        sendgrid._content.decode()  # pylint: disable=protected-access
                    )
                    if isinstance(res, dict) and res.get("errors"):
                        internals.logger.error(res.get("errors"))

            for cert in certs.values():
                cert.save()
                services.webhook.send(
                    event_name=models.WebhookEvent.SELF_HOSTED_UPLOADS,
                    account=authz.account,
                    data={
                        "type": models.ScanRecordType.SELF_MANAGED,
                        "status": "certificate",
                        "timestamp": round(time() * 1000),
                        "account": authz.account.name,
                        "client": authz.client.name,
                        "sha1_fingerprint": cert.sha1_fingerprint,
                        "ip_addr": authz.ip_addr,
                        "user_agent": authz.user_agent.ua_string,
                    },
                )
            for host in full_report.targets:  # pylint: disable=not-an-iterable
                host.save()
                services.webhook.send(
                    event_name=models.WebhookEvent.SELF_HOSTED_UPLOADS,
                    account=authz.account,
                    data={
                        "type": models.ScanRecordType.SELF_MANAGED,
                        "status": "host_version",
                        "timestamp": round(time() * 1000),
                        "account": authz.account.name,
                        "client": authz.client.name,
                        "ip_addr": authz.ip_addr,
                        "user_agent": authz.user_agent.ua_string,
                        "last_updated": host.last_updated,
                        "hostname": host.transport.hostname,
                        "port": host.transport.port,
                    },
                )
            return {"results_uri": f"/result/{full_report.report_id}/details"}

    if report_type is models.ReportType.CERTIFICATE and file.filename.endswith(".pem"):  # type: ignore
        sha1_fingerprint = file.filename.replace(".pem", "")  # type: ignore
        object_key = path.join(
            internals.APP_ENV, "certificates", f"{sha1_fingerprint}.pem"
        )
        if services.aws.store_s3(object_key, contents):
            services.webhook.send(
                event_name=models.WebhookEvent.SELF_HOSTED_UPLOADS,
                account=authz.account,
                data={
                    "type": models.ScanRecordType.SELF_MANAGED,
                    "status": "certificate",
                    "timestamp": round(time() * 1000),
                    "account": authz.account.name,
                    "client": authz.client.name,
                    "sha1_fingerprint": sha1_fingerprint,
                    "pem": contents.decode(),
                    "ip_addr": authz.ip_addr,
                    "user_agent": authz.user_agent.ua_string,
                },
            )
            return {"results_uri": f"/certificate/{sha1_fingerprint}"}

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


@router.delete(
    "/report/{report_id}",
    status_code=status.HTTP_202_ACCEPTED,
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
    tags=["Scan Reports"],
)
async def delete_report(
    report_id: str,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Deletes a specific ReportSummary within the ScannerRecord, the accompanying FullReport file, and eventually any aggregate evaluation records will be computed out also
    (as they are triggered from the deleted report file)
    """
    services.aws.delete_dynamodb(
        table_name=services.aws.Tables.REPORT_HISTORY, item_key={"report_id": report_id}
    )
    report = models.FullReport(report_id=report_id, account_name=authz.account.name)  # type: ignore
    if report.load():
        report.delete()
        services.webhook.send(
            event_name=models.WebhookEvent.REPORT_DELETED,
            account=authz.account,
            data={
                "report_id": report.report_id,
                "timestamp": round(time() * 1000),
                "account": authz.account.name,
                "member": authz.member.email,
                "ip_addr": authz.ip_addr,
                "user_agent": authz.user_agent.ua_string,
            },
        )
        for item in services.aws.query_dynamodb(
            table_name=services.aws.Tables.FINDINGS,
            IndexName="account_name-index",
            KeyConditionExpression=Key("account_name").eq(authz.account.name),
        ):
            finding = models.Finding(
                **services.aws.get_dynamodb(  # type: ignore
                    table_name=services.aws.Tables.FINDINGS,
                    item_key={"finding_id": item["finding_id"]},
                )
            )
            occurrences = []
            updated = False
            for occurrence in finding.occurrences.copy():
                if occurrence.report_ids and report_id in occurrence.report_ids:
                    updated = True
                    occurrence.report_ids = [
                        rid for rid in occurrence.report_ids.copy() if rid != report_id
                    ]
                if occurrence.report_ids:
                    occurrences.append(occurrence)
            if not occurrences:
                finding.delete()
            elif updated:
                finding.occurrences = occurrences
                finding.save()


@router.get(
    "/early-warning-service/alerts",
    response_model=list[models.EarlyWarningAlert],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No alert data is present for this account"},
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
    tags=["Early Warning Service"],
)
@cachier(
    stale_after=timedelta(seconds=15),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name,
)
def early_warning_service_alerts(
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves early warning service alert
    """

    def make_reference_url(item: models.ThreatIntel) -> Union[str, None]:
        if item.feed_data.get("cidr"):
            if item.source == models.ThreatIntelSource.DARKLIST:
                return (
                    f'https://www.darklist.de/view.php?ip={item.feed_data.get("cidr")}'
                )
            if item.source == models.ThreatIntelSource.TALOS_INTELLIGENCE:
                return f'https://www.talosintelligence.com/reputation_center/lookup?search={item.feed_data.get("cidr")}'
        if item.feed_data.get("ip_address"):
            if item.source == models.ThreatIntelSource.DARKLIST:
                return f'https://www.darklist.de/view.php?ip={item.feed_data.get("ip_address")}'
            if item.source == models.ThreatIntelSource.TALOS_INTELLIGENCE:
                return f'https://www.talosintelligence.com/reputation_center/lookup?search={item.feed_data.get("ip_address")}'
        return None

    scanner_record = models.ScannerRecord(account_name=authz.account.name)  # type: ignore
    if scanner_record.load(load_ews=True):
        return [
            models.EarlyWarningAlert(
                summary=ALERT_DETAIL[threat_intel.source][
                    threat_intel.feed_data.get("category")
                ]["summary"],
                description=ALERT_DETAIL[threat_intel.source][
                    threat_intel.feed_data.get("category")
                ]["description"],
                abuse=ALERT_DETAIL[threat_intel.source][
                    threat_intel.feed_data.get("category")
                ]["abuse"],
                reference_url=make_reference_url(threat_intel),  # type: ignore
                **threat_intel.dict(),
            )
            for threat_intel in scanner_record.ews
        ]
    return Response(status_code=status.HTTP_204_NO_CONTENT)
