from datetime import datetime

import models

def date_label(date: datetime) -> tuple[str, str]:
    label = "a moment ago"
    group: str
    now = datetime.utcnow()
    cur_year = now.strftime("%Y")
    cur_month = now.strftime("%b")
    year = date.strftime("%Y")
    month = date.strftime("%b")
    delta = now - date
    if year != cur_year:
        group = "year"
        if delta.days < 730:
            label = "1 year ago"
        else:
            label = f"{round(delta.days/365, 0)} years ago"
    if month != cur_month:
        group = "month"
        if delta.days <= 60:
            label = "1 month ago"
        else:
            label = f"{round(delta.days/30, 0)} months ago"
    else:
        group = "week"
        if delta.days == 0:
            label = "today"
        elif delta.days == 1:
            label = "1 day ago"
        elif delta.days <= 30:
            label = f"{delta.days} days ago"
    return label, group


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
    passive_total = 0
    active_total = 0
    if sub := models.SubscriptionAddon().load(account.name):  # type: ignore
        unlimited_scans = True
        new_only = False
    if sub := models.SubscriptionBooster().load(account.name):  # type: ignore
        monitoring_total = 1 if sub.quantity is None else sub.quantity + 1
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
        monitoring_total = None
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
