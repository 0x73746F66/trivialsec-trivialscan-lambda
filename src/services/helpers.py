from datetime import datetime


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
