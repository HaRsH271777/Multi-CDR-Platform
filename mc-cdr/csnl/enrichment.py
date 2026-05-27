from datetime import timezone
import ipaddress

from csnl.schema import NormalizedEvent


def _is_private_or_loopback(ip_value: str) -> bool | None:
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return None
    return ip_obj.is_private or ip_obj.is_loopback


def enrich(event: NormalizedEvent) -> NormalizedEvent:
    source_ip = event.source_ip
    if source_ip is None:
        is_private_ip = None
    else:
        is_private_ip = _is_private_or_loopback(source_ip)

    timestamp = event.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp_utc = timestamp.astimezone(timezone.utc)

    enrichments = dict(event.enrichments)
    enrichments["is_private_ip"] = is_private_ip
    enrichments["is_off_hours"] = timestamp_utc.hour < 9 or timestamp_utc.hour > 17
    enrichments["day_of_week"] = timestamp_utc.strftime("%A")

    event.enrichments = enrichments
    return event
