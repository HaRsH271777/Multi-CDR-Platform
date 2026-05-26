from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import threading
import time
from typing import Any

from azure.monitor.query import LogsQueryClient
from azure.identity import DefaultAzureCredential

logger = logging.getLogger(__name__)


@dataclass
class CollectorMetrics:
    events_collected: int = 0
    errors: int = 0
    last_poll: str | None = None

    def log_snapshot(self) -> None:
        """Log a snapshot of current metrics for observability."""
        logger.info(
            "collector metrics: events=%d errors=%d last_poll=%s",
            self.events_collected,
            self.errors,
            self.last_poll,
        )


class AzureActivityLogCollector:
    """Collects Azure Activity Logs and enqueues raw payloads."""

    def __init__(self, workspace_id: str, event_queue: Any):
        self.credential = DefaultAzureCredential()
        self.client = LogsQueryClient(self.credential)
        self.workspace_id = workspace_id
        self.event_queue = event_queue
        self.metrics = CollectorMetrics()
        self._metrics_thread: threading.Thread | None = None
        self._stop_metrics = threading.Event()

    def start_metrics_logger(self, interval_seconds: int = 60) -> None:
        """Start a background loop that logs metrics every interval."""
        if self._metrics_thread and self._metrics_thread.is_alive():
            return

        self._stop_metrics.clear()

        def _loop() -> None:
            while not self._stop_metrics.is_set():
                self.metrics.log_snapshot()
                time.sleep(interval_seconds)

        self._metrics_thread = threading.Thread(target=_loop, daemon=True)
        self._metrics_thread.start()

    def stop_metrics_logger(self) -> None:
        """Stop the background metrics logging loop."""
        self._stop_metrics.set()

    def poll(self, lookback_minutes: int = 5) -> None:
        """Query Activity Logs and enqueue each event payload."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=lookback_minutes)

        query = """
        AzureActivity
        | where TimeGenerated between (datetime({start}) .. datetime({end}))
        | project TimeGenerated, Caller, OperationName, ResourceGroup,
                  ResourceId, ActivityStatus, Properties, CallerIpAddress
        """.format(
            start=start_time.isoformat(),
            end=end_time.isoformat(),
        )

        try:
            response = self.client.query_workspace(
                workspace_id=self.workspace_id,
                query=query,
                timespan=timedelta(minutes=lookback_minutes),
            )
            for table in response.tables:
                for row in table.rows:
                    try:
                        event = dict(zip(table.columns, row))
                        self.event_queue.put(
                            {
                                "provider": "azure",
                                "collected_at": datetime.now(timezone.utc).isoformat(),
                                "raw_payload": event,
                            }
                        )
                        self.metrics.events_collected += 1
                    except Exception as exc:
                        self.metrics.errors += 1
                        logger.error("Azure event enqueue error: %s", exc)
            self.metrics.last_poll = end_time.isoformat()

        except Exception as exc:
            self.metrics.errors += 1
            logger.error("Azure collection error: %s", exc)
