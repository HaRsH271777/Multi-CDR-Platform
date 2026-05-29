import time
from dataclasses import dataclass
from typing import List
import statistics


@dataclass
class LatencyRecord:
    detection_id: str
    event_timestamp: float
    detection_timestamp: float
    response_timestamp: float
    provider: str

    @property
    def detection_latency_ms(self) -> int:
        return int((self.detection_timestamp - self.event_timestamp) * 1000)

    @property
    def response_latency_ms(self) -> int:
        return int((self.response_timestamp - self.event_timestamp) * 1000)


class LatencyTracker:
    def __init__(self):
        self.records: List[LatencyRecord] = []

    def record(self, record: LatencyRecord):
        self.records.append(record)

    def report(self) -> dict:
        if not self.records:
            return {}

        response_latencies = [r.response_latency_ms for r in self.records]
        response_latencies.sort()
        n = len(response_latencies)

        def percentile(data, p):
            idx = int(len(data) * p / 100)
            return data[min(idx, len(data) - 1)]

        return {
            "sample_size": n,
            "p50_ms": percentile(response_latencies, 50),
            "p75_ms": percentile(response_latencies, 75),
            "p90_ms": percentile(response_latencies, 90),
            "p95_ms": percentile(response_latencies, 95),
            "p99_ms": percentile(response_latencies, 99),
            "mean_ms": int(statistics.mean(response_latencies)),
            "stdev_ms": int(statistics.stdev(response_latencies)) if n > 1 else 0,
            "by_provider": {
                provider: {
                    "count": len([r for r in self.records if r.provider == provider]),
                    "p95_ms": percentile(
                        sorted(
                            [
                                r.response_latency_ms
                                for r in self.records
                                if r.provider == provider
                            ]
                        ),
                        95,
                    ),
                }
                for provider in set(r.provider for r in self.records)
            },
        }
