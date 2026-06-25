from dataclasses import dataclass
from typing import List
import statistics


@dataclass
class LatencyRecord:
    detection_id: str
    event_timestamp: float
    detection_latency_us: float
    response_latency_us: float
    provider: str

    @property
    def detection_latency_ms(self) -> int:
        return int(self.detection_latency_us / 1000)

    @property
    def response_latency_ms(self) -> int:
        return int(self.response_latency_us / 1000)


class LatencyTracker:
    def __init__(self):
        self.records: List[LatencyRecord] = []

    def record(self, record: LatencyRecord):
        self.records.append(record)

    def report(self) -> dict:
        if not self.records:
            return {}

        latencies_us = [r.response_latency_us for r in self.records]
        latencies_us.sort()
        n = len(latencies_us)

        def percentile(data, p):
            idx = int(len(data) * p / 100)
            return data[min(idx, len(data) - 1)]

        return {
            "sample_size": n,
            "p50_us": round(percentile(latencies_us, 50), 1),
            "p95_us": round(percentile(latencies_us, 95), 1),
            "p50_ms": round(percentile(latencies_us, 50) / 1000, 3),
            "p75_ms": round(percentile(latencies_us, 75) / 1000, 3),
            "p90_ms": round(percentile(latencies_us, 90) / 1000, 3),
            "p95_ms": round(percentile(latencies_us, 95) / 1000, 3),
            "p99_ms": round(percentile(latencies_us, 99) / 1000, 3),
            "mean_ms": round(statistics.mean(latencies_us) / 1000, 3),
            "stdev_ms": round(statistics.stdev(latencies_us) / 1000, 3) if n > 1 else 0,
            "by_provider": {
                provider: {
                    "count": len([r for r in self.records if r.provider == provider]),
                    "p95_ms": round(percentile(
                        sorted(
                            [
                                r.response_latency_us
                                for r in self.records
                                if r.provider == provider
                            ]
                        ),
                        95,
                    ) / 1000, 3),
                }
                for provider in set(r.provider for r in self.records)
            },
        }
