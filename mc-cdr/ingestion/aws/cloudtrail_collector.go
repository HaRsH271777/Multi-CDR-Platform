package aws

import (
    "context"
    "encoding/json"
    "log"
    "sync/atomic"
    "time"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
    "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// CloudTrailClient defines the interface needed by the paginator.
type CloudTrailClient interface {
    cloudtrail.LookupEventsAPIClient
}

// CloudTrailCollector collects CloudTrail events and forwards raw payloads.
type CloudTrailCollector struct {
    client    CloudTrailClient
    eventChan chan<- RawEvent
    metrics   *CollectorMetrics
}

// CollectorMetrics tracks collection statistics.
type CollectorMetrics struct {
    EventsCollected int64
    ErrorCount      int64
    LastPollUnix    int64
}

// RawEvent represents a provider-specific event payload.
type RawEvent struct {
    Provider    string          `json:"provider"`
    CollectedAt time.Time       `json:"collected_at"`
    RawPayload  json.RawMessage `json:"raw_payload"`
}

// NewCollector builds a CloudTrailCollector with a real AWS client.
func NewCollector(ctx context.Context, eventChan chan<- RawEvent) (*CloudTrailCollector, error) {
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return nil, err
    }
    return NewCollectorWithClient(cloudtrail.NewFromConfig(cfg), eventChan), nil
}

// NewCollectorWithClient builds a collector with an injected client (used for tests).
func NewCollectorWithClient(client CloudTrailClient, eventChan chan<- RawEvent) *CloudTrailCollector {
    return &CloudTrailCollector{
        client:    client,
        eventChan: eventChan,
        metrics:   &CollectorMetrics{},
    }
}

// Poll runs periodic collection and logs metrics every 60 seconds.
func (c *CloudTrailCollector) Poll(ctx context.Context, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    go c.logMetrics(ctx, 60*time.Second)

    startTime := time.Now().Add(-interval)
    for {
        select {
        case <-ticker.C:
            endTime := time.Now()
            c.collectEvents(ctx, startTime, endTime)
            startTime = endTime
            atomic.StoreInt64(&c.metrics.LastPollUnix, endTime.Unix())
        case <-ctx.Done():
            log.Println("collector shutting down")
            return
        }
    }
}

// collectEvents fetches CloudTrail events for a time window and processes them.
func (c *CloudTrailCollector) collectEvents(ctx context.Context, start, end time.Time) {
    input := &cloudtrail.LookupEventsInput{
        StartTime: &start,
        EndTime:   &end,
    }
    paginator := cloudtrail.NewLookupEventsPaginator(c.client, input)

    for paginator.HasMorePages() {
        page, err := paginator.NextPage(ctx)
        if err != nil {
            atomic.AddInt64(&c.metrics.ErrorCount, 1)
            log.Printf("error fetching CloudTrail events: %v", err)
            continue
        }
        for _, event := range page.Events {
            c.processEvent(event)
        }
    }
}

// processEvent serializes and forwards a raw CloudTrail event payload.
func (c *CloudTrailCollector) processEvent(event types.Event) {
    defer func() {
        if r := recover(); r != nil {
            atomic.AddInt64(&c.metrics.ErrorCount, 1)
            log.Printf("panic processing event: %v", r)
        }
    }()

    payload, err := json.Marshal(event)
    if err != nil {
        atomic.AddInt64(&c.metrics.ErrorCount, 1)
        log.Printf("error marshaling CloudTrail event: %v", err)
        return
    }

    c.eventChan <- RawEvent{
        Provider:    "aws",
        CollectedAt: time.Now().UTC(),
        RawPayload:  payload,
    }

    atomic.AddInt64(&c.metrics.EventsCollected, 1)
}

// logMetrics emits metrics snapshots on a fixed interval.
func (c *CloudTrailCollector) logMetrics(ctx context.Context, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            events := atomic.LoadInt64(&c.metrics.EventsCollected)
            errors := atomic.LoadInt64(&c.metrics.ErrorCount)
            lastPoll := time.Unix(atomic.LoadInt64(&c.metrics.LastPollUnix), 0).UTC()
            log.Printf("collector metrics: events=%d errors=%d last_poll=%s", events, errors, lastPoll.Format(time.RFC3339))
        case <-ctx.Done():
            return
        }
    }
}
