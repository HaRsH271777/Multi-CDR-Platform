package aws

import (
    "context"
    "strconv"
    "testing"
    "time"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
    "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

type mockCloudTrailClient struct {
    events   []types.Event
    pageSize int
}

// LookupEvents returns paginated events for testing.
func (m *mockCloudTrailClient) LookupEvents(ctx context.Context, input *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
    startIndex := 0
    if input.NextToken != nil {
        parsed, err := strconv.Atoi(*input.NextToken)
        if err == nil {
            startIndex = parsed
        }
    }

    endIndex := startIndex + m.pageSize
    if endIndex > len(m.events) {
        endIndex = len(m.events)
    }

    var nextToken *string
    if endIndex < len(m.events) {
        token := strconv.Itoa(endIndex)
        nextToken = aws.String(token)
    }

    return &cloudtrail.LookupEventsOutput{
        Events:    m.events[startIndex:endIndex],
        NextToken: nextToken,
    }, nil
}

// TestCollectorProcessesAllEvents validates that the collector forwards all events.
func TestCollectorProcessesAllEvents(t *testing.T) {
    events := make([]types.Event, 50)
    client := &mockCloudTrailClient{events: events, pageSize: 10}
    ch := make(chan RawEvent, 100)

    collector := NewCollectorWithClient(client, ch)
    collector.collectEvents(context.Background(), time.Now().Add(-time.Minute), time.Now())

    if got := len(ch); got != 50 {
        t.Fatalf("expected 50 events, got %d", got)
    }
}

// TestCollectorHandlesMalformedEvent ensures a malformed event does not crash the collector.
func TestCollectorHandlesMalformedEvent(t *testing.T) {
    client := &mockCloudTrailClient{events: []types.Event{{}}, pageSize: 1}
    ch := make(chan RawEvent, 10)

    collector := NewCollectorWithClient(client, ch)
    collector.collectEvents(context.Background(), time.Now().Add(-time.Minute), time.Now())

    if got := len(ch); got != 1 {
        t.Fatalf("expected 1 event, got %d", got)
    }
}
