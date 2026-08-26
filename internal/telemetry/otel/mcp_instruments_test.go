package otel

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMCPFinishDoesNotExportSessionIdentifier(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	instruments := &MCPInstruments{
		traceEnabled: true,
		tracer:       provider.Tracer("test"),
	}

	handle, _ := instruments.Start(context.Background(), MCPRequestInfo{
		Server: "mcp.example.test",
		Method: "tools/list",
	})
	instruments.Finish(handle, 200, "success", "sse", "1.1", true, "")

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected one completed span, got %d", len(spans))
	}
	assertSessionPresenceAttributes(t, spans[0].Attributes(), true)
}

func TestMCPFinishOmitsSessionMetadataWhenAbsent(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	instruments := &MCPInstruments{
		traceEnabled: true,
		tracer:       provider.Tracer("test"),
	}

	handle, _ := instruments.Start(context.Background(), MCPRequestInfo{Method: "tools/list"})
	instruments.Finish(handle, 200, "success", "json", "", false, "")

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected one completed span, got %d", len(spans))
	}
	for _, attr := range spans[0].Attributes() {
		if attr.Key == "mcp.session" || attr.Key == "mcp.session_present" {
			t.Fatalf("MCP telemetry reported a session when none was present")
		}
	}
}

func TestMCPFinishMetricsExportOnlySessionPresence(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	instruments := newMCPInstruments(&Provider{
		meterProvider: provider,
		meter:         provider.Meter("test"),
	}, false)

	handle, _ := instruments.Start(context.Background(), MCPRequestInfo{Method: "tools/list"})
	instruments.Finish(handle, 200, "success", "sse", "1.1", true, "")

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatalf("collect MCP metrics: %v", err)
	}
	dataPoints := 0
	for _, scope := range collected.ScopeMetrics {
		for _, metric := range scope.Metrics {
			switch data := metric.Data.(type) {
			case metricdata.Sum[int64]:
				for _, point := range data.DataPoints {
					assertSessionPresenceAttributes(t, point.Attributes.ToSlice(), true)
					dataPoints++
				}
			case metricdata.Histogram[int64]:
				for _, point := range data.DataPoints {
					assertSessionPresenceAttributes(t, point.Attributes.ToSlice(), true)
					dataPoints++
				}
			}
		}
	}
	if dataPoints == 0 {
		t.Fatal("expected MCP metric data points")
	}
}

func assertSessionPresenceAttributes(t *testing.T, attrs []attribute.KeyValue, wantPresent bool) {
	t.Helper()
	foundPresence := false
	for _, attr := range attrs {
		if attr.Key == "mcp.session" {
			t.Fatal("MCP telemetry retained the legacy session value attribute")
		}
		if attr.Key == "mcp.session_present" && attr.Value.AsBool() {
			foundPresence = true
		}
	}
	if foundPresence != wantPresent {
		t.Fatalf("MCP telemetry session presence mismatch: got %t want %t", foundPresence, wantPresent)
	}
}
