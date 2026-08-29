package managercontract

import (
	"strings"
	"testing"
)

func validLabels() map[string]string {
	return map[string]string{
		LabelContractVersion:       "2",
		LabelMinCompatibleContract: "1",
		LabelRevision:              "0123456789abcdef",
	}
}

func TestParseAndValidate(t *testing.T) {
	metadata, err := Parse(validLabels())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := Validate(metadata, 1, "0123456789abcdef"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestParseRejectsMissingAndMalformedMetadata(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{name: "missing", labels: nil, want: "no OCI"},
		{name: "bad version", labels: map[string]string{LabelContractVersion: "x"}, want: LabelContractVersion},
		{name: "inverted", labels: map[string]string{LabelContractVersion: "1", LabelMinCompatibleContract: "2", LabelRevision: "abc"}, want: "minimum 2"},
		{name: "missing revision", labels: map[string]string{LabelContractVersion: "1", LabelMinCompatibleContract: "1"}, want: LabelRevision},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.labels)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestValidateRejectsContractAndDefaultRevisionMismatch(t *testing.T) {
	metadata, err := Parse(validLabels())
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(metadata, 3, ""); err == nil || !strings.Contains(err.Error(), "contract mismatch") {
		t.Fatalf("contract error = %v", err)
	}
	if err := Validate(metadata, 1, "different"); err == nil || !strings.Contains(err.Error(), "revision mismatch") {
		t.Fatalf("revision error = %v", err)
	}
	if err := Validate(metadata, 1, ""); err != nil {
		t.Fatalf("compatible override should allow a different revision: %v", err)
	}
}
