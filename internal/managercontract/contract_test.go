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

func TestParseCLI(t *testing.T) {
	labels := validLabels()
	labels[LabelVersion] = " native-v0.4.0 "
	labels[LabelCLIContractVersion] = "3"
	labels[LabelCLIMinCompatibleContract] = "0"
	labels[LabelCapabilities] = "policy, runtime,policy,manager-inspect"
	cli, err := ParseCLI(labels)
	if err != nil {
		t.Fatal(err)
	}
	if cli.Version != "native-v0.4.0" || cli.ContractVersion == nil || *cli.ContractVersion != 3 ||
		cli.MinCompatibleContract == nil || *cli.MinCompatibleContract != 0 || !cli.CapabilitiesPresent {
		t.Fatalf("cli = %+v", cli)
	}
	if strings.Join(cli.Capabilities, ",") != "policy,runtime,manager-inspect" {
		t.Fatalf("capabilities = %v", cli.Capabilities)
	}

	old, err := ParseCLI(validLabels())
	if err != nil || old.ContractVersion != nil || old.MinCompatibleContract != nil || old.CapabilitiesPresent || len(old.Capabilities) != 0 || old.Capabilities == nil {
		t.Fatalf("unlabeled image = %+v, %v", old, err)
	}

	for name, bad := range map[string]map[string]string{
		"negative":   {LabelCLIContractVersion: "-1"},
		"text":       {LabelCLIMinCompatibleContract: "x"},
		"inverted":   {LabelCLIContractVersion: "1", LabelCLIMinCompatibleContract: "2"},
		"empty name": {LabelCapabilities: "policy,,runtime"},
	} {
		if _, err := ParseCLI(bad); err == nil {
			t.Errorf("%s: ParseCLI accepted %v", name, bad)
		}
	}
}
