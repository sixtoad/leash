package leashversion

import (
	"reflect"
	"testing"
)

// TestContractBoundsAreTheLiteralsTheDocsPublish pins the two integers to the
// values CHANGELOG.md, docs/api-contracts-leash-core.md and docs/DEVELOPMENT.md
// print. It is written as literals on purpose: an assertion phrased against the
// constants themselves ("ContractVersion >= 1") compares the constant to itself
// and cannot fail. Changing either number is a contract event — update the docs
// and this test together, deliberately.
func TestContractBoundsAreTheLiteralsTheDocsPublish(t *testing.T) {
	t.Parallel()

	if ContractVersion != 1 {
		t.Fatalf("ContractVersion = %d, want 1 (the value the docs publish); bumping it is a contract change — update the docs and this test", ContractVersion)
	}
	if MinCompatibleContract != 0 {
		t.Fatalf("MinCompatibleContract = %d, want 0 (contract 1 removed nothing); raising it refuses every older caller — update the docs and this test", MinCompatibleContract)
	}
}

// TestCapabilitiesArePinned pins the advertised surface names. They are wire
// values a provisioner compares against string literals of its own, so a typo or
// a rename is a break even though the field is additive.
func TestCapabilitiesArePinned(t *testing.T) {
	t.Parallel()

	want := []string{"policy", "inject-service", "runtime", "user", "require-lsm", "version-json"}
	if got := Capabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Capabilities() = %v, want %v", got, want)
	}
}

// TestCapabilitiesReturnsACopy: the document is read by callers that may hold
// and mutate the slice; the package's own list must not be reachable through it.
func TestCapabilitiesReturnsACopy(t *testing.T) {
	t.Parallel()

	first := Capabilities()
	first[0] = "clobbered"
	if got := Capabilities()[0]; got != "policy" {
		t.Fatalf("Capabilities()[0] = %q after a caller mutated an earlier result, want %q", got, "policy")
	}
}

// TestCheckCallerRange pins the rule the contract documents:
// minCompatibleContract <= callerContract <= contractVersion. The Info is built
// by hand with a range open on both sides, which the real constants ([0,1]) do
// not yet have, so both failure directions are exercised.
func TestCheckCallerRange(t *testing.T) {
	t.Parallel()

	leash := Info{MinCompatibleContract: 2, ContractVersion: 4}

	tests := []struct {
		name           string
		callerContract int
		want           Compatibility
	}{
		{name: "caller below the floor: leash dropped its surface", callerContract: 1, want: "leash-too-new"},
		{name: "caller at the floor", callerContract: 2, want: "compatible"},
		{name: "caller inside the range", callerContract: 3, want: "compatible"},
		{name: "caller at the ceiling", callerContract: 4, want: "compatible"},
		{name: "caller above the ceiling: leash predates its surface", callerContract: 5, want: "leash-too-old"},
		{name: "pre-feature caller is below this floor too", callerContract: 0, want: "leash-too-new"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := leash.CheckCaller(tt.callerContract); got != tt.want {
				t.Fatalf("CheckCaller(%d) = %q, want %q", tt.callerContract, got, tt.want)
			}
			if got, want := leash.SupportsCaller(tt.callerContract), tt.want == "compatible"; got != want {
				t.Fatalf("SupportsCaller(%d) = %t, want %t", tt.callerContract, got, want)
			}
		})
	}
}

// TestCheckCallerAgainstTheDocumentThisBuildEmits uses the shipped bounds, with
// the outcomes written as literals rather than derived from the constants.
// Contract 0 — a caller written before `version --json` existed — is compatible
// with this build because contract 1 removed nothing.
func TestCheckCallerAgainstTheDocumentThisBuildEmits(t *testing.T) {
	t.Parallel()

	info := Info{ContractVersion: ContractVersion, MinCompatibleContract: MinCompatibleContract}

	tests := []struct {
		callerContract int
		want           Compatibility
	}{
		{callerContract: 0, want: "compatible"},
		{callerContract: 1, want: "compatible"},
		{callerContract: 2, want: "leash-too-old"},
	}
	for _, tt := range tests {
		if got := info.CheckCaller(tt.callerContract); got != tt.want {
			t.Fatalf("CheckCaller(%d) = %q, want %q", tt.callerContract, got, tt.want)
		}
	}
}

// TestHasCapability covers the reason the field exists: a caller that drives one
// flag can ask for that flag instead of being refused by an integer bumped for
// an unrelated removal.
func TestHasCapability(t *testing.T) {
	t.Parallel()

	// A hypothetical future leash: it dropped --inject-service and raised the
	// floor past a contract-1 caller, but still offers --policy.
	future := Info{
		ContractVersion:       4,
		MinCompatibleContract: 4,
		Capabilities:          []string{"policy", "runtime", "user", "require-lsm", "version-json"},
	}
	if got := future.CheckCaller(1); got != "leash-too-new" {
		t.Fatalf("CheckCaller(1) = %q, want %q", got, "leash-too-new")
	}
	if !future.HasCapability("policy") {
		t.Fatal(`HasCapability("policy") = false, want true: the integer over-refuses, the capability is the point`)
	}
	if future.HasCapability("inject-service") {
		t.Fatal(`HasCapability("inject-service") = true, want false: it was removed`)
	}

	// A document from a leash that predates the field decodes with it empty.
	var older Info
	if older.HasCapability("policy") {
		t.Fatal(`HasCapability on a document with no capabilities = true, want false`)
	}
}

// TestParseReadsTheWireDocument is the consumer path: the bytes are a literal of
// what an installed binary prints, not something this package produced, so a
// renamed JSON tag fails here.
func TestParseReadsTheWireDocument(t *testing.T) {
	t.Parallel()

	stdout := []byte(`{
  "version": "v0.2.0",
  "commit": "c686025-dirty",
  "builtAt": "2026-07-21T10:11:12Z",
  "enforcing": true,
  "contractVersion": 3,
  "minCompatibleContract": 2,
  "capabilities": [
    "policy",
    "runtime"
  ],
  "os": "linux",
  "arch": "amd64"
}
`)

	got, err := Parse(stdout)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := Info{
		Version:               "v0.2.0",
		Commit:                "c686025-dirty",
		BuiltAt:               "2026-07-21T10:11:12Z",
		Enforcing:             true,
		ContractVersion:       3,
		MinCompatibleContract: 2,
		Capabilities:          []string{"policy", "runtime"},
		OS:                    "linux",
		Arch:                  "amd64",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse(...) = %+v, want %+v", got, want)
	}

	// And the decoded document drives the comparison a provisioner runs.
	if got.SupportsCaller(1) {
		t.Fatal("SupportsCaller(1) = true against a leash whose floor is 2, want false")
	}
	if !got.SupportsCaller(2) {
		t.Fatal("SupportsCaller(2) = false against the range [2,3], want true")
	}
	if !got.HasCapability("policy") {
		t.Fatal(`HasCapability("policy") = false, want true`)
	}
}

// TestParseRejectsNonDocuments: per the contract, output that does not parse
// means contract 0, so the error must be reported rather than yielding a
// zero-value Info the caller might mistake for a real one.
func TestParseRejectsNonDocuments(t *testing.T) {
	t.Parallel()

	for _, stdout := range []string{"", "leash: unknown command \"version\"\n", "{"} {
		if _, err := Parse([]byte(stdout)); err == nil {
			t.Fatalf("Parse(%q) error = nil, want one", stdout)
		}
	}
}
