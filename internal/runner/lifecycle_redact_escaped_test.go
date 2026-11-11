package runner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLifecycleEscapedCredentialAssignments(t *testing.T) {
	r, err := newLifecycleRedactor("")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"opaque spaced material", `opaque "quoted" material`, "opaque\\material", "opaque\nmaterial",
	} {
		encoded, _ := json.Marshal(map[string]string{"password": secret})
		for depth := 1; depth <= 4; depth++ {
			next, _ := json.Marshal(string(encoded))
			encoded = next[1 : len(next)-1]
			input := "prefix " + string(encoded) + " suffix"
			clean := r.text(input)
			if strings.Contains(clean, "opaque") || strings.Contains(clean, "material") {
				t.Errorf("depth=%d secret persisted: %s", depth, clean)
			}
			if !strings.HasPrefix(clean, "prefix ") || !strings.HasSuffix(clean, " suffix") {
				t.Errorf("surrounding context lost: %s", clean)
			}
		}
	}
	for _, input := range []string{`prefix {\"password\":\"opaque unterminated`, `prefix {\"password\":opaque unquoted`} {
		if clean := r.text(input); strings.Contains(clean, "opaque") {
			t.Errorf("malformed encoded credential persisted: %s", clean)
		}
	}
	ordinary := `prefix {\"message\":\"ordinary quoted text\"} suffix`
	if r.text(ordinary) != ordinary {
		t.Fatal("ordinary text changed")
	}
}
