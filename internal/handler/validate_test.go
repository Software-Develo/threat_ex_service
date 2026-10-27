package handler

import (
	"strings"
	"testing"

	"github.com/Software-Develo/threat_ex_service/internal/storage"
)


func validThreat() storage.Threat {
	return storage.Threat{
		Name:       "Trojan.Win32.Generic",
		Type:       "trojan",
		Severity:   "high",
		VulnStatus: "unknown",
	}
}

func strPtr(s string) *string {
	return &s
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(th *storage.Threat) // что испортить в корректной записи
		wantErr bool
	}{
		{"valid as is", func(th *storage.Threat) {}, false},

		{"empty name", func(th *storage.Threat) { th.Name = "" }, true},
		{"spaces-only name", func(th *storage.Threat) { th.Name = "   " }, true},
		{"name 255 chars", func(th *storage.Threat) { th.Name = strings.Repeat("a", 255) }, false},
		{"name 256 chars", func(th *storage.Threat) { th.Name = strings.Repeat("a", 256) }, true},
		{"cyrillic name 255 chars", func(th *storage.Threat) { th.Name = strings.Repeat("я", 255) }, false},

		{"unknown type", func(th *storage.Threat) { th.Type = "banana" }, true},
		{"empty type", func(th *storage.Threat) { th.Type = "" }, true},
		{"unknown severity", func(th *storage.Threat) { th.Severity = "extreme" }, true},
		{"unknown vuln_status", func(th *storage.Threat) { th.VulnStatus = "fixed" }, true},

		{"description 1000 chars", func(th *storage.Threat) { th.Description = strings.Repeat("a", 1000) }, false},
		{"description 1001 chars", func(th *storage.Threat) { th.Description = strings.Repeat("a", 1001) }, true},

		{"valid sha256", func(th *storage.Threat) { th.SHA256 = strPtr(strings.Repeat("a", 64)) }, false},
		{"short sha256", func(th *storage.Threat) { th.SHA256 = strPtr("abc") }, true},
		{"non-hex sha256", func(th *storage.Threat) { th.SHA256 = strPtr(strings.Repeat("z", 64)) }, true},

		{"valid cve", func(th *storage.Threat) { th.CVE = []string{"CVE-2017-0144"} }, false},
		{"malformed cve", func(th *storage.Threat) { th.CVE = []string{"cve-abc"} }, true},
		{"21 cve items", func(th *storage.Threat) { th.CVE = make([]string, 21) }, true},

		{"playbook step 500 chars", func(th *storage.Threat) { th.Playbook = []string{strings.Repeat("a", 500)} }, false},
		{"playbook step 501 chars", func(th *storage.Threat) { th.Playbook = []string{strings.Repeat("a", 501)} }, true},
		{"21 playbook steps", func(th *storage.Threat) { th.Playbook = make([]string, 21) }, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			th := validThreat()
			tc.mutate(&th)

			err := validate(th)
			if (err != nil) != tc.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}