package recordpolicy_test

import (
	"errors"
	"testing"

	"github.com/oarlock/oarlock/internal/recordpolicy"
	"github.com/oarlock/oarlock/pkg/plugin"
)

func TestDefaultRecordInputIsUsedWhenNoRuleMatches(t *testing.T) {
	got, err := (recordpolicy.RecordInput{Default: false}).Resolve(
		&plugin.Principal{ID: "phuc@example.com"},
		&plugin.Device{ID: "treadmill-4821"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("record_input resolved true, want default false")
	}
}

func TestRecordInputMatchesDeviceTagsAndPrincipalGroups(t *testing.T) {
	policy := recordpolicy.RecordInput{Rules: []recordpolicy.Rule{
		{
			Name:  "pci devices",
			When:  recordpolicy.Selector{DeviceTags: map[string]string{"pci_scope": "true"}},
			Value: true,
		},
	}}
	got, err := policy.Resolve(
		&plugin.Principal{ID: "phuc@example.com", Groups: []string{"apac-staff"}},
		&plugin.Device{ID: "treadmill-4821", Tags: map[string]string{"pci_scope": "true"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("record_input resolved false, want true")
	}
}

func TestRecordInputConflictNamesBothRules(t *testing.T) {
	policy := recordpolicy.RecordInput{Rules: []recordpolicy.Rule{
		{
			Name:  "pci capture",
			When:  recordpolicy.Selector{DeviceTags: map[string]string{"pci_scope": "true"}},
			Value: true,
		},
		{
			Authority: "employment-law",
			When:      recordpolicy.Selector{PrincipalGroups: []string{"eu-*"}},
			Value:     false,
		},
	}}
	_, err := policy.Resolve(
		&plugin.Principal{ID: "ana@example.com", Groups: []string{"eu-staff"}},
		&plugin.Device{ID: "treadmill-4821", Tags: map[string]string{"pci_scope": "true"}},
	)
	if err == nil {
		t.Fatal("expected conflict")
	}
	var conflict *recordpolicy.ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %T %v, want ConflictError", err, err)
	}
	if conflict.First != "pci capture" || conflict.Second != "employment-law" {
		t.Fatalf("conflict = %+v", conflict)
	}
}

func TestRecordInputValidatesPatterns(t *testing.T) {
	err := (recordpolicy.RecordInput{Rules: []recordpolicy.Rule{{
		When: recordpolicy.Selector{Principals: []string{"["}},
	}}}).Validate()
	if err == nil {
		t.Fatal("expected invalid pattern")
	}
}
