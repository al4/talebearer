package internal

import (
	"fmt"
	"strings"
	"testing"

	vaultApi "github.com/hashicorp/vault/api"

	"github.com/al4/talebearer/vault"
)

func TestNewSecret_FetchingFallback(t *testing.T) {
	example := "secret/example!key:fallbackPassword"

	s, err := NewSecret(example)
	if err != nil {
		t.Error(err)
	}
	if s.Value() != "fallbackPassword" {
		t.Error("Expected value 'fallbackPassword'")
	}
}

func TestNewSecret_WithNoFallback(t *testing.T) {
	example := "secret/example!key"

	s, err := NewSecret(example)
	if err != nil {
		t.Error(err)
	}

	if s.(*VaultSecret).path != "secret/example" {
		t.Error("path did not match 'secret/example'")
	}
	if s.Value() != "" {
		t.Error("s.Value() was not an empty string")
	}
}

func TestNewSecret_WithErrors(t *testing.T) {
	example := "secret/example/missingKey"

	s, err := NewSecret(example)
	if err == nil {
		t.Error("expected an error")
	}

	expected := "does not contain a `!` separator"
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("error did not contain expected string: %s", expected)
	}
	if nil != s {
		t.Error("s should be nil")
	}
}

func TestRetrieve_ExistingSecret(t *testing.T) {
	example := "secret/example!testKey"

	s, err := NewSecret(example)
	if err != nil {
		t.Error(err)
	}

	testData := make(map[string]interface{})
	testData["testKey"] = "testValue"
	returnSecret := vaultApi.Secret{
		Data: testData,
	}
	mockClient := &vault.MockClient{
		ReturnSecret: &returnSecret,
	}
	mockClient.On("Read", "secret/example")

	err = s.Retrieve(mockClient)
	if err != nil {
		t.Error(err)
	}
	if s.Value() != "testValue" {
		t.Errorf("s.Value() != 'testValue' (got %s)", s.Value())
	}
}

func TestRetrieve_KvAPIv2(t *testing.T) {
	example := "secret/example!testKey"

	s, err := NewSecret(example)
	if err != nil {
		t.Error(err)
	}

	// KV v2 buries the data another level down
	testData := make(map[string]interface{})
	testDataData := make(map[string]interface{})
	testDataData["testKey"] = "testValue"
	testData["data"] = testDataData
	returnSecret := vaultApi.Secret{
		Data: testData,
	}
	mockClient := &vault.MockClient{
		ReturnSecret: &returnSecret,
	}
	mockClient.On("Read", "secret/example")

	err = s.Retrieve(mockClient)
	if err != nil {
		t.Error(err)
	}
	if s.Value() != "testValue" {
		t.Errorf("s.Value() != 'testValue' (got %s)", s.Value())
	}
}

func TestRetrieve_MissingDocument(t *testing.T) {
	example := "secret/missing!key"

	s, err := NewSecret(example)
	if err != nil {
		t.Error(err)
	}
	mockClient := &vault.MockClient{
		ReturnError: fmt.Errorf("document missing"),
	}
	mockClient.On("Read", "secret/missing")

	err = s.Retrieve(mockClient)
	if err == nil {
		t.Error("expected an error")
	}
	expected := "document missing"
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("expected error to contain '%s', got '%s'", expected, err)
	}
}

func TestRetrieve_MissingKeyFromValidDocument(t *testing.T) {
	example := "secret/example!missing_key"

	s, err := NewSecret(example)
	if err != nil {
		t.Error(err)
	}
	testData := make(map[string]interface{})
	returnSecret := vaultApi.Secret{
		Data: testData,
	}
	mockClient := &vault.MockClient{
		ReturnSecret: &returnSecret,
	}
	mockClient.On("Read", "secret/example")

	err = s.Retrieve(mockClient)
	if err == nil {
		t.Error("expected an error")
	}
	expected := "does not contain key missing_key"
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("expected error to contain '%s'", expected)
	}
}

var trimBracketsTests = []struct {
	input  string // input
	output string // output
}{
	{"{{ foo }}", "foo"},
	{" {{ foo }} ", "foo"},
	{"{{foo}}", "foo"},
	{"{{ foo bar }}", "foo bar"},
	// {"{{foo}}}", "foo}"}, // currently doesn't handle incorrect number of braces
}

func TestTrimBrackets(t *testing.T) {
	for _, tc := range trimBracketsTests {
		result := trimBrackets(tc.input)
		if result != tc.output {
			t.Errorf("trimBrackets(%s): expected '%s', got '%s'", tc.input, tc.output, result)
		}
	}
}
