package internal

import (
	"testing"

	"github.com/al4/talebearer/vault"
)

type mockSecret struct {
	ReturnString string
	ReturnError  error
}

func (s *mockSecret) Retrieve(client vault.Vault) error { return s.ReturnError }
func (s *mockSecret) Value() string                     { return s.ReturnString }
func (s *mockSecret) Key() string                       { return s.ReturnString }
func (s *mockSecret) Path() string                      { return s.ReturnString }
func (s *mockSecret) SetValue(val string)               {}

// Ensure the mock satisfies the interface
var _ Secret = (*mockSecret)(nil)

func TestResolveSecretsPropertiesFile(t *testing.T) {
	secretFunc := func(string) (Secret, error) {
		return &mockSecret{
			ReturnString: "mock",
		}, nil
	}

	r := &SecretResolver{
		client: new(vault.MockClient),
		secret: secretFunc,
	}

	placeholders := []string{
		"secret/example1!key",
		"secret/example2!key",
	}

	secrets, err := r.Resolve(placeholders)
	if err != nil {
		t.Error(err)
	}

	result := secrets["secret/example1!key"].Value()
	if result != "mock" {
		t.Errorf("expected '%s', got '%s'", "mock", result)
	}
}
