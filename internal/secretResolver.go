package internal

import (
	"fmt"
	"strings"

	"github.com/al4/talebearer/vault"
)

// SecretResolver - Doc TODO
type SecretResolver struct {
	client vault.Vault
	secret func(string) (Secret, error)
}

// NewSecretResolver - create a new SecretResolver
func NewSecretResolver(client vault.Vault, secretFactory func(string) (Secret, error)) *SecretResolver {
	return &SecretResolver{
		client: client,
		secret: secretFactory,
	}
}

// Resolve - resolve secrets for the given placeholders (strings)
func (m *SecretResolver) Resolve(placeholders []string) (map[string]Secret, error) {

	secrets, err := m.secrets(placeholders)
	if err != nil {
		return nil, err
	}

	var errStrings []string
	for _, s := range secrets {
		err = s.Retrieve(m.client)
		if err != nil {
			errStrings = append(errStrings, fmt.Sprintf("\"%s\"", err.Error()))
		}
	}

	if len(errStrings) > 0 {
		err = fmt.Errorf("[%s]", strings.Join(errStrings, ", "))
	}

	return secrets, err
}

// secrets - Construct a map of secrets from placeholders
func (m *SecretResolver) secrets(placeholders []string) (map[string]Secret, error) {
	secrets := make(map[string]Secret)
	for _, placeholder := range placeholders {
		s, err := m.secret(placeholder)
		if err != nil {
			return nil, fmt.Errorf("could not construct secret for %s", placeholder)
		}
		secrets[placeholder] = s
	}

	return secrets, nil

}
