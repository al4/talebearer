package internal

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/al4/talebearer/vault"
)

// Secret - Doc TODO
type Secret interface {
	Retrieve(vault.Vault) error
	Value() string
	Key() string
	Path() string
	SetValue(string)
}

// VaultSecret - a document from Vault
type VaultSecret struct {
	path  string // Document path inside Vault
	key   string // Key inside a Vault document
	value string // Secret value
}

// NewSecret creates a new Secret. The actual secret value is not yet retrieved from Vault
func NewSecret(placeholder string) (Secret, error) {
	s := &VaultSecret{}

	if !strings.Contains(placeholder, "!") {
		return nil, fmt.Errorf("path does not contain a `!` separator")
	}

	p := trimBrackets(placeholder)

	var err error
	s.value, err = s.fallback(p)
	if err != nil {
		return nil, fmt.Errorf("failed to construct fallback password")
	}

	split := strings.Split(p, "!")
	fallbackSplit := strings.Split(split[1], ":")
	s.path, s.key = split[0], fallbackSplit[0]

	if s.key == "data" {
		logrus.Warnf("A secret called %q can confuse things, as it's the name of the data "+
			"field in the vault response. It should work under KV v2, but please consider "+
			"renaming it.", s.key)
	}

	return s, nil
}

func trimBrackets(placeholder string) string {
	placeholder = strings.TrimSpace(placeholder)
	placeholder = strings.TrimLeft(placeholder, "{")
	placeholder = strings.TrimRight(placeholder, "}")
	placeholder = strings.TrimSpace(placeholder)
	return placeholder
}

// Retrieve - retries secret from Vault or falls back to default
func (s *VaultSecret) Retrieve(client vault.Vault) error {
	secret, err := client.Read(s.path)

	if err != nil {
		return fmt.Errorf("failed to fetch secret '%s' from Vault: %s", s.path, err)
	}

	if secret == nil {
		return fmt.Errorf("failed to fetch secret '%s' from Vault, secret was nil", s.path)
	}

	if secret.Data == nil {
		return fmt.Errorf("failed to fetch secret '%s' from Vault, secret.Data was nil", s.path)
	}

	// Could do with some more sanity-checking here
	if val, ok := secret.Data["data"]; ok { // KV API v2
		// Let's not make any KV API v1 secrets called "data", OK?
		v, ok := val.(map[string]interface{})
		if !ok {
			return fmt.Errorf("could not parse KV v2 secret data: %v", val)
		}
		if x, ok := v[s.key]; ok {
			logrus.Debugf("Setting value of %s (KV API v2)", s.key)
			s.SetValue(x.(string))
			return nil
		}
	} else if val, ok := secret.Data[s.key]; ok { // KV API v1
		logrus.Debugf("Setting value of %s (KV API v1)", s.key)
		s.SetValue(val.(string))
		return nil
	}

	return fmt.Errorf("secret data for path %s does not contain key %s", s.path, s.key)
}

// Key - Key in a key:value pair
func (s VaultSecret) Key() string {
	return s.key
}

// Path - the path to the secret
func (s VaultSecret) Path() string {
	return s.path
}

// Value - the value in a key:value pair
func (s VaultSecret) Value() string {
	return s.value
}

// SetValue - set the value of this secret
func (s *VaultSecret) SetValue(val string) {
	s.value = val
}

// Fallback secret in case the secret retrieval fails
func (s *VaultSecret) fallback(placeholder string) (value string, err error) {
	if strings.Contains(placeholder, ":") {
		tempSplit := strings.Split(placeholder, ":")

		return tempSplit[1], nil
	}

	return "", nil
}
