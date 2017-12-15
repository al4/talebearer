package vault

import (
	"fmt"

	vaultApi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/mock"
)

// MockClient - mock of a vault client
type MockClient struct {
	mock.Mock
	ReturnString string
	ReturnError  error
	ReturnSecret *vaultApi.Secret
}

// Authenticate - mock method
func (m *MockClient) Authenticate(role string) error {
	m.Called(role)
	if role == "ConnectionRefused" {
		return fmt.Errorf("dial tcp [::1]:8200: getsockopt: connection refused")
	} else if role == "InvalidRole" {
		return fmt.Errorf("entry for role InvalidRole not found")
	}
	return m.ReturnError
}

// DisableAuth - mock method
func (m *MockClient) DisableAuth(path string) error {
	m.Called(path)
	return m.ReturnError
}

// EnableAuth - mock method
func (m *MockClient) EnableAuth(path string, options *vaultApi.EnableAuthOptions) error {
	m.Called(path, options)
	return m.ReturnError
}

// ListAuth - mock method
func (m *MockClient) ListAuth() (map[string]*vaultApi.AuthMount, error) {
	m.Called()
	rv := make(map[string]*vaultApi.AuthMount)
	return rv, m.ReturnError
}

// ListPolicies - mock method
func (m *MockClient) ListPolicies() ([]string, error) {
	m.Called()
	rv := make([]string, 0)
	return rv, m.ReturnError
}

// GetPolicy - mock method
func (m *MockClient) GetPolicy(name string) (string, error) {
	m.Called(name)
	return m.ReturnString, m.ReturnError
}

// PutPolicy - mock method
func (m *MockClient) PutPolicy(name string, data string) error {
	m.Called(name)
	return m.ReturnError
}

// DeletePolicy - mock method
func (m *MockClient) DeletePolicy(name string) error {
	m.Called(name)
	return m.ReturnError
}

// Read - mock method
func (m *MockClient) Read(path string) (*vaultApi.Secret, error) {
	m.Called(path)
	return m.ReturnSecret, m.ReturnError
}

// Write - mock method
func (m *MockClient) Write(path string, data map[string]interface{}) (*vaultApi.Secret, error) {
	m.Called(path, data)
	return m.ReturnSecret, m.ReturnError
}

// List - mock method
func (m *MockClient) List(path string) (*vaultApi.Secret, error) {
	m.Called(path)
	return m.ReturnSecret, m.ReturnError
}

// Delete - mock method
func (m *MockClient) Delete(path string) (*vaultApi.Secret, error) {
	m.Called(path)
	return m.ReturnSecret, m.ReturnError
}
