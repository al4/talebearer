package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	vaultApi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

func TestNewVaultClient(t *testing.T) {
	_, err := NewVaultClient(true)
	if err != nil {
		t.Error(err)
	}
}

// mockHandler - a mock of Vault's CLIHandler
type mockHandler struct {
	mock.Mock
	ReturnError  error
	ReturnSecret *vaultApi.Secret
}

func (h *mockHandler) Auth(c *vaultApi.Client, m map[string]string) (s *vaultApi.Secret, e error) {
	h.Called(c, m)
	return h.ReturnSecret, h.ReturnError
}

func (h *mockHandler) Help() string {
	return "mock help text"
}

// roundTripper - dummy of net.http.RoundTripper, for mocking Vault responses
type roundTripper struct {
	ReturnResponseSecret *vaultApi.Secret
	ReturnError          error
}

func (rt *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	js, err := json.Marshal(rt.ReturnResponseSecret)
	if err != nil {
		return nil, err
	}
	response := &http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(bytes.NewBufferString(string(js))),
	}
	return response, rt.ReturnError
}

// generateVaultClient - generate a mock vault client for use in tests
// All http requests issued with this client will return the given vault Secret
func generateVaultClient(returnSecret *vaultApi.Secret, returnError error) (*vaultApi.Client, error) {
	vaultConfig := vaultApi.DefaultConfig()
	vaultConfig.HttpClient = &http.Client{
		Transport: &roundTripper{
			ReturnResponseSecret: returnSecret,
			ReturnError:          returnError,
		},
	}
	return vaultApi.NewClient(vaultConfig)
}

func TestBaseClient_Authenticate_CallsHandler(t *testing.T) {
	returnSecret := &vaultApi.Secret{
		Auth: &vaultApi.SecretAuth{
			ClientToken: "devToken",
		},
	}
	vaultClient, err := generateVaultClient(returnSecret, nil)
	if err != nil {
		t.Error(err)
	}

	handler := &mockHandler{
		ReturnSecret: returnSecret,
	}
	handler.On("Auth", vaultClient, map[string]string{"role": "testRole"})

	client := &BaseClient{
		client:      vaultClient,
		authHandler: handler,
		logger:      log.WithField("test", true),
	}

	err = client.Authenticate("testRole")
	if err != nil {
		t.Error(err)
	}
	if client.client.Token() != "devToken" {
		t.Errorf("expected client.Token() to be %q", "devtoken")
	}
}

func TestBaseClient_AuthenticateAuthError(t *testing.T) {
	vaultClient, err := generateVaultClient(&vaultApi.Secret{
		Auth: nil,
	}, nil)
	if err != nil {
		t.Error(err)
	}
	handler := &mockHandler{
		ReturnError: errors.New("test error"),
	}
	handler.On("Auth", vaultClient, map[string]string{"role": "testRole"})

	client := &BaseClient{
		client:      vaultClient,
		authHandler: handler,
		logger:      log.WithField("test", true),
	}
	err = client.Authenticate("testRole")
	if err == nil {
		t.Error("error should not be nil")
	}
	if !strings.Contains(err.Error(), "test error") {
		t.Errorf("error message did not contain expected string")
	}
}

func TestBaseClient_Read(t *testing.T) {
	testData := map[string]interface{}{
		"foo": "bar",
	}
	vaultClient, err := generateVaultClient(
		&vaultApi.Secret{
			Auth: nil,
			Data: testData,
		},
		nil,
	)
	if err != nil {
		t.Error(err)
	}
	client := &BaseClient{
		client:      vaultClient,
		authHandler: &mockHandler{},
		logger:      log.WithField("test", true),
	}

	s, err := client.Read("/secret/test")
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(testData, s.Data) {
		t.Errorf("secret data %q was not as expected: %q", s.Data, testData)
	}
}

func TestBaseClient_Read_KvAPIV2(t *testing.T) {
	testData := map[string]interface{}{
		"data": map[string]interface{}{
			"foo": "bar",
		},
		"options": map[string]interface{}{
			"version": "2",
		},
	}
	vaultClient, err := generateVaultClient(
		&vaultApi.Secret{
			Auth: nil,
			Data: testData,
		},
		nil,
	)
	if err != nil {
		t.Error(err)
	}
	client := &BaseClient{
		client:      vaultClient,
		authHandler: &mockHandler{},
		logger:      log.WithField("test", true),
	}

	s, err := client.Read("/secret/test")
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(testData, s.Data) {
		t.Errorf("secret data %q was not as expected: %q", s.Data, testData)
	}
}

func TestBaseClient_Read_KvAPIUnknown(t *testing.T) {
	// Test an error is raised when the api version is unsupported
	testData := map[string]interface{}{
		"foo": "bar",
		"options": map[string]interface{}{
			"version": "0987w456",
		},
	}
	vaultClient, err := generateVaultClient(
		&vaultApi.Secret{
			Auth: nil,
			Data: testData,
		},
		nil,
	)
	if err != nil {
		t.Error(err)
	}
	client := &BaseClient{
		client:      vaultClient,
		authHandler: &mockHandler{},
		logger:      log.WithField("test", true),
	}

	s, err := client.Read("/secret/test")
	if err == nil {
		t.Error("expected error")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Error("expected error to contain the string 'unknown'")
	}
	if s != nil {
		t.Errorf("expected nil secret, got %v", s)
	}
}

func TestBaseClient_Write(t *testing.T) {
	testData := map[string]interface{}{
		"foo": "bar",
	}
	vaultClient, err := generateVaultClient(
		&vaultApi.Secret{
			Auth: nil,
			Data: testData,
		},
		nil,
	)
	if err != nil {
		t.Error(err)
	}
	logger := log.WithField("test", true)
	client := &BaseClient{
		client: vaultClient,
		writeMethods: &writeClient{
			client: vaultClient,
			logger: logger,
		},
		authHandler: &mockHandler{},
		logger:      logger,
	}

	s, err := client.Write("/secret/test", testData)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(testData, s.Data) {
		t.Errorf("secret data %q was not as expected: %q", s.Data, testData)
	}
}

func Test_sanitisePath(t *testing.T) {
	path := "/secret/foo/"
	expected := "secret/foo"
	result := sanitisePath(path)
	if expected != result {
		log.Fatalf("Result %s, expected %s", result, expected)
	}
}

func Test_updatePath(t *testing.T) {
	path := "secret/foo"
	expected := "secret/data/foo"
	result := updatePath(path)
	if expected != result {
		t.Errorf("Result '%s', expected '%s'", result, expected)
	}
}
