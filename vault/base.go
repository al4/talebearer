package vault

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	vaultApi "github.com/hashicorp/vault/api"
	credAws "github.com/hashicorp/vault/builtin/credential/aws"
)

// Vault - an abstraction of hashicorp's vault api client
// With the exception of Authenticate, most functions in this file are simple pass-through calls
// to the vault API, which don't do anything special.
type Vault interface {
	readMethods
	writeMethods
	Authenticate(string) error
}

type readMethods interface {
	GetPolicy(name string) (string, error)
	List(path string) (*vaultApi.Secret, error)
	ListAuth() (map[string]*vaultApi.AuthMount, error)
	ListPolicies() ([]string, error)
	Read(path string) (*vaultApi.Secret, error)
}

type writeMethods interface {
	Delete(path string) (*vaultApi.Secret, error)
	DeletePolicy(name string) error
	DisableAuth(string) error
	EnableAuth(path string, options *vaultApi.EnableAuthOptions) error
	PutPolicy(string, string) error
	Write(path string, data map[string]interface{}) (*vaultApi.Secret, error)
}

// authHandler - handles Vault authentication
// in AWS scenarios, vault/builtin/credential/aws/CLIHandler would normally be used
type authHandler interface {
	Auth(c *vaultApi.Client, m map[string]string) (*vaultApi.Secret, error)
	Help() string
}

// BaseClient - The base vault client with common read/write methods
type BaseClient struct {
	readMethods
	writeMethods
	client      *vaultApi.Client
	authHandler authHandler
	logger      *log.Entry
}

// NewVaultClient - create a vault client
func NewVaultClient(readonly bool) (c Vault, err error) {
	config := vaultApi.DefaultConfig()
	vaultAPIClient, err := vaultApi.NewClient(config)
	if err != nil {
		return c, err
	}
	logger := log.WithFields(log.Fields{"readonly": readonly})

	var writer writeMethods
	if readonly {
		writer = &dryClient{
			logger: logger,
		}
	} else {
		writer = &writeClient{
			logger: logger,
			client: vaultAPIClient,
		}
	}
	return &BaseClient{
		writeMethods: writer,
		client:       vaultAPIClient,
		authHandler:  &credAws.CLIHandler{},
		logger:       logger,
	}, nil
}

// updatePath - insert "data" into the path after the mount
func updatePath(path string) (p string) {
	// Currently doesn't do any sanity checking
	s := sanitisePath(path)
	a := strings.Split(s, "/")
	mount := a[0]
	ap := a[1:]
	out := []string{mount, "data"}
	out = append(out, ap...)

	return strings.Join(out, "/")
}

// sanitisePath - trim whitespace and leading/trailing slashes
func sanitisePath(path string) string {
	p := strings.TrimSpace(path)
	p = strings.Trim(p, "/")
	return p
}

// getMountVersion - determine the version of the KV backend API
// based heavily on vault.command.kvPreflightVersionRequest, a private method
func getMountVersion(client *vaultApi.Client, path string) (int, error) {
	currentWrappingLookupFunc := client.CurrentWrappingLookupFunc()
	client.SetWrappingLookupFunc(nil)
	defer client.SetWrappingLookupFunc(currentWrappingLookupFunc)
	currentOutputCurlString := client.OutputCurlString()
	client.SetOutputCurlString(false)
	defer client.SetOutputCurlString(currentOutputCurlString)

	r := client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, which means api v1
		if resp != nil && resp.StatusCode == 404 {
			return 1, nil
		}
		return 0, err
	}
	// Parse mount path and kv api version from the returned secret
	secret, err := vaultApi.ParseSecret(resp.Body)
	if err != nil {
		return 0, err
	}
	options := secret.Data["options"]
	if options == nil {
		return 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return 1, nil
	case "2":
		return 2, nil
	}
	return 0, fmt.Errorf("unknown KV API version %v", version)
}

// pathToSecret - Determine the secret path
// Talebearer secrets are traditionally given in KV API v1 format, v2 needs an extra "data" element
// inserted
func pathToSecret(client *vaultApi.Client, path string) (string, error) {
	version, err := getMountVersion(client, path)
	if err != nil {
		return "", err
	}
	switch version {
	case 1:
		return path, nil
	case 2:
		return updatePath(path), nil
	}
	return "", fmt.Errorf("unsupported KV API version: %v", version)
}

// Authenticate - authenticate to Vault using official client methods
func (c *BaseClient) Authenticate(role string) error {
	if c.client.Token() != "" {
		// Already authenticated. Supposedly.
		c.logger.Debugf("Already authenticated by environment variable")
		return nil
	}

	log.Debugf("Authenticating with Vault...")
	secret, err := c.authHandler.Auth(c.client, map[string]string{"role": role})
	if err != nil {
		return err
	}

	if secret == nil {
		return errors.New("no secret returned from Vault")
	}

	c.client.SetToken(secret.Auth.ClientToken)

	secret, err = c.client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("no token found in Vault client: %s", err)
	}
	if secret == nil {
		return errors.New("got nil secret when checking token")
	}

	return nil
}

// Read - Read the given path
func (c *BaseClient) Read(path string) (s *vaultApi.Secret, err error) {
	p, err := pathToSecret(c.client, path)
	if err != nil {
		return nil, err
	}
	return c.client.Logical().Read(p)
}

// List - list at given path
func (c *BaseClient) List(path string) (*vaultApi.Secret, error) {
	return c.client.Logical().List(path)
}

// ListAuth - list configured auth methods
func (c *BaseClient) ListAuth() (map[string]*vaultApi.AuthMount, error) {
	return c.client.Sys().ListAuth()
}

// GetPolicy - get policy by given name
func (c *BaseClient) GetPolicy(name string) (string, error) {
	return c.client.Sys().GetPolicy(name)
}

// ListPolicies - list policies
func (c *BaseClient) ListPolicies() ([]string, error) {
	return c.client.Sys().ListPolicies()
}
