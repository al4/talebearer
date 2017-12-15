package vault

import (
	vaultApi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

type writeClient struct {
	logger *log.Entry
	client *vaultApi.Client
}

// Used by sysAuthHandler
func (c *writeClient) EnableAuth(path string, options *vaultApi.EnableAuthOptions) error {
	c.logger.WithFields(log.Fields{
		"action":  "EnableAuth",
		"options": options,
		"path":    path,
	}).Debug()
	return c.client.Sys().EnableAuthWithOptions(path, options)
}

func (c *writeClient) DisableAuth(path string) error {
	c.logger.WithFields(log.Fields{
		"action": "DisableAuth",
		"path":   path,
	}).Debug("Calling Vault API")
	return c.client.Sys().DisableAuth(path)
}

// Used by sysPolicyHandler
func (c *writeClient) PutPolicy(name string, data string) error {
	c.logger.WithFields(log.Fields{
		"action": "PutPolicy",
		"name":   name,
		"data":   data,
	}).Debug("Calling Vault API")
	return c.client.Sys().PutPolicy(name, data)
}

func (c *writeClient) DeletePolicy(name string) error {
	c.logger.WithFields(log.Fields{
		"action": "DeletePolicy",
		"name":   name,
	}).Debug("Calling Vault API")
	return c.client.Sys().DeletePolicy(name)
}

// Used by genericHandler
func (c *writeClient) Write(path string, data map[string]interface{}) (*vaultApi.Secret, error) {
	p, err := pathToSecret(c.client, path)
	if err != nil {
		return nil, err
	}
	c.logger.WithFields(log.Fields{
		"action": "Write",
		"path":   p,
		"data":   data,
	}).Debug("Calling Vault API")
	return c.client.Logical().Write(p, data)
}

func (c *writeClient) Delete(path string) (*vaultApi.Secret, error) {
	c.logger.WithFields(log.Fields{
		"action": "Delete",
		"path":   path,
	}).Debug("Calling Vault API")
	return c.client.Logical().Delete(path)
}
