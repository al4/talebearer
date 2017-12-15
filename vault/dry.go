package vault

import (
	vaultApi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

type dryClient struct {
	logger *log.Entry
}

// Override any methods that write, so we can only perform reads
func (c *dryClient) EnableAuth(path string, options *vaultApi.EnableAuthOptions) error {
	c.logger.WithFields(log.Fields{
		"action":  "EnableAuth",
		"options": options,
		"path":    path,
	}).Debug("No Vault API call made")
	return nil
}

func (c *dryClient) DisableAuth(path string) error {
	c.logger.WithFields(log.Fields{
		"action": "DisableAuth",
		"path":   path,
	}).Debug("No Vault API call made")
	return nil
}

func (c *dryClient) PutPolicy(name string, data string) error {
	c.logger.WithFields(log.Fields{
		"action": "PutPolicy",
		"name":   name,
		"data":   data,
	}).Debug("No Vault API call made")
	return nil
}

func (c *dryClient) DeletePolicy(name string) error {
	c.logger.WithFields(log.Fields{
		"action": "DeletePolicy",
		"name":   name,
	}).Debug("No Vault API call made")
	return nil
}

func (c *dryClient) Write(path string, data map[string]interface{}) (*vaultApi.Secret, error) {
	c.logger.WithFields(log.Fields{
		"action": "Write",
		"path":   path,
		"data":   data,
	}).Debug("No Vault API call made")
	return &vaultApi.Secret{}, nil
}

func (c *dryClient) Delete(path string) (*vaultApi.Secret, error) {
	c.logger.WithFields(log.Fields{
		"action": "Delete",
		"path":   path,
	}).Debug("No Vault API call made")
	return &vaultApi.Secret{}, nil
}
