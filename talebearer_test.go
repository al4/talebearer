package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/al4/talebearer/vault"

	"io/ioutil"

	vaultApi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TaleBearerTestSuite struct {
	suite.Suite
	config *talebearerConfig
}

func (suite *TaleBearerTestSuite) SetupTest() {
	suite.config = &talebearerConfig{
		inputFile:  "examples/file1.in",
		outputFile: "examples/output",
		vaultRole:  "ValidRole",
	}
}

func (suite *TaleBearerTestSuite) TearDownTest() {
	err := os.Remove(suite.config.outputFile)
	if err != nil {
		suite.Error(err)
	}
}

var mockSecret = vaultApi.Secret{
	Data: map[string]interface{}{
		"key": "value1",
	},
}

func (suite *TaleBearerTestSuite) TestRunWhenInputFileDoesNotExist() {

	suite.config.inputFile = "examples/nonexistingfile.in"

	err := Run(nil, suite.config)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed creating template")
	assert.Contains(suite.T(), err.Error(), suite.config.inputFile)
}

func (suite *TaleBearerTestSuite) TestRunWhenVaultNotListening() {
	mockClient := new(vault.MockClient)
	suite.config.vaultRole = "ConnectionRefused"
	mockClient.On("Authenticate", suite.config.vaultRole)

	err := Run(mockClient, suite.config)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed authenticating with Vault:")
	assert.Contains(suite.T(), err.Error(), "connection refused")
	mockClient.AssertExpectations(suite.T())
}

func (suite *TaleBearerTestSuite) TestRunWhenRoleIsInvalid() {
	mockClient := new(vault.MockClient)
	suite.config.vaultRole = "InvalidRole"
	mockClient.On("Authenticate", suite.config.vaultRole)

	err := Run(mockClient, suite.config)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed authenticating with Vault:")
	assert.Contains(suite.T(), err.Error(), fmt.Sprintf("entry for role %s not found", suite.config.vaultRole))
	mockClient.AssertExpectations(suite.T())
}

func (suite *TaleBearerTestSuite) TestRunWhenReadingPropertiesFileWithSecrets() {
	mockClient := new(vault.MockClient)
	mockClient.ReturnSecret = &mockSecret
	suite.config.inputFile = "examples/file1.in"
	mockClient.On("Authenticate", suite.config.vaultRole)
	mockClient.On("Read", "secret/example")

	err := Run(mockClient, suite.config)
	assert.NoError(suite.T(), err)

	actual, _ := ioutil.ReadFile(suite.config.outputFile)
	expected, _ := ioutil.ReadFile("examples/file1.out")
	assert.Equal(suite.T(), expected, actual)
	mockClient.AssertExpectations(suite.T())
}

func (suite *TaleBearerTestSuite) TestRunWhenWritingToInvalidOutputFile() {
	mockClient := new(vault.MockClient)
	mockClient.ReturnSecret = &mockSecret
	suite.config.inputFile = "examples/file1.in"
	suite.config.outputFile = "nonexistingdir/file1.out"
	mockClient.On("Authenticate", suite.config.vaultRole)
	mockClient.On("Read", "secret/example")

	err := Run(mockClient, suite.config)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed writing to file")
	assert.Contains(suite.T(), err.Error(), suite.config.outputFile)
	mockClient.AssertExpectations(suite.T())
}

func (suite *TaleBearerTestSuite) TestRunWhenReadingGenericFileWithSecrets() {
	mockClient := new(vault.MockClient)
	mockClient.ReturnSecret = &mockSecret
	suite.config.inputFile = "examples/file3.in"
	mockClient.On("Authenticate", suite.config.vaultRole)
	mockClient.On("Read", "secret/example")

	err := Run(mockClient, suite.config)
	assert.NoError(suite.T(), err)

	actual, _ := ioutil.ReadFile(suite.config.outputFile)
	expected, _ := ioutil.ReadFile("examples/file3.out")
	assert.Equal(suite.T(), expected, actual)

	mockClient.AssertNotCalled(suite.T(), "Read", "secret/invalid")
	mockClient.AssertExpectations(suite.T())
}

func (suite *TaleBearerTestSuite) TestRunWhenSomeSecretsAreNotResolved() {
	mockClient := new(vault.MockClient)
	mockClient.ReturnSecret = &mockSecret
	suite.config.inputFile = "examples/file4.in"
	mockClient.On("Authenticate", suite.config.vaultRole)
	mockClient.On("Read", "secret/example")
	mockClient.On("Read", "secret/invalid")

	err := Run(mockClient, suite.config)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed resolving secrets")
	assert.Contains(suite.T(), err.Error(), "secret data for path secret/invalid does not contain key invalid")

	mockClient.AssertCalled(suite.T(), "Read", "secret/invalid")
	mockClient.AssertExpectations(suite.T())
}

func (suite *TaleBearerTestSuite) TestRunWhenFatalIssueWhileResolving() {
	mockClient := new(vault.MockClient)
	mockClient.ReturnSecret = &mockSecret
	//mockClient.ReturnError = fmt.Errorf("failed resolving secrets")
	suite.config.inputFile = "examples/file5.in"
	mockClient.On("Authenticate", suite.config.vaultRole)
	mockClient.On("Read", "secret/example")
	mockClient.On("Read", "secret/FATAL")

	err := Run(mockClient, suite.config)
	if err == nil {
		suite.T().Error("error expected when called run")
	}
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed resolving secrets")

	mockClient.AssertCalled(suite.T(), "Read", "secret/FATAL")
	mockClient.AssertExpectations(suite.T())
}

func (suite *TaleBearerTestSuite) TestRunCallsAuthenticate() {
	mockClient := new(vault.MockClient)
	mockClient.ReturnSecret = &mockSecret
	suite.config.inputFile = "examples/file1.in"
	mockClient.On("Authenticate", suite.config.vaultRole)
	mockClient.On("Read", "secret/example")

	err := Run(mockClient, suite.config)
	assert.NoError(suite.T(), err)

	mockClient.AssertExpectations(suite.T())
}

func TestTaleBearerTestSuite(t *testing.T) {
	suite.Run(t, new(TaleBearerTestSuite))
}
