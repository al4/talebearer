package internal

import (
	"os"
	"testing"

	"io/ioutil"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	//"os"
	"strings"
)

type TemplateFileTestSuite struct {
	suite.Suite
}

func (suite *TemplateFileTestSuite) TestFindPlaceholdersInNonExistingFile() {

	template, err := NewTemplateFile("../examples/nonexisting.properties")
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), template)
	assert.Contains(suite.T(), err.Error(), "does not exist")
}

func (suite *TemplateFileTestSuite) TestFindPlaceholdersInPropertiesFile() {

	template, err := NewTemplateFile("../examples/example.properties")
	assert.NoError(suite.T(), err)

	placeholders, err := template.FindPlaceholders()

	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), placeholders, "{{ secret/example!foo }}")

}

func (suite *TemplateFileTestSuite) TestFindPlaceholdersInGenericFile() {

	template, err := NewTemplateFile("../examples/generic.conf")
	assert.NoError(suite.T(), err)

	placeholders, err := template.FindPlaceholders()

	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), placeholders, "{{ secret/bar!password_key }}")
}

func (suite *TemplateFileTestSuite) TestFindPlaceholdersInJsonFile() {

	template, err := NewTemplateFile("../examples/example.json")
	assert.NoError(suite.T(), err)

	placeholders, err := template.FindPlaceholders()

	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), placeholders, "{{ secret/example!password_key }}")

	assert.NotContains(suite.T(), placeholders, "{{ secret/invalid!invalid }")
}

func (suite *TemplateFileTestSuite) TestRenderSecretsInPropertiesFile() {
	tmpfile, err := ioutil.TempFile("", "tempfile")
	if err != nil {
		log.Fatal(err)
	}
	//defer os.Remove(tmpfile.Name())

	secrets := make(map[string]Secret)
	secrets["{{ secret/example!foo }}"], _ = NewSecret("secret/example!foo:fallback1")
	secrets["{{ secret/example!two }}"], _ = NewSecret("secret/example!two:fallback2")

	template, err := NewTemplateFile("../examples/example.properties")
	if err != nil {
		suite.Error(err)
	}
	err = template.RenderSecrets(secrets, tmpfile.Name())
	if err != nil {
		suite.Error(err)
	}

	assert.NoError(suite.T(), err)

	contents, err := ioutil.ReadFile(tmpfile.Name())
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), string(contents), "secret=fallback1")
	assert.Contains(suite.T(), string(contents), "secret-two=fallback2")
	assert.Contains(suite.T(), string(contents), "baz=boz")
}

func (suite *TemplateFileTestSuite) TestRenderSecretsInGenericFile() {
	tmpfile, err := ioutil.TempFile("", "tempfile")
	if err != nil {
		log.Fatal(err)
	}
	//defer os.Remove(tmpfile.Name())

	secrets := make(map[string]Secret)
	secrets["{{ secret/example!foo }}"], _ = NewSecret("secret/example!foo:fallback1")
	secrets["{{ secret/bar!password_key }}"], _ = NewSecret("secret/bar!password_key:fallback2")

	template, err := NewTemplateFile("../examples/generic.conf")
	if err != nil {
		suite.Error(err)
	}
	err = template.RenderSecrets(secrets, tmpfile.Name())
	if err != nil {
		suite.Error(err)
	}

	assert.NoError(suite.T(), err)

	contents, err := ioutil.ReadFile(tmpfile.Name())
	assert.NoError(suite.T(), err)
	assert.Contains(suite.T(), string(contents), "some fallback1 secrets in random places")
	assert.Contains(suite.T(), string(contents), "No structure required fallback2")
	assert.Contains(suite.T(), string(contents), "such as {{ secret/invalid!invalid } should not be resolved")
}

func (suite *TemplateFileTestSuite) TestRenderSecretsInPemFile() {
	tmpfile, err := ioutil.TempFile("", "tempfile")
	if err != nil {
		log.Fatal(err)
	}
	//defer os.Remove(tmpfile.Name())

	secrets := make(map[string]Secret)
	secrets["{{ secret/rsa_key!pem }}"], _ = NewSecret("secret/rsa_key!pem")
	secrets["{{ secret/rsa_key!pem }}"].SetValue(`-----BEGIN RSA PRIVATE KEY-----
	MIIEogIBAAKCAQEAwi+DoHfnNj2ghsShw0r5i/4Me23YsynU+JHnBBiO78Uez/+s
	0qKeVhPCg8dvmgKJbK/9b+STvRVdGMcuMh5hKUQGjkpbwIL4fW0=
	-----END RSA PRIVATE KEY-----`)

	template, err := NewTemplateFile("../examples/example.pem")
	if err != nil {
		suite.Error(err)
	}
	err = template.RenderSecrets(secrets, tmpfile.Name())
	assert.NoError(suite.T(), err)

	contents, err := ioutil.ReadFile(tmpfile.Name())
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), secrets["{{ secret/rsa_key!pem }}"].Value(), string(contents))
}

func (suite *TemplateFileTestSuite) TestRenderSecretsInFileWithNoSecrets() {
	tmpfile, err := ioutil.TempFile("", "tempfile")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if _err := os.Remove(tmpfile.Name()); _err != nil {
			log.Fatal(_err)
		}
	}()

	secrets := make(map[string]Secret)

	template, err := NewTemplateFile("../examples/nosecrets.conf")
	if err != nil {
		suite.Error(err)
	}
	err = template.RenderSecrets(secrets, tmpfile.Name())
	if err != nil {
		suite.Error(err)
	}

	assert.NoError(suite.T(), err)

	contents, err := ioutil.ReadFile(tmpfile.Name())
	assert.NoError(suite.T(), err)

	assert.Equal(suite.T(), strings.HasPrefix(string(contents), "File with no secrets:\n"), true)
	assert.Equal(suite.T(), strings.HasSuffix(string(contents), "\nand after secret rendering."), true)
}

func TestTemplateFileSuite(t *testing.T) {
	suite.Run(t, new(TemplateFileTestSuite))
}
