package internal

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Template - Doc TODO
type Template interface {
	FindPlaceholders() ([]string, error)
	RenderSecrets(map[string]Secret, string) error
}

// TemplateFile - Doc TODO
type TemplateFile struct {
	path    string
	matcher *regexp.Regexp
}

// NewTemplateFile - Doc TODO
func NewTemplateFile(filename string) (t *TemplateFile, err error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("file %s does not exist", filename)
	}
	return &TemplateFile{
		path:    filename,
		matcher: regexp.MustCompile(`{{\s*([^ }]*)?\s*}}`),
	}, nil
}

// FindPlaceholders - Find the placeholders in a given string
func (t *TemplateFile) FindPlaceholders() (placeholders []string, err error) {

	contents, err := ioutil.ReadFile(t.path)
	if err != nil {
		return nil, err
	}

	return t.matcher.FindAllString(string(contents), -1), nil
}

// RenderSecrets - Render the secrets given to a file
func (t *TemplateFile) RenderSecrets(secrets map[string]Secret, outputFile string) (err error) {
	contents, err := ioutil.ReadFile(t.path)
	if err != nil {
		return err
	}

	newContents := string(contents)
	for p, s := range secrets {
		log.Infof("Replacing %s\n", s.Path())
		if s.Value() == "" {
			log.Warnf("Not replacing %s, empty string value", p)
			continue
		}
		newContents = strings.Replace(newContents, p, s.Value(), -1)
	}

	err = ioutil.WriteFile(outputFile, []byte(newContents), 0644)
	if err != nil {
		return fmt.Errorf("failed writing to file '%s': %s", outputFile, err)
	}
	return nil
}
