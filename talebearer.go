package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/al4/talebearer/internal"
	"github.com/al4/talebearer/vault"
)

var flags = flag.NewFlagSet("Talebearer", flag.ExitOnError)
var logLevel string
var outputFile string
var inputFile string
var vaultRole string
var inPlace bool
var continueOnError bool

type talebearerConfig struct {
	inputFile  string
	outputFile string
	vaultRole  string
}

func init() {
	flags.StringVar(
		&logLevel, "log-level", "info", fmt.Sprintf("Log level, valid "+
			"values are %+v", log.AllLevels),
	)
	flags.StringVar(
		&inputFile, "input-file", "", "The path of the source properties file",
	)
	flags.StringVar(
		&outputFile, "output-file", "", "The path of the properties file to write",
	)
	flags.StringVar(
		&vaultRole, "role", "", "The Vault role to authenticate as",
	)
	flags.BoolVar(
		&inPlace, "inplace", false, "Alter input-file in-place instead of writing to output-file",
	)
	flags.BoolVar(
		&continueOnError, "continue-on-error", false, "Don't abort on error, always exit 0",
	)

	flags.Usage = func() {
		fmt.Printf("Usage of Talebearer:\n")
		flags.PrintDefaults()
		fmt.Println("\nVault authentication is handled by environment variables (the same " +
			"ones as the Vault Client, as talebearer uses the same code). So ensure VAULT_ADDR " +
			"and VAULT_TOKEN are set.")
		fmt.Println()
	}

	// Avoid parsing flags passed on running `go test`
	var args []string

	for _, s := range os.Args[1:] {
		if !strings.HasPrefix(s, "-test.") {
			args = append(args, s)
		}
	}

	err := flags.Parse(args)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	log.SetOutput(os.Stderr)
	ll, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalln(err)
	}
	log.SetLevel(ll)

	config, err := newTalebearerConfig()
	if err != nil {
		log.Fatal(err)
	}

	vaultClient, err := vault.NewVaultClient(true)
	if err != nil {
		log.Fatal(err)
	}

	err = Run(vaultClient, config)
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}

}

func newTalebearerConfig() (*talebearerConfig, error) {
	switch {
	case (inputFile == "" || outputFile == "") && !inPlace:
		flags.Usage()
		return nil, fmt.Errorf("both input and output files must be specified")
	case inputFile == "" && inPlace:
		flags.Usage()
		return nil, fmt.Errorf("input file must be specified")
	}

	if inPlace {
		outputFile = inputFile
	}

	return &talebearerConfig{
		inputFile:  inputFile,
		outputFile: outputFile,
		vaultRole:  vaultRole,
	}, nil
}

// Run - Main control function, has to decide whether to continue or exit at each step
func Run(client vault.Vault, config *talebearerConfig) error {
	template, err := internal.NewTemplateFile(config.inputFile)
	if err != nil {
		// Not really possible to continue without error here
		return fmt.Errorf("failed creating template: %s", err)
	}

	placeholders, err := template.FindPlaceholders()
	if err != nil {
		return fmt.Errorf("failed finding placeholders in template: %s", err)
	}

	err = client.Authenticate(config.vaultRole)
	if err != nil {
		msg := fmt.Sprintf("failed authenticating with Vault: %s", err)
		if continueOnError {
			log.Error(msg)
		} else {
			return fmt.Errorf("%s; exiting", msg)
		}
	}

	secrets, err := internal.NewSecretResolver(client, internal.NewSecret).Resolve(placeholders)
	if err != nil {
		msg := fmt.Sprintf("failed resolving secrets: %s", err)
		if continueOnError {
			log.Errorf("%s; continuing", msg)
		} else {
			return fmt.Errorf("%s; exiting", msg)
		}
	}

	err = template.RenderSecrets(secrets, config.outputFile)
	if err != nil {
		msg := fmt.Sprintf("failed rendering secrets: %s", err)
		if continueOnError {
			log.Errorf("%s; continuing", msg)
		} else {
			return fmt.Errorf("%s; exiting", msg)
		}
	}

	log.Debugf("Reached end of run()")
	return nil
}
