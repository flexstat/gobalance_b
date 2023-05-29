package main

import (
	"crypto/ed25519"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
	"gobalance/pkg/brand"
	"gobalance/pkg/onionbalance"
	"gobalance/pkg/stem/descriptor"
	_ "golang.org/x/crypto/sha3"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// https://onionbalance.readthedocs.io
// https://github.com/torproject/torspec/blob/main/control-spec.txt
// https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt

var appVersion = "0.0.0"

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	app := &cli.App{
		Name:    "gobalance",
		Usage:   "Golang rewrite of onionbalance",
		Authors: []*cli.Author{{Name: "n0tr1v", Email: "n0tr1v@protonmail.com"}},
		Version: appVersion,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "ip",
				Aliases: []string{"i"},
				Usage:   "Tor control IP address",
				Value:   "127.0.0.1",
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "Tor control port",
				Value:   9051,
			},
			&cli.StringFlag{
				Name:    "torPassword",
				Aliases: []string{"tor-password"},
				Usage:   "Tor control password",
			},
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Config file location",
				Value:   "config.toml",
			},
			&cli.BoolFlag{
				Name:    "quick",
				Aliases: []string{"q"},
				Usage:   "Quickly deploy a new descriptor (no 5min wait)",
			},
			&cli.StringFlag{
				Name:    "verbosity",
				Aliases: []string{"vv"},
				Usage:   "Minimum verbosity level for logging. Available in ascending order: debug, info, warning, error, critical). The default is info.",
				Value:   "info",
			},
		},
		Action: mainAction,
		Commands: []*cli.Command{
			{
				Name:    "generate-config",
				Aliases: []string{"g"},
				Usage:   "generate a config.toml file",
				Action:  generateConfigAction,
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		logrus.Fatal(err)
	}
}

func mainAction(c *cli.Context) error {
	config := c.String("config")
	ip := c.String("ip")
	port := c.Int("port")
	quick := c.Bool("quick")
	torPassword := c.String("torPassword")
	verbosity := c.String("verbosity")

	logLvl := logrus.InfoLevel
	switch verbosity {
	case "debug":
		logLvl = logrus.DebugLevel
	case "info":
		logLvl = logrus.InfoLevel
	case "warning":
		logLvl = logrus.WarnLevel
	case "error":
		logLvl = logrus.ErrorLevel
	case "critical":
		logLvl = logrus.FatalLevel
	}
	logrus.SetLevel(logLvl)

	logrus.Warningf("Initializing onionbalance (version: %s)...", appVersion)
	myOnionbalance := onionbalance.Onionbalance()
	myOnionbalance.InitSubsystems(onionbalance.InitSubsystemsParams{
		ConfigPath:  config,
		IP:          ip,
		Port:        port,
		TorPassword: torPassword,
	})
	initScheduler(quick)
	select {}
}

func fileExists(filePath string) bool {
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func generateConfigAction(c *cli.Context) error {
	/*
		Enter path to store generated config
		Number of services (frontends) to create (default: 1):
		Enter path to master service private key (i.e. path to 'hs_ed25519_secret_key') (Leave empty to generate a key)
		Number of instance services to create (default: 2) (min: 1, max: 8)
		Provide a tag name to group these instances [node]

		Wrote master service config file '/Users/n0tr1v/Documents/onionbalance/config/config.yaml'
		Done! Successfully generated Onionbalance config
		Now please edit 'config/config.yaml' with a text editor to add/remove/edit your backend instances
	*/
	configFilePath, _ := filepath.Abs("./config.toml")
	if fileExists(configFilePath) {
		logrus.Fatalf("config file %s already exists", configFilePath)
	}

	masterPublicKey, masterPrivateKey, _ := ed25519.GenerateKey(brand.Reader())
	masterPrivateKeyDer, _ := x509.MarshalPKCS8PrivateKey(masterPrivateKey)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: masterPrivateKeyDer}
	onionAddress := descriptor.AddressFromIdentityKey(masterPublicKey)
	masterKeyFileName := strings.TrimSuffix(onionAddress, ".onion") + ".key"
	masterKeyFile, err := os.Create(masterKeyFileName)
	if err != nil {
		logrus.Fatal(err)
	}
	defer masterKeyFile.Close()
	_ = pem.Encode(masterKeyFile, block)

	configFile, err := os.Create(configFilePath)
	if err != nil {
		logrus.Fatal(err)
	}
	defer configFile.Close()
	data := onionbalance.ConfigData{
		Services: []onionbalance.ServiceConfig{{
			Key:       masterKeyFileName,
			Instances: []onionbalance.InstanceConfig{{Address: "<Enter the instance onion address here>"}},
		}},
	}
	if err := toml.NewEncoder(configFile).Encode(data); err != nil {
		logrus.Fatal(err)
	}
	return nil
}

const (
	InitialCallbackDelay            = 45
	FetchDescriptorFrequency        = 10 * 60
	PublishDescriptorCheckFrequency = 5 * 60
)

func initScheduler(quick bool) {
	myOnionbalance := onionbalance.Onionbalance()
	if myOnionbalance.IsTestnet {
	} else {
		go func() {
			for {
				time.Sleep(FetchDescriptorFrequency * time.Second)
				myOnionbalance.FetchInstanceDescriptors()
			}
		}()
		go func() {
			for {
				time.Sleep(PublishDescriptorCheckFrequency * time.Second)
				myOnionbalance.PublishAllDescriptors()
			}
		}()
		// Quick is a hack to quickly deploy a new descriptor without having to wait
		if quick {
			myOnionbalance.FetchInstanceDescriptors()
			myOnionbalance.PublishAllDescriptors()
			time.Sleep(5 * time.Second)
			myOnionbalance.PublishAllDescriptors()
		} else {
			time.Sleep(InitialCallbackDelay * time.Second)
			myOnionbalance.FetchInstanceDescriptors()
			myOnionbalance.PublishAllDescriptors()
		}
	}
}
