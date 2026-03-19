package app

import (
	"flag"
	"fmt"
	"log"
)

func Run() int {
	var (
		flagConfig      = flag.String("config", "", "path to config file")
		flagServer      = flag.String("server", "", "VPN server address")
		flagUsername    = flag.String("username", "", "login username")
		flagPassword    = flag.String("password", "", "login password")
		flagPfxPath     = flag.String("pfx-path", "", "path to .pfx certificate file")
		flagPfxPassword = flag.String("pfx-password", "", "password for .pfx file")
		flagBaseMTU     = flag.Int("base-mtu", 0, "base MTU value")
		flagVerbose     = flag.Bool("verbose", false, "enable verbose VPN core logs")
		flagVersion     = flag.Bool("version", false, "show version")
	)
	flag.Parse()

	if *flagVersion {
		fmt.Printf("tuncat %s\n", Version)
		return 0
	}

	cfgPath := findConfigFile(*flagConfig)
	if cfgPath != "" {
		log.Printf("Using config: %s", cfgPath)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Print(err)
		return 1
	}

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })
	if setFlags["server"] {
		cfg.Server = *flagServer
	}
	if setFlags["username"] {
		cfg.Username = *flagUsername
	}
	if setFlags["password"] {
		cfg.Password = *flagPassword
	}
	if setFlags["pfx-path"] {
		cfg.PfxPath = *flagPfxPath
	}
	if setFlags["pfx-password"] {
		cfg.PfxPassword = *flagPfxPassword
	}
	if setFlags["base-mtu"] {
		cfg.BaseMTU = *flagBaseMTU
	}

	normalizeConfig(cfg)
	configErrs := validateConfig(cfg)
	for _, e := range configErrs {
		log.Print(e)
	}
	if len(configErrs) > 0 {
		return 1
	}
	preflightErrs := preflightChecks(cfg)
	for _, e := range preflightErrs {
		log.Print(e)
	}
	if len(preflightErrs) > 0 {
		return 1
	}

	cfg.PfxPassword, err = reveal(cfg.PfxPassword)
	if err != nil {
		log.Printf("Error decoding pfx_password: %v", err)
		return 1
	}
	cfg.Password, err = reveal(cfg.Password)
	if err != nil {
		log.Printf("Error decoding password: %v", err)
		return 1
	}

	if cfg.PfxPassword == "" {
		cfg.PfxPassword, err = readPassword("PFX password: ")
		if err != nil {
			log.Printf("Error reading PFX password: %v", err)
			return 1
		}
	}
	if cfg.Password == "" {
		cfg.Password, err = readPassword("VPN password: ")
		if err != nil {
			log.Printf("Error reading VPN password: %v", err)
			return 1
		}
	}

	pfxCreds, err := loadPFXCredentials(cfg.PfxPath, cfg.PfxPassword)
	if err != nil {
		log.Printf("Error loading PFX credentials: %v", err)
		return 1
	}

	onConnected := func() {
		changed, err := obscureConfigSecretsInFile(cfgPath, setFlags)
		if err != nil {
			log.Printf("Warning: config write-back failed: %v", err)
			return
		}
		if changed {
			log.Printf("Updated config secrets in %s", cfgPath)
		}
	}

	exitCode, err := runVPNCore(cfg, pfxCreds, *flagVerbose, onConnected)
	if err != nil {
		log.Print(err)
		return 1
	}

	return exitCode
}
