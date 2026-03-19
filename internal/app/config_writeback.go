package app

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func obscureConfigSecretsInFile(path string, setFlags map[string]bool) (bool, error) {
	if path == "" {
		return false, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read config for write-back: %w", err)
	}

	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return false, fmt.Errorf("parse config for write-back: %w", err)
	}

	changed := false
	for key, flagName := range map[string]string{
		"password":     "password",
		"pfx_password": "pfx-password",
	} {
		if setFlags[flagName] {
			continue
		}
		value, ok := cfg[key].(string)
		if !ok || value == "" || isObscured(value) {
			continue
		}
		obscured, err := obscure(value)
		if err != nil {
			return false, fmt.Errorf("obscure %s: %w", key, err)
		}
		cfg[key] = obscured
		changed = true
	}

	if !changed {
		return false, nil
	}

	encoded, err := yaml.Marshal(cfg)
	if err != nil {
		return false, fmt.Errorf("marshal config write-back: %w", err)
	}

	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, encoded, mode); err != nil {
		return false, fmt.Errorf("write config write-back: %w", err)
	}

	return true, nil
}

func isObscured(value string) bool {
	return len(value) >= len(obscurePrefix) && value[:len(obscurePrefix)] == obscurePrefix
}
