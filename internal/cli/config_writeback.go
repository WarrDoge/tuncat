package cli

import (
	"fmt"
	"os"
	"path/filepath"

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

	tmp, err := os.CreateTemp(filepath.Dir(path), "tuncat-config-*.yaml")
	if err != nil {
		return false, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return false, fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return false, fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("rename temp file: %w", err)
	}

	return true, nil
}

func isObscured(value string) bool {
	return len(value) >= len(obscurePrefix) && value[:len(obscurePrefix)] == obscurePrefix
}
