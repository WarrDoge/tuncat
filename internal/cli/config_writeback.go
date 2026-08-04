package cli

import (
	"bytes"
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

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return false, fmt.Errorf("parse config for write-back: %w", err)
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return false, fmt.Errorf("parse config for write-back: expected document node")
	}

	mapping := doc.Content[0]
	if mapping.Kind != yaml.MappingNode {
		return false, fmt.Errorf("parse config for write-back: expected mapping at root")
	}

	changed := false
	for key, flagName := range map[string]string{
		"password":     "password",
		"pfx_password": "pfx-password",
	} {
		if setFlags[flagName] {
			continue
		}
		val := findMappingValue(mapping, key)
		if val == nil || val.Kind != yaml.ScalarNode {
			continue
		}
		if val.Value == "" || isObscured(val.Value) {
			continue
		}
		obscured, err := obscure(val.Value)
		if err != nil {
			return false, fmt.Errorf("obscure %s: %w", key, err)
		}
		val.Value = obscured
		val.Tag = "!!str"
		changed = true
	}

	if !changed {
		return false, nil
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&doc); err != nil {
		return false, fmt.Errorf("encode config write-back: %w", err)
	}
	encoder.Close()

	encoded := buf.Bytes()
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, encoded, mode); err != nil {
		return false, fmt.Errorf("write config write-back: %w", err)
	}

	return true, nil
}

// findMappingValue walks a yaml.MappingNode looking for the given key
// at the top level and returns the corresponding value node, or nil
// if the key is not found.
func findMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func isObscured(value string) bool {
	return len(value) >= len(obscurePrefix) && value[:len(obscurePrefix)] == obscurePrefix
}
