package hi

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	EnableDebian bool
	EnableGitHub bool
	EnableGo     bool
}

func ReadConfigFile(configDirectory string) (*Config, error) {
	path := filepath.Join(configDirectory, "config")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(file)
	result, err := parseConfig(scanner)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		if closeErr == nil {
			return nil, err
		} else if err == nil {
			return nil, closeErr
		}

		return nil, fmt.Errorf("both parsing and close failed %w %w", err, closeErr)
	}

	return result, nil
}

type ConfigKey string

const (
	keyEnableDebian ConfigKey = "EnableDebian"
	keyEnableGitHub ConfigKey = "EnableGitHub"
	keyEnableGo     ConfigKey = "EnableGo"
)

type ConfigMap struct {
	m map[ConfigKey]string
}

func newConfigMap(keys ...ConfigKey) *ConfigMap {
	m := make(map[ConfigKey]string)

	for _, key := range keys {
		m[key] = ""
	}

	return &ConfigMap{m: m}
}

func (c *ConfigMap) set(key ConfigKey, value string) {
	c.m[key] = value
}

func (c *ConfigMap) get(key ConfigKey) (string, bool) {
	a, b := c.m[key]
	return a, b
}

func (c *ConfigMap) getBool(key ConfigKey, defaultValue bool) (bool, error) {
	result := defaultValue

	stringValue := c.m[key]
	if stringValue != "" {
		v, err := strconv.ParseBool(stringValue)
		if err != nil {
			return false, fmt.Errorf("config %s= invalid bool '%s'", key, stringValue)
		}
		result = v
	}

	return result, nil
}

func parseConfig(scanner *bufio.Scanner) (*Config, error) {
	configMap := newConfigMap(keyEnableDebian,
		keyEnableGitHub,
		keyEnableGo,
	)

	for scanner.Scan() {
		line := scanner.Text()

		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, "=", 2)

			if len(parts) != 2 {
				return nil, fmt.Errorf("config malformed line: '%s'", line)
			}

			key := ConfigKey(parts[0])
			value := parts[1]

			s, found := configMap.get(key)
			if !found {
				return nil, fmt.Errorf("config unknown key '%s': '%s'", key, line)
			}

			if s != "" {
				return nil, fmt.Errorf("config duplicate key '%s'", line)
			}

			if value == "" {
				return nil, fmt.Errorf("config %s= is empty", key)
			}

			configMap.set(key, value)
		}
	}

	err := scanner.Err()
	if err != nil {
		return nil, err
	}

	enableDebian, err := configMap.getBool(keyEnableDebian, false)
	if err != nil {
		return nil, err
	}

	enableGitHub, err := configMap.getBool(keyEnableGitHub, false)
	if err != nil {
		return nil, err
	}

	enableGo, err := configMap.getBool(keyEnableGo, false)
	if err != nil {
		return nil, err
	}

	return &Config{
		EnableDebian: enableDebian,
		EnableGitHub: enableGitHub,
		EnableGo:     enableGo,
	}, nil
}

func readConfig(configDirectory string, filename string) (res []string, err error) {
	path := filepath.Join(configDirectory, filename)

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var result []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := sc.Text()

		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}

	err = sc.Err()
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		if closeErr == nil {
			return nil, err
		} else if err == nil {
			return nil, closeErr
		}

		return nil, fmt.Errorf("both scanning and close failed %w %w", err, closeErr)
	}

	return result, err
}
