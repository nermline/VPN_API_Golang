package pkg

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Postgres  DBConfig  `yaml:"Postgres"`
	Wireguard WGConfig  `yaml:"Wireguard"`
	API       APIConfig `yaml:"API"`
}

type DBConfig struct {
	User     string `yaml:"User"`
	Password string `yaml:"Password"`
	Host     string `yaml:"Host"`
	DBName   string `yaml:"DBName"`
	SSLMode  string `yaml:"SSLMode"`
}

type WGConfig struct {
	Interface string `yaml:"Interface"`
	DNS       string `yaml:"DNS"`
	Port      string `yaml:"Port"`
}

type APIConfig struct {
	Listen              string `yaml:"Listen"`
	Port                string `yaml:"Port"`
	Domain              string `yaml:"Domain"`
	Debug               bool   `yaml:"Debug"`
	ForwardedByClientIP bool   `yaml:"ForwardedByClientIP"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("LoadConfig: %v", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("LoadConfig: %v", err)
	}
	return &cfg, nil
}
