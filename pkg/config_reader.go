package pkg

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Postgres  DBConfig `yaml:"Posgress"`
	Wireguard WGConfig `yaml:"Wireguard"`
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
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
