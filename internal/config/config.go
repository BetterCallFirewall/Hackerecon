package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
	Web   WebConfig   `yaml:"web"`
}

type ProxyConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type WebConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

func Load() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}
	return &Config{
		Proxy: ProxyConfig{
			ListenAddr: os.Getenv("PROXY_LISTEN_ADDR"),
		},
		Web: WebConfig{
			ListenAddr: os.Getenv("PROXY_LISTEN_ADDR"),
		},
	}, nil
}
