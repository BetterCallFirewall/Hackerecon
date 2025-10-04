package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
	Web   WebConfig   `yaml:"web"`
	Cert  CertConfig  `yaml:"cert"`
}

type ProxyConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type WebConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type CertConfig struct {
	CertFile string `yaml:"cert_file"`
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
		Cert: CertConfig{
			CertFile: os.Getenv("PROXY_CERT_FILE"),
		},
	}, nil
}
