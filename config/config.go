package config

import (
	"fmt"

	"github.com/incodi404/logintel/utils"
)

type LoadedConfig struct {
	Server ServerConfig `yaml:"server"`
	Token  TokenConfig  `yaml:"token"`
}

type ServerConfig struct {
	Url string `yaml:"url"`
}

type TokenConfig struct {
	AgentId string `yaml:"agentId"`
}

var ConfigValues LoadedConfig

func LoadConfig() error {
	configData, err := utils.YamlProcessing[LoadedConfig]("./config.yaml")
	if err != nil {
		return fmt.Errorf("[CONFIG] Error loading config.yaml: %w", err)
	}

	ConfigValues.Server.Url = configData.Server.Url
	ConfigValues.Token.AgentId = configData.Token.AgentId

	return nil
}
