package utils

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func YamlProcessing[T any](path string) (T, error) {
	var config T

	// reading file
	rawData, err := os.ReadFile(path)
	if err != nil {
		fmt.Println(Error("[+] ERROR :: YAML file open has been failed"))
		fmt.Println(err)
		return config, err
	}

	// processing
	err = yaml.Unmarshal(rawData, &config)
	if err != nil {
		fmt.Println(Error("[+] ERROR :: YAML file data reading has been failed"))
		fmt.Println(err)
		return config, err
	}

	return config, nil
}
