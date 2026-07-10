package models

type Fanotify_Filter_Rule struct {
	BlacklistDic Blacklist `yaml:"blacklist"`
}

type Blacklist struct {
	Path        map[string]bool `yaml:"path"`
	ProcessName map[string]bool `yaml:"process_name"`
	CmdName     map[string]bool `yaml:"cmd_name"`
}
