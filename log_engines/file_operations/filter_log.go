package fileoperations

import (
	"strings"

	"github.com/incodi404/logintel/models"
)

func Fanotify_Filter(
	incomingLog *models.FileOperationLog, rule models.Fanotify_Filter_Rule,
) (*models.FileOperationLog, error) {
	if rule.BlacklistDic.Path[incomingLog.Path] {
		return nil, nil
	}

	if rule.BlacklistDic.ProcessName[incomingLog.Pid.Name] {
		return nil, nil
	}

	if rule.BlacklistDic.CmdName[strings.TrimSpace(incomingLog.Pid.Cmd)] {
		return nil, nil
	}

	return incomingLog, nil
}
