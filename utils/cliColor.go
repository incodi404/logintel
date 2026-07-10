package utils

func Error(text string) string {
	return "\033[31m" + text + "\033[0m"
}

func Success(text string) string {
	return "\033[32m" + text + "\033[0m"
}

func Warn(text string) string {
	return "\033[33m" + text + "\033[0m"
}

func Info(text string) string {
	return "\033[34m" + text + "\033[0m"
}
