package utils

import "strings"

func ByteToStrFilename(filename [64]byte) string {
	str := string(filename[:])
	return strings.TrimRight(str, "\x00") // \x00 is NULL terminator and 0 value in byte
}

func ByteToStrComm(filename [16]byte) string {
	str := string(filename[:])
	return strings.TrimRight(str, "\x00") // \x00 is NULL terminator and 0 value in byte
}
