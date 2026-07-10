package utils

import (
	"encoding/binary"
	"strconv"
	"strings"
)

/*
NOTE: strconv.Itoa(int(ip_arr[0])),

ip_arr[0] byte
int(ip_arr[0]) byte => int (same value)
strconv.Itoa(int(ip_arr[0])) int => string
*/

func FormatIPv4Str(ip_arr [4]byte) string {
	parts := []string{
		strconv.Itoa(int(ip_arr[0])),
		strconv.Itoa(int(ip_arr[1])),
		strconv.Itoa(int(ip_arr[2])),
		strconv.Itoa(int(ip_arr[3])),
	}

	return strings.Join(parts, ".")
}

func UintToIPv4(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return FormatIPv4Str([4]byte(b))
}
