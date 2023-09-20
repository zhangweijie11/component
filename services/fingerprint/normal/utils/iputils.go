package utils

import (
	"crypto/rand"
	stringsUtil "github.com/projectdiscovery/utils/strings"
	"net"
)

// IsCIDR 检查字符串是否为有效的 CIDR (IPV4 & IPV6)
func IsCIDR(str string) bool {
	_, _, err := net.ParseCIDR(str)
	return err == nil
}

// IsIPv4 检查是否为 IPv4 类型数据
func IsIPv4(ips ...interface{}) bool {
	for _, ip := range ips {
		switch ipv := ip.(type) {
		case string:
			parsedIP := net.ParseIP(ipv)
			isIP4 := parsedIP != nil && parsedIP.To4() != nil && stringsUtil.ContainsAny(ipv, ".")
			if !isIP4 {
				return false
			}
		case net.IP:
			isIP4 := ipv != nil && ipv.To4() != nil && stringsUtil.ContainsAny(ipv.String(), ".")
			if !isIP4 {
				return false
			}
		}
	}

	return true
}

// IsIPv6 检查是否为 IPv6 类型的数据
func IsIPv6(ips ...interface{}) bool {
	for _, ip := range ips {
		switch ipv := ip.(type) {
		case string:
			parsedIP := net.ParseIP(ipv)
			isIP6 := parsedIP != nil && parsedIP.To16() != nil && stringsUtil.ContainsAny(ipv, ":")
			if !isIP6 {
				return false
			}
		case net.IP:
			isIP6 := ipv != nil && ipv.To16() != nil && stringsUtil.ContainsAny(ipv.String(), ":")
			if !isIP6 {
				return false
			}
		}
	}

	return true
}

// 获取随机 IP
func getRandomIP(ipnet *net.IPNet, size int) net.IP {
	ip := ipnet.IP
	var iteration int

	for iteration < 255 {
		iteration++
		ones, _ := ipnet.Mask.Size()
		quotient := ones / 8
		remainder := ones % 8
		var r []byte
		switch size {
		case 4, 16:
			r = make([]byte, size)
		default:
			return ip
		}

		rand.Read(r)

		for i := 0; i <= quotient; i++ {
			if i == quotient {
				shifted := r[i] >> remainder
				r[i] = ipnet.IP[i] + (^ipnet.IP[i] & shifted)
			} else {
				r[i] = ipnet.IP[i]
			}
		}

		ip = r

		if !ip.Equal(ipnet.IP) {
			break
		}
	}

	return ip
}
