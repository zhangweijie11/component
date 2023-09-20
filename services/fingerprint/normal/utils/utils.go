package utils

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"math/rand"
	"net"
	"strconv"
	"strings"
)

// ContainsAny 判断某个元素是否在切片内
func ContainsAny(s string, ss ...string) bool {
	for _, sss := range ss {
		if strings.Contains(s, sss) {
			return true
		}
	}
	return false
}

// IndexAt 根据位置查找字符串
func IndexAt(s, sep string, n int) int {
	idx := strings.Index(s[n:], sep)
	if idx > -1 {
		idx += n
	}
	return idx
}

// InsertInto 在某个位置插入数据
func InsertInto(s string, interval int, sep rune) string {
	var buffer bytes.Buffer
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteRune(char)
		if i%interval == before && i != last {
			buffer.WriteRune(sep)
		}
	}
	buffer.WriteRune(sep)
	return buffer.String()
}

// map转字符串
func mapToString(dataMap map[string]string, separator string) string {
	var result string
	for key, value := range dataMap {
		result += key + "=" + value + separator
	}

	// 去掉末尾的分隔符
	if len(result) > len(separator) {
		result = result[:len(result)-len(separator)]
	}

	return result
}

// map转字符串
func mapToToString(dataMap map[string][]string) string {
	var result string
	for key, values := range dataMap {
		// 将每个键值对的键和值拼接为字符串
		valueString := strings.Join(values, ", ")
		result += key + "=" + valueString
	}

	return result
}

// ToString 快速将接口转换为字符串
func ToString(data interface{}) string {
	switch s := data.(type) {
	case nil:
		return ""
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32)
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case int32:
		return strconv.Itoa(int(s))
	case int16:
		return strconv.FormatInt(int64(s), 10)
	case int8:
		return strconv.FormatInt(int64(s), 10)
	case uint:
		return strconv.FormatUint(uint64(s), 10)
	case uint64:
		return strconv.FormatUint(s, 10)
	case uint32:
		return strconv.FormatUint(uint64(s), 10)
	case uint16:
		return strconv.FormatUint(uint64(s), 10)
	case uint8:
		return strconv.FormatUint(uint64(s), 10)
	case []byte:
		return string(s)
	case []string:
		return strings.Join(s, "")
	case map[string]string:
		// 将 map 转换为字符串，使用逗号和空格作为键值对的分隔符
		return mapToString(s, "")
	case map[string][]string:
		return mapToToString(s)
	case fmt.Stringer:
		return s.String()
	case error:
		return s.Error()
	default:
		return fmt.Sprintf("%v", data)
	}
}

// GetRandomIPWithCidr 随机获取 CIDR 类型的 IP
func GetRandomIPWithCidr(cidrs ...string) (net.IP, error) {
	if len(cidrs) == 0 {
		return nil, errors.Errorf("must specify at least one cidr")
	}
	cidr := cidrs[rand.Intn(len(cidrs))]

	if !IsCIDR(cidr) {
		return nil, errors.Errorf("%s is not a valid cidr", cidr)
	}

	baseIp, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	switch {
	case 255 == ipnet.Mask[len(ipnet.Mask)-1]:
		return baseIp, nil
	case IsIPv4(baseIp.String()):
		return getRandomIP(ipnet, 4), nil
	case IsIPv6(baseIp.String()):
		return getRandomIP(ipnet, 16), nil
	default:
		return nil, errors.New("invalid base ip")
	}
}

// FirstNonZero 函数采用类似类型输入的切片，并返回切片中的第一个非零元素以及是否找到非零元素的布尔值
func FirstNonZero[T comparable](inputs []T) (T, bool) {
	var zero T

	for _, v := range inputs {
		if v != zero {
			return v, true
		}
	}

	return zero, false
}

// GetStatusCode 获取有效的状态码
func GetStatusCode(data map[string]interface{}) (int, bool) {
	statusCodeValue, ok := data["status_code"]
	if !ok {
		return 0, false
	}
	statusCode, ok := statusCodeValue.(int)
	if !ok {
		return 0, false
	}
	return statusCode, true
}
