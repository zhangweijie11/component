package templates

import (
	"encoding/json"
	"errors"
	"github.com/alecthomas/jsonschema"
	"strings"
)

// HTTPMethodType 请求方式
type HTTPMethodType int

// HTTPMethodTypeHolder 请求方式的内部类型
type HTTPMethodTypeHolder struct {
	MethodType HTTPMethodType `mapping:"true"`
}

// name:HTTPMethodType
const (
	// name:GET
	HTTPGet HTTPMethodType = iota + 1
	// name:HEAD
	HTTPHead
	// name:POST
	HTTPPost
	// name:PUT
	HTTPPut
	// name:DELETE
	HTTPDelete
	// name:CONNECT
	HTTPConnect
	// name:OPTIONS
	HTTPOptions
	// name:TRACE
	HTTPTrace
	// name:PATCH
	HTTPPatch
	// name:PURGE
	HTTPPurge
	// name:Debug
	HTTPDebug
	httpLimit
)

// HTTPMethodMapping 请求方式和字符串的映射关系
var HTTPMethodMapping = map[HTTPMethodType]string{
	HTTPGet:     "GET",
	HTTPHead:    "HEAD",
	HTTPPost:    "POST",
	HTTPPut:     "PUT",
	HTTPDelete:  "DELETE",
	HTTPConnect: "CONNECT",
	HTTPOptions: "OPTIONS",
	HTTPTrace:   "TRACE",
	HTTPPatch:   "PATCH",
	HTTPPurge:   "PURGE",
	HTTPDebug:   "DEBUG",
}

func (t HTTPMethodType) String() string {
	return HTTPMethodMapping[t]
}

func (holder *HTTPMethodTypeHolder) String() string {
	return holder.MethodType.String()
}

// GetSupportedHTTPMethodTypes 获取支持请求方式的列表
func GetSupportedHTTPMethodTypes() []HTTPMethodType {
	var result []HTTPMethodType
	for index := HTTPMethodType(1); index < httpLimit; index++ {
		result = append(result, index)
	}
	return result
}

func ToHTTPMethodTypes(valueToMap string) (HTTPMethodType, error) {
	normalizedValue := strings.TrimSpace(strings.ToUpper(valueToMap))
	for key, currentValue := range HTTPMethodMapping {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid HTTP method verb: " + valueToMap)
}

func (holder *HTTPMethodTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "method is the HTTP request method",
		Description: "Method is the HTTP Request Method",
	}
	for _, types := range GetSupportedHTTPMethodTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *HTTPMethodTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.MethodType.String())
}

func (holder *HTTPMethodTypeHolder) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" {
		return nil
	}
	computedType, err := ToHTTPMethodTypes(s)
	if err != nil {
		return err
	}

	holder.MethodType = computedType
	return nil
}

func (holder *HTTPMethodTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.MethodType.String(), nil
}

func (holder *HTTPMethodTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := ToHTTPMethodTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.MethodType = computedType
	return nil
}
