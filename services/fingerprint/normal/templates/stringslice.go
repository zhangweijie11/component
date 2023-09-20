package templates

import (
	"encoding/json"
	"github.com/alecthomas/jsonschema"
	"strings"
)

// StringSlice 代表一个或多个string
type StringSlice struct {
	Value interface{} `json:"value" yaml:"value"`
}

func (stringSlice *StringSlice) ToSlice() []string {
	switch value := stringSlice.Value.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case nil:
		return []string{}
	default:
		return []string{}
	}
}

// IsBlank 去除空格后是否为空
func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func (stringSlice *StringSlice) String() string {
	return strings.Join(stringSlice.ToSlice(), ", ")
}

func (stringSlice *StringSlice) Normalize(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (stringSlice *StringSlice) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		OneOf: []*jsonschema.Type{{Type: "string"}, {Type: "array"}},
	}
	return gotType
}

func (stringSlice *StringSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal(stringSlice.Value)
}

func (stringSlice *StringSlice) UnmarshalJSON(data []byte) error {
	var marshalledValueAsString string
	var marshalledValuesAsSlice []string

	sliceMarshalError := json.Unmarshal(data, &marshalledValuesAsSlice)
	if sliceMarshalError != nil {
		stringMarshalError := json.Unmarshal(data, &marshalledValueAsString)
		if stringMarshalError != nil {
			return stringMarshalError
		}
	}

	var result []string
	switch {
	case len(marshalledValuesAsSlice) > 0:
		result = marshalledValuesAsSlice
	case !IsBlank(marshalledValueAsString):
		result = strings.Split(marshalledValueAsString, ",")
	default:
		result = []string{}
	}

	values := make([]string, 0, len(result))
	for _, value := range result {
		values = append(values, stringSlice.Normalize(value))
	}
	stringSlice.Value = values
	return nil
}

func (stringSlice *StringSlice) MarshalYAML() (interface{}, error) {
	return stringSlice.Value, nil
}

func (stringSlice *StringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	marshalledSlice, err := marshalStringToSlice(unmarshal)
	if err != nil {
		return err
	}

	result := make([]string, 0, len(marshalledSlice))
	for _, value := range marshalledSlice {
		result = append(result, stringSlice.Normalize(value))
	}
	stringSlice.Value = result
	return nil
}

// 字符串转切片
func marshalStringToSlice(unmarshal func(interface{}) error) ([]string, error) {
	var marshalledValueAsString string
	var marshalledValuesAsSlice []string

	sliceMarshalError := unmarshal(&marshalledValuesAsSlice)
	if sliceMarshalError != nil {
		stringMarshalError := unmarshal(&marshalledValueAsString)
		if stringMarshalError != nil {
			return nil, stringMarshalError
		}
	}

	var result []string
	switch {
	case len(marshalledValuesAsSlice) > 0:
		result = marshalledValuesAsSlice
	case !(strings.TrimSpace(marshalledValueAsString) == ""):
		result = strings.Split(marshalledValueAsString, ",")
	default:
		result = []string{}
	}

	return result, nil
}
