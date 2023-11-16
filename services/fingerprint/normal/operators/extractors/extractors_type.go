package extractors

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// ExtractorType 提取器
type ExtractorType int

const (
	// name:regex
	RegexExtractor ExtractorType = iota + 1
	// name:kval
	KValExtractor
	// name:xpath
	XPathExtractor
	// name:json
	JSONExtractor
	// name:dsl
	DSLExtractor
	extractorLimit
)

var extractorMappings = map[ExtractorType]string{
	RegexExtractor: "regex",
	KValExtractor:  "kval",
	XPathExtractor: "xpath",
	JSONExtractor:  "json",
	DSLExtractor:   "dsl",
}

// GetSupportedExtractorTypes 获取支持的提取器
func GetSupportedExtractorTypes() []ExtractorType {
	var result []ExtractorType
	for index := ExtractorType(1); index < extractorLimit; index++ {
		result = append(result, index)
	}
	return result
}

// ToExtractorTypes 根据参数获取提取器类型
func ToExtractorTypes(valueToMap string) (ExtractorType, error) {
	normalizedValue := strings.TrimSpace(strings.ToLower(valueToMap))
	for key, currentValue := range extractorMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid extractor type: " + valueToMap)
}

func (t ExtractorType) String() string {
	return extractorMappings[t]
}

// ExtractorTypeHolder 用于容纳提取器的内部类型
type ExtractorTypeHolder struct {
	ExtractorType ExtractorType `mapping:"true"`
}

func (holder *ExtractorTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of the extractor",
		Description: "Type of the extractor",
	}
	for _, types := range GetSupportedExtractorTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *ExtractorTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := ToExtractorTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.ExtractorType = computedType
	return nil
}

func (holder *ExtractorTypeHolder) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" {
		return nil
	}
	computedType, err := ToExtractorTypes(s)
	if err != nil {
		return err
	}

	holder.ExtractorType = computedType
	return nil
}

func (holder *ExtractorTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.ExtractorType.String())
}

func (holder *ExtractorTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.ExtractorType.String(), nil
}
