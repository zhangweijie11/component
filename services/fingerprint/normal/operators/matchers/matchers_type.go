package matchers

import (
	"encoding/json"
	"errors"
	"github.com/alecthomas/jsonschema"
	"strings"
)

// MatcherType 匹配器匹配类型
type MatcherType int

// MatcherTypeHolder 匹配器内部匹配类型
type MatcherTypeHolder struct {
	MatcherType MatcherType `mapping:"true"`
}

// name:MatcherType
const (
	// name:word
	WordsMatcher MatcherType = iota + 1
	// name:regex
	RegexMatcher
	// name:binary
	BinaryMatcher
	// name:status
	StatusMatcher
	// name:size
	SizeMatcher
	// name:dsl
	DSLMatcher
	matchLimit
)

// MatcherTypes 匹配类型和字符串的映射关系
var MatcherTypes = map[MatcherType]string{
	StatusMatcher: "status",
	SizeMatcher:   "size",
	WordsMatcher:  "word",
	RegexMatcher:  "regex",
	BinaryMatcher: "binary",
	DSLMatcher:    "dsl",
}

// GetMatcherType 获取匹配器的匹配类型
func (matcher *Matcher) GetMatcherType() MatcherType {
	return matcher.Type.MatcherType
}

// GetMatcherPartType 获取匹配器的匹配模块
func (matcher *Matcher) GetMatcherPartType() MatcherPartType {
	if part := matcher.Part.String(); part == "" {
		return AllMatcherPart
	} else {
		return matcher.Part.MatcherPartType
	}
}

// GetSupportedMatcherTypes 获取支持的匹配器类型列表
func GetSupportedMatcherTypes() []MatcherType {
	var result []MatcherType
	for index := MatcherType(1); index < matchLimit; index++ {
		result = append(result, index)
	}
	return result
}

func ToMatcherTypes(valueToMap string) (MatcherType, error) {
	normalizedValue := strings.TrimSpace(strings.ToLower(valueToMap))
	for key, currentValue := range MatcherTypes {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid matcher type: " + valueToMap)
}

func (t MatcherType) String() string {
	return MatcherTypes[t]
}

func (holder *MatcherTypeHolder) String() string {
	return holder.MatcherType.String()
}

func (holder *MatcherTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of the matcher",
		Description: "Type of the matcher",
	}
	for _, types := range GetSupportedMatcherTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *MatcherTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.MatcherType.String())
}

func (holder *MatcherTypeHolder) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" {
		return nil
	}
	computedType, err := ToMatcherTypes(s)
	if err != nil {
		return err
	}

	holder.MatcherType = computedType
	return nil
}

func (holder *MatcherTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.MatcherType.String(), nil
}

func (holder *MatcherTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}
	computedType, err := ToMatcherTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.MatcherType = computedType
	return nil
}
