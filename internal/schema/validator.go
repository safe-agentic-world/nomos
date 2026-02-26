package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

type Schema struct {
	Type                 string             `json:"type"`
	Required             []string           `json:"required"`
	Properties           map[string]*Schema `json:"properties"`
	AdditionalProperties *bool              `json:"additionalProperties"`
	Pattern              string             `json:"pattern"`
	MaxLength            *int               `json:"maxLength"`
	MinLength            *int               `json:"minLength"`
	Enum                 []string           `json:"enum"`
}

func ParseSchema(data []byte) (*Schema, error) {
	var s Schema
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func Validate(schema *Schema, data []byte) error {
	var value any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return err
	}
	return validateValue(schema, value)
}

func validateValue(schema *Schema, value any) error {
	if schema == nil {
		return errors.New("schema is nil")
	}
	switch schema.Type {
	case "object":
		obj, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object, got %T", value)
		}
		for _, field := range schema.Required {
			if _, ok := obj[field]; !ok {
				return fmt.Errorf("missing required field %q", field)
			}
		}
		if schema.AdditionalProperties != nil && !*schema.AdditionalProperties {
			for key := range obj {
				if _, ok := schema.Properties[key]; !ok {
					return fmt.Errorf("unknown field %q", key)
				}
			}
		}
		keys := make([]string, 0, len(obj))
		for key := range obj {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			propertySchema, ok := schema.Properties[key]
			if !ok {
				continue
			}
			if err := validateValue(propertySchema, obj[key]); err != nil {
				return fmt.Errorf("field %q: %w", key, err)
			}
		}
	case "string":
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
		if schema.MinLength != nil && len(str) < *schema.MinLength {
			return fmt.Errorf("string too short")
		}
		if schema.MaxLength != nil && len(str) > *schema.MaxLength {
			return fmt.Errorf("string too long")
		}
		if schema.Pattern != "" {
			re, err := regexp.Compile(schema.Pattern)
			if err != nil {
				return fmt.Errorf("invalid pattern: %w", err)
			}
			if !re.MatchString(str) {
				return fmt.Errorf("string does not match pattern")
			}
		}
		if len(schema.Enum) > 0 {
			match := false
			for _, item := range schema.Enum {
				if item == str {
					match = true
					break
				}
			}
			if !match {
				return fmt.Errorf("string is not in enum")
			}
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return fmt.Errorf("expected array, got %T", value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean, got %T", value)
		}
	case "number", "integer":
		if _, ok := value.(json.Number); !ok {
			return fmt.Errorf("expected number, got %T", value)
		}
	case "null":
		if value != nil {
			return fmt.Errorf("expected null, got %T", value)
		}
	default:
		return fmt.Errorf("unsupported schema type %q", schema.Type)
	}
	return nil
}
