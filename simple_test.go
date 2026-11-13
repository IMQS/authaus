package authaus

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
)

type LegacyStringArray []string

func (a *LegacyStringArray) UnmarshalJSON(b []byte) error {
	var raw json.RawMessage
	// Pass 1: Standard library handles all the "nuances"
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	// Now 'raw' is guaranteed to be a valid JSON value with no leading whitespace.
	// We can safely look at the first byte.
	if len(raw) == 0 {
		return nil
	}

	switch raw[0] {
	case '[':
		// Pass 2: Specific unmarshal for Array
		var slice []string
		if err := json.Unmarshal(raw, &slice); err != nil {
			return err
		}
		*a = slice
	case '{':
		// Pass 2: Specific unmarshal for Map
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		// Extract keys
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys) // Important: Maps are unordered in JSON!
		*a = keys
	default:
		return fmt.Errorf("unexpected JSON type: starts with %q", raw[0])
	}

	return nil
}

func TestTwoParseMarshalling(t *testing.T) {
	var a LegacyStringArray

	// Test with an array
	jsonData1 := `["apple", "banana", "cherry"]`
	if err := json.Unmarshal([]byte(jsonData1), &a); err != nil {
		t.Fatalf("Failed to unmarshal array: %v", err)
	}
	fmt.Printf("Parsed from array: %v\n", a)

	// Test with a map
	jsonData2 := `{"apple": "FCA", "banana": "Mailer", "cherry": 3, "cherry": 4}`
	if err := json.Unmarshal([]byte(jsonData2), &a); err != nil {
		t.Fatalf("Failed to unmarshal map: %v", err)
	}
	fmt.Printf("Parsed from map: %v\n", a)
}
