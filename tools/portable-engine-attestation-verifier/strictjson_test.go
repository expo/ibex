package main

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseStrictJSON(t *testing.T) {
	t.Parallel()

	valid := []string{
		`null`,
		`{"emoji":"\uD83D\uDE00","fraction":0.1,"integer":9007199254740991}`,
		strings.Repeat("[", maxJSONNestingDepth) + "null" + strings.Repeat("]", maxJSONNestingDepth),
	}
	for _, raw := range valid {
		raw := raw
		t.Run("valid", func(t *testing.T) {
			t.Parallel()
			if _, err := parseStrictJSON([]byte(raw)); err != nil {
				t.Fatalf("parseStrictJSON(%q): %v", raw, err)
			}
		})
	}

	invalid := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"invalid UTF-8", []byte{'"', 0xff, '"'}},
		{"duplicate root member", []byte(`{"x":1,"x":2}`)},
		{"duplicate decoded member", []byte(`{"a":1,"\u0061":2}`)},
		{"duplicate nested member", []byte(`{"outer":{"x":1,"x":2}}`)},
		{"lone high surrogate", []byte(`"\uD800"`)},
		{"lone low surrogate", []byte(`"\uDC00"`)},
		{"bad surrogate pair", []byte(`"\uD800\u0041"`)},
		{"unescaped control", []byte{'"', 0x01, '"'}},
		{"second document", []byte(`{} {}`)},
		{"trailing data", []byte(`nullx`)},
		{"nonfinite binary64", []byte(`1e400`)},
		{"binary64 underflow", []byte(`1e-4000`)},
		{"unsafe integer", []byte(`9007199254740992`)},
		{"unsafe integer-valued decimal", []byte(`9007199254740992.0`)},
		{"unsafe integer-valued exponent", []byte(`9.007199254740992e15`)},
		{"leading zero", []byte(`01`)},
		{"trailing decimal", []byte(`1.`)},
		{"missing exponent", []byte(`1e`)},
		{"too deeply nested", []byte(strings.Repeat("[", maxJSONNestingDepth+1) + "null" + strings.Repeat("]", maxJSONNestingDepth+1))},
		{"object key cap", []byte(`{"` + strings.Repeat("k", maxJSONObjectKeyBytes+1) + `":null}`)},
		{"object member cap", objectWithMembers(maxJSONObjectMembers + 1)},
		{"array element cap", []byte(`[` + strings.Repeat("null,", maxJSONArrayElements) + `null]`)},
		{"number token cap", []byte(strings.Repeat("9", maxJSONNumberTokenBytes+1))},
	}
	for _, test := range invalid {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseStrictJSON(test.raw); err == nil {
				t.Fatalf("parseStrictJSON(%q) unexpectedly succeeded", test.raw)
			}
		})
	}
}

func objectWithMembers(count int) []byte {
	var builder strings.Builder
	builder.WriteByte('{')
	for index := 0; index < count; index++ {
		if index != 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(`"k`)
		builder.WriteString(strconv.Itoa(index))
		builder.WriteString(`":null`)
	}
	builder.WriteByte('}')
	return []byte(builder.String())
}

func TestExactFieldsIsClosed(t *testing.T) {
	t.Parallel()

	if err := exactFields(map[string]any{"a": "value"}, "$", "a"); err != nil {
		t.Fatalf("exact field set rejected: %v", err)
	}
	if err := exactFields(map[string]any{"a": "value", "extra": "value"}, "$", "a"); err == nil {
		t.Fatal("unknown field unexpectedly accepted")
	}
	if err := exactFields(map[string]any{}, "$", "a"); err == nil {
		t.Fatal("missing field unexpectedly accepted")
	}
}

func FuzzParseStrictJSONNeverPanics(f *testing.F) {
	f.Add([]byte(`{"a":[true,false,null,"\uD83D\uDE00",1.25]}`))
	f.Add([]byte(`{"x":1,"x":2}`))
	f.Add([]byte(`"\uD800"`))
	f.Add([]byte{0xff, 0x00, '{'})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseStrictJSON(raw)
	})
}
