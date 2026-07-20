package main

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxIJSONInteger         = int64(1<<53 - 1)
	maxJSONNestingDepth     = 64
	maxJSONObjectMembers    = 4096
	maxJSONArrayElements    = 4096
	maxJSONObjectKeyBytes   = 1024
	maxJSONNumberTokenBytes = 128
)

// parseStrictJSON implements the byte-level I-JSON gate used before either
// protobuf JSON or application-schema parsing. encoding/json alone is not
// sufficient here: it replaces lone UTF-16 surrogates and accepts duplicate
// object names using last-wins semantics.
func parseStrictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("input is not valid UTF-8")
	}
	p := strictJSONParser{raw: raw}
	p.skipSpace()
	if p.pos == len(raw) {
		return nil, fmt.Errorf("empty JSON document")
	}
	value, err := p.parseValue("$", 0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(raw) {
		return nil, fmt.Errorf("byte %d: trailing data or a second JSON document", p.pos)
	}
	return value, nil
}

type strictJSONParser struct {
	raw []byte
	pos int
}

// strictJSONNumber remains distinct from string so schema checks cannot
// accidentally accept a JSON number where the signed profile requires text.
type strictJSONNumber string

func (p *strictJSONParser) parseValue(where string, depth int) (any, error) {
	p.skipSpace()
	if p.pos >= len(p.raw) {
		return nil, fmt.Errorf("%s: unexpected end of JSON input", where)
	}
	switch p.raw[p.pos] {
	case '{':
		if depth >= maxJSONNestingDepth {
			return nil, fmt.Errorf("%s: JSON nesting exceeds %d containers", where, maxJSONNestingDepth)
		}
		return p.parseObject(where, depth+1)
	case '[':
		if depth >= maxJSONNestingDepth {
			return nil, fmt.Errorf("%s: JSON nesting exceeds %d containers", where, maxJSONNestingDepth)
		}
		return p.parseArray(where, depth+1)
	case '"':
		return p.parseString(where)
	case 't':
		if p.consumeLiteral("true") {
			return true, nil
		}
	case 'f':
		if p.consumeLiteral("false") {
			return false, nil
		}
	case 'n':
		if p.consumeLiteral("null") {
			return nil, nil
		}
	default:
		if p.raw[p.pos] == '-' || (p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9') {
			return p.parseNumber(where)
		}
	}
	return nil, fmt.Errorf("%s: byte %d: invalid JSON value", where, p.pos)
}

func (p *strictJSONParser) parseObject(where string, depth int) (map[string]any, error) {
	p.pos++
	p.skipSpace()
	result := make(map[string]any)
	if p.take('}') {
		return result, nil
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.raw) || p.raw[p.pos] != '"' {
			return nil, fmt.Errorf("%s: byte %d: object member name must be a string", where, p.pos)
		}
		key, err := p.parseString(where + " object key")
		if err != nil {
			return nil, err
		}
		if len(key) > maxJSONObjectKeyBytes {
			return nil, fmt.Errorf("%s: object member name exceeds %d bytes", where, maxJSONObjectKeyBytes)
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("%s: duplicate object member %q", where, key)
		}
		if len(result) >= maxJSONObjectMembers {
			return nil, fmt.Errorf("%s: object exceeds %d members", where, maxJSONObjectMembers)
		}
		p.skipSpace()
		if !p.take(':') {
			return nil, fmt.Errorf("%s.%s: byte %d: expected ':'", where, key, p.pos)
		}
		value, err := p.parseValue(where+"."+key, depth)
		if err != nil {
			return nil, err
		}
		result[key] = value
		p.skipSpace()
		if p.take('}') {
			return result, nil
		}
		if !p.take(',') {
			return nil, fmt.Errorf("%s: byte %d: expected ',' or '}'", where, p.pos)
		}
	}
}

func (p *strictJSONParser) parseArray(where string, depth int) ([]any, error) {
	p.pos++
	p.skipSpace()
	result := []any{}
	if p.take(']') {
		return result, nil
	}
	for index := 0; ; index++ {
		if index >= maxJSONArrayElements {
			return nil, fmt.Errorf("%s: array exceeds %d elements", where, maxJSONArrayElements)
		}
		value, err := p.parseValue(fmt.Sprintf("%s[%d]", where, index), depth)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
		p.skipSpace()
		if p.take(']') {
			return result, nil
		}
		if !p.take(',') {
			return nil, fmt.Errorf("%s: byte %d: expected ',' or ']'", where, p.pos)
		}
	}
}

func (p *strictJSONParser) parseString(where string) (string, error) {
	if !p.take('"') {
		return "", fmt.Errorf("%s: byte %d: expected string", where, p.pos)
	}
	var out bytes.Buffer
	for p.pos < len(p.raw) {
		c := p.raw[p.pos]
		switch {
		case c == '"':
			p.pos++
			return out.String(), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.raw) {
				return "", fmt.Errorf("%s: truncated string escape", where)
			}
			escaped := p.raw[p.pos]
			p.pos++
			switch escaped {
			case '"', '\\', '/':
				out.WriteByte(escaped)
			case 'b':
				out.WriteByte('\b')
			case 'f':
				out.WriteByte('\f')
			case 'n':
				out.WriteByte('\n')
			case 'r':
				out.WriteByte('\r')
			case 't':
				out.WriteByte('\t')
			case 'u':
				r, err := p.parseUnicodeEscape(where)
				if err != nil {
					return "", err
				}
				out.WriteRune(r)
			default:
				return "", fmt.Errorf("%s: byte %d: invalid string escape", where, p.pos-1)
			}
		case c < 0x20:
			return "", fmt.Errorf("%s: byte %d: unescaped control character", where, p.pos)
		default:
			r, size := utf8.DecodeRune(p.raw[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return "", fmt.Errorf("%s: byte %d: invalid UTF-8", where, p.pos)
			}
			out.Write(p.raw[p.pos : p.pos+size])
			p.pos += size
		}
	}
	return "", fmt.Errorf("%s: unterminated string", where)
}

func (p *strictJSONParser) parseUnicodeEscape(where string) (rune, error) {
	first, err := p.takeHex4(where)
	if err != nil {
		return 0, err
	}
	firstRune := rune(first)
	if firstRune >= 0xDC00 && firstRune <= 0xDFFF {
		return 0, fmt.Errorf("%s: lone low UTF-16 surrogate", where)
	}
	if firstRune < 0xD800 || firstRune > 0xDBFF {
		return firstRune, nil
	}
	if p.pos+2 > len(p.raw) || p.raw[p.pos] != '\\' || p.raw[p.pos+1] != 'u' {
		return 0, fmt.Errorf("%s: lone high UTF-16 surrogate", where)
	}
	p.pos += 2
	second, err := p.takeHex4(where)
	if err != nil {
		return 0, err
	}
	secondRune := rune(second)
	if secondRune < 0xDC00 || secondRune > 0xDFFF {
		return 0, fmt.Errorf("%s: high UTF-16 surrogate is not followed by a low surrogate", where)
	}
	return utf16.DecodeRune(firstRune, secondRune), nil
}

func (p *strictJSONParser) takeHex4(where string) (uint16, error) {
	if p.pos+4 > len(p.raw) {
		return 0, fmt.Errorf("%s: truncated Unicode escape", where)
	}
	value, err := strconv.ParseUint(string(p.raw[p.pos:p.pos+4]), 16, 16)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid Unicode escape at byte %d", where, p.pos)
	}
	p.pos += 4
	return uint16(value), nil
}

func (p *strictJSONParser) parseNumber(where string) (any, error) {
	start := p.pos
	if p.take('-') && p.pos >= len(p.raw) {
		return nil, fmt.Errorf("%s: truncated number", where)
	}
	if p.take('0') {
		if p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9' {
			return nil, fmt.Errorf("%s: byte %d: leading zero in number", where, p.pos)
		}
	} else {
		if p.pos >= len(p.raw) || p.raw[p.pos] < '1' || p.raw[p.pos] > '9' {
			return nil, fmt.Errorf("%s: byte %d: invalid number", where, p.pos)
		}
		for p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.take('.') {
		fractionStart := p.pos
		for p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == fractionStart {
			return nil, fmt.Errorf("%s: number has no digits after decimal point", where)
		}
	}
	if p.pos < len(p.raw) && (p.raw[p.pos] == 'e' || p.raw[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.raw) && (p.raw[p.pos] == '+' || p.raw[p.pos] == '-') {
			p.pos++
		}
		exponentStart := p.pos
		for p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == exponentStart {
			return nil, fmt.Errorf("%s: number has no exponent digits", where)
		}
	}
	text := string(p.raw[start:p.pos])
	if len(text) > maxJSONNumberTokenBytes {
		return nil, fmt.Errorf("%s: number token exceeds %d bytes", where, maxJSONNumberTokenBytes)
	}
	parsed, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) {
		return nil, fmt.Errorf("%s: number %q is not finite binary64", where, text)
	}
	rat, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, fmt.Errorf("%s: invalid JSON number %q", where, text)
	}
	if parsed == 0 && rat.Sign() != 0 {
		return nil, fmt.Errorf("%s: number %q underflows binary64", where, text)
	}
	if rat.IsInt() {
		limit := big.NewInt(maxIJSONInteger)
		absolute := new(big.Int).Abs(rat.Num())
		if absolute.Cmp(limit) > 0 {
			return nil, fmt.Errorf("%s: integer-valued number %q is outside the I-JSON safe range", where, text)
		}
	}
	return strictJSONNumber(text), nil
}

func (p *strictJSONParser) skipSpace() {
	for p.pos < len(p.raw) {
		switch p.raw[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *strictJSONParser) take(want byte) bool {
	if p.pos < len(p.raw) && p.raw[p.pos] == want {
		p.pos++
		return true
	}
	return false
}

func (p *strictJSONParser) consumeLiteral(literal string) bool {
	if len(p.raw)-p.pos < len(literal) || string(p.raw[p.pos:p.pos+len(literal)]) != literal {
		return false
	}
	p.pos += len(literal)
	return true
}

func objectAt(value any, where string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected JSON object", where)
	}
	return object, nil
}

func arrayAt(value any, where string) ([]any, error) {
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected JSON array", where)
	}
	return array, nil
}

func stringAt(value any, where string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s: expected JSON string", where)
	}
	return text, nil
}

func exactFields(object map[string]any, where string, fields ...string) error {
	want := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		want[field] = struct{}{}
	}
	for field := range object {
		if _, ok := want[field]; !ok {
			return fmt.Errorf("%s: unknown field %q", where, field)
		}
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return fmt.Errorf("%s: missing field %q", where, field)
		}
	}
	return nil
}

func exactString(object map[string]any, field, expected, where string) error {
	actual, err := stringAt(object[field], where+"."+field)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("%s.%s: expected %q, got %q", where, field, expected, actual)
	}
	return nil
}
