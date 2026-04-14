package sanitize

import "testing"

func TestForTerminal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain text preserved",
			input: "hello world 123",
			want:  "hello world 123",
		},
		{
			name:  "newlines replaced with spaces",
			input: "line1\nline2\rline3\ttab",
			want:  "line1 line2 line3 tab",
		},
		{
			name:  "null bytes stripped",
			input: "before\x00after",
			want:  "beforeafter",
		},
		{
			name:  "ANSI escape sequence stripped",
			input: "normal\x1b[31mred\x1b[0m",
			want:  "normal[31mred[0m",
		},
		{
			name:  "DEL character stripped",
			input: "abc\x7fdef",
			want:  "abcdef",
		},
		{
			name:  "C1 control characters stripped",
			input: "before\u0080\u008a\u009fafter",
			want:  "beforeafter",
		},
		{
			name:  "bidi override LRO stripped",
			input: "safe\u202Adangerous\u202E",
			want:  "safedangerous",
		},
		{
			name:  "bidi isolate characters stripped",
			input: "a\u2066b\u2069c",
			want:  "abc",
		},
		{
			name:  "zero-width characters stripped",
			input: "a\u200Bb\u200Cc\u200Dd\uFEFFe",
			want:  "abcde",
		},
		{
			name:  "printable unicode preserved",
			input: "café résumé 日本語",
			want:  "café résumé 日本語",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "all control chars",
			input: "\x01\x02\x03\x04\x05",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ForTerminal(tt.input)
			if got != tt.want {
				t.Errorf("ForTerminal(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
