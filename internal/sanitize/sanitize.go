package sanitize

import "strings"

// ForTerminal strips ANSI escape sequences and non-printable characters
// from a string so it is safe to display in a terminal.
//
// Specifically it:
//   - replaces newlines, carriage returns, and tabs with spaces
//   - drops ASCII control characters (< 32 and DEL)
//   - drops C1 control characters (U+0080–U+009F), some of which terminals
//     interpret as escape sequences (e.g. U+009B ≡ ESC[)
//   - drops Unicode bidirectional override characters that could visually
//     reorder text (U+202A–U+202E, U+2066–U+2069)
//   - drops zero-width and BOM characters (U+200B, U+200C, U+200D, U+FEFF)
func ForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		if r >= 0x80 && r <= 0x9F {
			return -1
		}
		if r >= 0x202A && r <= 0x202E {
			return -1
		}
		if r >= 0x2066 && r <= 0x2069 {
			return -1
		}
		if r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF {
			return -1
		}
		return r
	}, s)
}
