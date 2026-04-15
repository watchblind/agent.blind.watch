//go:build windows

package pathbrowser

// Allowlist of permitted root prefixes on Windows.
var allowedRoots = []string{
	`C:\Logs`,
	`C:\ProgramData`,
	`C:\Users`,
	`C:\Windows\System32\LogFiles`,
}

// Denylisted substrings on Windows — sensitive system directories.
var deniedContains = []string{
	`\Windows\System32\config`,
	`\Windows\security`,
}
