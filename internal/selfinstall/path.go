// SPDX-License-Identifier: MIT

package selfinstall

import "strings"

// PathHas: a Windows PATH value (dirs separated by ;) has dir, in any
// case, with or without a trailing backslash.
func PathHas(path, dir string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimRight(strings.TrimSpace(s), `\`)) }
	d := norm(dir)
	for _, p := range strings.Split(path, ";") {
		if norm(p) == d {
			return true
		}
	}
	return false
}

// PathAppend adds dir to the end of a PATH value.
func PathAppend(path, dir string) string {
	path = strings.TrimRight(path, ";")
	if path == "" {
		return dir
	}
	return path + ";" + dir
}
