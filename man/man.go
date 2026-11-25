// SPDX-License-Identifier: MIT

// Package man is dpt's manual page, built into dpt so dpt install puts
// it where man finds it.
package man

import _ "embed"

// Page is dpt(1), in man's own format.
//
//go:embed dpt.1
var Page []byte
