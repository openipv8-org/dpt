// SPDX-License-Identifier: MIT

//go:build darwin

package mel

import "os"

func dhcpPrivileged() bool { return os.Geteuid() == 0 }
