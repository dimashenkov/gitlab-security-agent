package convert

import "os/exec"

// Probe reports whether the converter binary is present.
func Probe() error {
	return exec.Command("/usr/bin/convert", "-version").Run()
}
