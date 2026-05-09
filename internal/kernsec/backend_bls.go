package kernsec

import "strings"

// BLSBackend implements BootBackend for BLS / grubby installs
// (RHEL/Alma/Rocky and similar). Reads next-boot args via
// `grubby --info=DEFAULT`.
type BLSBackend struct {
	FS FS
}

func (b *BLSBackend) Label() string {
	return "BLS / grubby"
}

func (b *BLSBackend) NextBootCmdline() (string, error) {
	out, err := b.FS.RunCapture("grubby", "--info=DEFAULT")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "args=") {
			continue
		}
		val := strings.TrimPrefix(t, "args=")
		val = strings.Trim(val, `"`)
		return val, nil
	}
	return "", nil
}
