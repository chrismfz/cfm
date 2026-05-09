package kernsec

import (
	"os"
	"os/exec"
)

// RealFS is the production FS implementation backed by the OS.
type RealFS struct{}

func (RealFS) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (RealFS) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (RealFS) IsDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func (RealFS) LookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (RealFS) RunCapture(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}
