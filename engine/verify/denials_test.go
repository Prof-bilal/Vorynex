package verify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDenials(t *testing.T) {
	p := filepath.Join(t.TempDir(), "st")
	os.WriteFile(p, []byte(`100 execve("/bin/sh", ["/bin/sh", "-c", "true"], 0x1 /* 2 vars */) = -1 EACCES (Permission denied)
100 execve("/bin/sh", ["/bin/sh"], 0x1 /* 2 vars */) = -1 EACCES (Permission denied)
100 openat(AT_FDCWD, "/etc/nope", O_RDONLY) = -1 ENOENT (No such file or directory)
100 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3
`), 0o644)
	d, err := Denials(p)
	if err != nil || len(d) != 1 || d[0].Resource != "/bin/sh" || d[0].Count != 2 || d[0].Action != "execve" {
		t.Fatalf("got %+v err=%v", d, err)
	}
}
