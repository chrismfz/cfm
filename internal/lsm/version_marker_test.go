package lsm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildMarker_StringEqual(t *testing.T) {
	a := BuildMarker{Version: "2026.05.18-1", BuildTime: "2026-05-18T21:10Z"}
	b := BuildMarker{Version: "2026.05.18-1", BuildTime: "2026-05-18T21:10Z"}
	if !a.Equal(b) {
		t.Fatalf("equal markers reported as different")
	}
	if a.String() != "2026.05.18-1\t2026-05-18T21:10Z" {
		t.Fatalf("unexpected String(): %q", a.String())
	}

	c := BuildMarker{Version: "2026.05.18-1", BuildTime: "different"}
	if a.Equal(c) {
		t.Fatalf("markers with different BuildTime reported as equal")
	}
}

func TestWriteReadBuildMarker_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "marker")

	want := BuildMarker{Version: "2026.05.18-1.180744.el10", BuildTime: "2026-05-18T21:10Z"}
	if err := WriteBuildMarker(path, want); err != nil {
		t.Fatalf("WriteBuildMarker: %v", err)
	}
	got, present, err := ReadBuildMarker(path)
	if err != nil {
		t.Fatalf("ReadBuildMarker: %v", err)
	}
	if !present {
		t.Fatal("marker not present after write")
	}
	if !got.Equal(want) {
		t.Fatalf("roundtrip mismatch: got=%+v want=%+v", got, want)
	}
}

func TestReadBuildMarker_Absent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist")
	_, present, err := ReadBuildMarker(path)
	if err != nil {
		t.Fatalf("absent marker returned err: %v", err)
	}
	if present {
		t.Fatal("absent marker reported as present")
	}
}

func TestReadBuildMarker_Malformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "marker")
	if err := os.WriteFile(path, []byte("\n"), 0o644); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	_, present, err := ReadBuildMarker(path)
	if err == nil {
		t.Fatal("malformed marker should return error")
	}
	if present {
		t.Fatal("malformed marker reported as present")
	}
}

func TestWriteBuildMarker_Atomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "marker")

	// First write creates the file.
	if err := WriteBuildMarker(path, BuildMarker{Version: "v1", BuildTime: "t1"}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	// Second write overwrites atomically (rename, not truncate+write).
	if err := WriteBuildMarker(path, BuildMarker{Version: "v2", BuildTime: "t2"}); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, present, err := ReadBuildMarker(path)
	if err != nil || !present {
		t.Fatalf("post-overwrite read: present=%v err=%v", present, err)
	}
	if got.Version != "v2" || got.BuildTime != "t2" {
		t.Fatalf("overwrite did not stick: %+v", got)
	}

	// No leftover temp files from CreateTemp.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "marker" {
			t.Errorf("leftover file in marker dir: %s", e.Name())
		}
	}
}
