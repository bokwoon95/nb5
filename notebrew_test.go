package nb5

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bokwoon95/nb5/internal/testutil"
)

func Test_validateName(t *testing.T) {
	type TestTable struct {
		description string
		name        string
		wantErrs    []string
	}

	tests := []TestTable{{
		description: "empty",
		name:        "",
		wantErrs: []string{
			"cannot be empty",
		},
	}, {
		description: "uppercase and forbidden characters",
		name:        "<<INDEX?.HTML>>",
		wantErrs: []string{
			"no uppercase letters [A-Z] allowed",
			"forbidden characters: <?>",
		},
	}, {
		description: "uppercase and forbidden characters",
		name:        "<<INDEX?.HTML>>",
		wantErrs: []string{
			"no uppercase letters [A-Z] allowed",
			"forbidden characters: <?>",
		},
	}, {
		description: "uppercase and forbidden name",
		name:        "COM1",
		wantErrs: []string{
			"no uppercase letters [A-Z] allowed",
			"forbidden name",
		},
	}, {
		description: "ok",
		name:        "apple",
		wantErrs:    nil,
	}}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()
			gotErrs := validateName(tt.name)
			if diff := testutil.Diff(gotErrs, tt.wantErrs); diff != "" {
				t.Error(testutil.Callers(), diff)
			}
		})
	}
}

func Test_validatePath(t *testing.T) {
	type TestTable struct {
		description string
		path        string
		wantErrs    []string
	}

	tests := []TestTable{{
		description: "empty",
		path:        "",
		wantErrs: []string{
			"cannot be empty",
		},
	}, {
		description: "slashes",
		path:        "/a/b//c/index.html/",
		wantErrs: []string{
			"cannot have leading slash",
			"cannot have trailing slash",
			"cannot have multiple slashes next to each other",
		},
	}, {
		description: "uppercase and forbidden characters",
		path:        "<<FOLDER/INDEX?.HTML>>",
		wantErrs: []string{
			"no uppercase letters [A-Z] allowed",
			"forbidden characters: <?>",
		},
	}, {
		description: "uppercase and forbidden name",
		path:        "FOLDER/COM1/cOn/lpT9",
		wantErrs: []string{
			"no uppercase letters [A-Z] allowed",
			"forbidden name(s): COM1, cOn, lpT9",
		},
	}, {
		description: "ok",
		path:        "apple/banana/cherry",
		wantErrs:    nil,
	}}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()
			gotErrs := validatePath(tt.path)
			if diff := testutil.Diff(gotErrs, tt.wantErrs); diff != "" {
				t.Error(testutil.Callers(), diff)
			}
		})
	}
}

func Test_create(t *testing.T) {
	type TestTable struct {
		description    string
		notebrew       *Notebrew
		method         string // request method
		header         http.Header
		rawQuery       string    // request GET query parameters
		body           io.Reader // request POST body
		wantStatusCode int       // response status code
		wantLocation   string    // response Location header (without the raw query after the "?")
	}
}

type TestFS struct {
	fstest.MapFS
}

func (fsys TestFS) OpenWriter(name string) (io.WriteCloser, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	testFile := &TestFile{
		mapFS: fsys.MapFS,
		name:  name,
		buf:   &bytes.Buffer{},
	}
	return testFile, nil
}

func (fsys TestFS) MkdirAll(path string, perm fs.FileMode) error {
	if !fs.ValidPath(path) {
		return &fs.PathError{Op: "mkdirall", Path: path, Err: fs.ErrInvalid}
	}
	fsys.MapFS[path] = &fstest.MapFile{
		Mode:    fs.ModeDir,
		ModTime: time.Now(),
	}
	return nil
}

func (fsys TestFS) RemoveAll(path string) error {
	if !fs.ValidPath(path) {
		return &fs.PathError{Op: "removeall", Path: path, Err: fs.ErrInvalid}
	}
	delete(fsys.MapFS, path)
	pathPrefix := path + "/"
	for name := range fsys.MapFS {
		if strings.HasPrefix(name, pathPrefix) {
			delete(fsys.MapFS, name)
		}
	}
	return nil
}

func (fsys TestFS) Move(oldpath, newpath string) error {
	if !fs.ValidPath(oldpath) {
		return &fs.PathError{Op: "move", Path: oldpath, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newpath) {
		return &fs.PathError{Op: "move", Path: newpath, Err: fs.ErrInvalid}
	}
	oldFileInfo, err := fs.Stat(fsys.MapFS, oldpath)
	if err != nil {
		// If source file/directory does not exist, no point in moving
		// anything.
		return err
	}
	var data []byte
	if !oldFileInfo.IsDir() {
		data, err = fs.ReadFile(fsys.MapFS, oldpath)
		if err != nil {
			return err
		}
	}
	newFileInfo, err := fs.Stat(fsys.MapFS, newpath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// If destination does not exist, the file or directory can safely
			// take its place. Copy the data and filemode over.
			delete(fsys.MapFS, oldpath)
			fsys.MapFS[newpath] = &fstest.MapFile{
				Data:    data,
				Mode:    oldFileInfo.Mode(),
				ModTime: time.Now(),
			}
			return nil
		}
		return err
	}
	if oldFileInfo.IsDir() {
		// A directory cannot be moved if its destination exists, no matter if
		// the destination is a file or another directory.
		return fmt.Errorf("%s already exists", newpath)
	}
	if newFileInfo.IsDir() {
		// Move file into directory.
		delete(fsys.MapFS, oldpath)
		fsys.MapFS[path.Join(newpath, oldFileInfo.Name())] = &fstest.MapFile{
			Data:    data,
			Mode:    oldFileInfo.Mode(),
			ModTime: time.Now(),
		}
		return nil
	}
	fsys.MapFS[newpath] = &fstest.MapFile{
		Data:    data,
		Mode:    oldFileInfo.Mode(),
		ModTime: time.Now(),
	}
	return nil
}

type TestFile struct {
	mapFS       fstest.MapFS
	name        string
	buf         *bytes.Buffer
	writeFailed bool
}

func (f *TestFile) Write(p []byte) (n int, err error) {
	n, err = f.buf.Write(p)
	if err != nil {
		f.writeFailed = true
	}
	return n, err
}

func (f *TestFile) Close() error {
	if f.buf == nil {
		return fmt.Errorf("already closed")
	}
	defer func() {
		f.buf = nil
	}()
	if f.writeFailed {
		return nil
	}
	f.mapFS[f.name] = &fstest.MapFile{
		Data:    f.buf.Bytes(),
		ModTime: time.Now(),
	}
	return nil
}
