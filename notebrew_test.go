package nb5

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bokwoon95/nb5/internal/testutil"
	"github.com/bokwoon95/sq"
	"github.com/bokwoon95/sqddl/ddl"
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
		name:        "<<IN>>DEX?.HTML",
		wantErrs: []string{
			"no uppercase letters [A-Z] allowed",
			"forbidden characters: <>?",
		},
	}, {
		description: "uppercase and forbidden characters",
		name:        "<<IN>>DEX?.HTML",
		wantErrs: []string{
			"no uppercase letters [A-Z] allowed",
			"forbidden characters: <>?",
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
		beforeHook     func(*testing.T, http.ResponseWriter, *http.Request) // TODO: need to include *Notebrew in the params?
		header         http.Header                                          // request header
		method         string                                               // request method
		url            string                                               // request url
		rawQuery       string                                               // request GET query parameters
		body           io.Reader                                            // request POST body
		wantStatusCode int                                                  // response status code
		wantPageValues url.Values                                           // values extracted from parsing html microdata
		wantLocation   string                                               // response Location header (without the raw query after the "?")
		afterHook      func(*testing.T, http.ResponseWriter, *http.Request)
	}
}

func Test_create_GET(t *testing.T) {
	type TestTable struct {
		description    string
		notebrew       *Notebrew
		header         http.Header
		rawQuery       string
		sessionData    map[string]any
		wantPageValues url.Values
	}

	tests := []TestTable{{
		description: "basic",
		notebrew: &Notebrew{
			DB:            newDatabase(t),
			Dialect:       sq.DialectSQLite,
			Scheme:        "https://",
			AdminDomain:   "notebrew.com",
			ContentDomain: "notebrew.blog",
			MultisiteMode: "subdomain",
		},
		wantPageValues: url.Values{
			"file_path":   []string{""},
			"folder_path": []string{""},
			"file_name":   []string{""},
		},
	}, {
		description: "folder_path, file_name provided",
		rawQuery:    "folder_path=foo/bar&file_name=baz.md",
		wantPageValues: url.Values{
			"file_path":   []string{""},
			"folder_path": []string{"foo/bar"},
			"file_name":   []string{"baz.md"},
		},
	}, {
		description: "file_path provided",
		rawQuery:    "file_path=foo/bar/baz.md",
		wantPageValues: url.Values{
			"file_path":   []string{"foo/bar/baz.md"},
			"folder_path": []string{""},
			"file_name":   []string{""},
		},
	}, {
		description: "valid session cookie",
		header: http.Header{
			"Cookie": []string{""},
		},
		wantPageValues: url.Values{
			"file_path":   []string{"aaa"},
			"folder_path": []string{"bbb"},
			"file_name":   []string{"ccc"},
		},
	}, func() TestTable {
		return TestTable{
			description: "",
		}
	}(), {
		description: "",
	}}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()
		})
	}
	// nothing
	// folder_path, file_name, file_path filled in
	// has valid session cookie
	// the header has a flash_session cookie but queryString was supplied, take it out and probe the database with it to make sure the session was deleted successfully
}

func Test_create_post(t *testing.T) {
	// all fields empty (both Content-Type, Accept headers, multisitemode subdirectory)
	// name validation error (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
	// post doesn't start with posts, notes, pages, templates or assets (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
	// post | note created too deep in  (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
	// {postID} | {noteID} automatically generated  (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
	// {category}/{postID} | {category}/{noteID} automatically generated  (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
	// post | note filename doesn't end in .md (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
	// page | template filename doesn't end in .html (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
	// asset filename doesn't have valid extension (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
	// parent folder doesn't exist (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
	// Using os.DirFS instead of TestFS causing ErrUnwritable (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
}

// extract into separate function that tests *all* paths for a specific error condition:
// - invalid JSON/url encoded values
// - invalid HTTP methods
// - nonexistent paths (404)
// - missing or invalid authentication token

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
			// take its place. Move the data and filemode over.
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
	// Otherwise, move the old file over to the newpath, replacing the current
	// file.
	delete(fsys.MapFS, oldpath)
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

var databaseCounter atomic.Int32

func newDatabase(t *testing.T) *sql.DB {
	count := databaseCounter.Add(1)
	// DSN must follow the format described in
	// https://github.com/mattn/go-sqlite3/issues/1036#issuecomment-1109264347.
	// SQLite author recommends vfs=memdb over :memory: or mode=memory
	// (https://sqlite.org/forum/forumpost/0359b21d172bd965).
	db, err := sql.Open("sqlite3", "file:/"+strconv.Itoa(int(count))+"?vfs=memdb&_foreign_keys=true")
	if err != nil {
		t.Fatal(testutil.Callers(), err)
	}
	automigrateCmd := &ddl.AutomigrateCmd{
		DB:             db,
		Dialect:        sq.DialectSQLite,
		DirFS:          schemaFS,
		Filenames:      []string{"schema.go"},
		DropObjects:    true,
		AcceptWarnings: true,
		Stderr:         io.Discard,
	}
	err = automigrateCmd.Run()
	if err != nil {
		t.Fatal(testutil.Callers(), err)
	}
	return db
}
