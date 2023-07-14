package nb5

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/exp/slog"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
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
		description   string           // test description
		seedQueries   []sq.CustomQuery // queries to seed database with
		header        http.Header      // request header
		rawQuery      string           // request GET query parameters
		wantItemprops url.Values       // values extracted from parsing response html microdata
	}

	var (
		sessionToken     = newToken(time.Now())
		sessionTokenHash = hashToken(sessionToken)
	)

	tests := []TestTable{{
		description: "basic",
		wantItemprops: url.Values{
			"file_path": []string{""},
		},
	}, {
		description: "folder_path and file_name provided",
		rawQuery:    "folder_path=foo/bar&file_name=baz.md",
		wantItemprops: url.Values{
			"folder_path": []string{"foo/bar"},
			"file_name":   []string{"baz.md"},
		},
	}, {
		description: "file_path provided",
		rawQuery:    "file_path=foo/bar/baz.md",
		wantItemprops: url.Values{
			"file_path": []string{"foo/bar/baz.md"},
		},
	}, {
		description: "session cookie",
		seedQueries: []sq.CustomQuery{{
			Format: "INSERT INTO sessions (session_token_hash, data) VALUES ({}, {})",
			Values: []any{
				sessionTokenHash,
				sq.JSONValue(map[string]any{
					"folder_path": "/FOO///BAR/",
					"folder_path_errors": []string{
						"cannot have leading slash",
						"cannot have trailing slash",
						"cannot have multiple slashes next to each other",
						"no uppercase letters [A-Z] allowed",
					},
					"file_name": "baz#$%&.md",
					"file_name_errors": []string{
						"forbidden characters: #$%&",
					},
				}),
			},
		}},
		header: http.Header{
			"Cookie": []string{"flash_session=" + strings.TrimLeft(hex.EncodeToString(sessionToken), "0")},
		},
		wantItemprops: url.Values{
			"folder_path": []string{"/FOO///BAR/"},
			"folder_path_errors": []string{
				"cannot have leading slash",
				"cannot have trailing slash",
				"cannot have multiple slashes next to each other",
				"no uppercase letters [A-Z] allowed",
			},
			"file_name": []string{"baz#$%&.md"},
			"file_name_errors": []string{
				"forbidden characters: #$%&",
			},
		},
	}}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()
			nbrew := &Notebrew{
				FS:            TestFS{fstest.MapFS{}},
				DB:            newDatabase(t),
				Dialect:       sq.DialectSQLite,
				Scheme:        "https://",
				AdminDomain:   "notebrew.com",
				ContentDomain: "notebrew.blog",
				MultisiteMode: "subdomain",
			}
			for _, seedQuery := range tt.seedQueries {
				_, err := sq.Exec(nbrew.DB, seedQuery)
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				AddSource: true,
			}))
			ctx := context.WithValue(context.Background(), loggerKey, logger)
			r, err := http.NewRequestWithContext(ctx, "GET", "", nil)
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r.Header = tt.header
			r.URL.RawQuery = tt.rawQuery
			w := httptest.NewRecorder()
			nbrew.create(w, r, "")
			response := w.Result()
			body := w.Body.String()
			if diff := testutil.Diff(response.StatusCode, http.StatusOK); diff != "" {
				t.Fatal(testutil.Callers(), diff, body)
			}
			gotItemprops, err := getItemprops(body)
			if err != nil {
				t.Fatal(testutil.Callers(), err, body)
			}
			if diff := testutil.Diff(gotItemprops, tt.wantItemprops); diff != "" {
				t.Error(testutil.Callers(), diff, body)
			}
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

var databaseCounter atomic.Int64

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

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func newToken(tm time.Time) []byte {
	token := make([]byte, 8+16)
	binary.BigEndian.PutUint64(token[:8], uint64(tm.Unix()))
	_, err := rand.Read(token[8:])
	if err != nil {
		panic(err)
	}
	return token[:]
}

func hashToken(token []byte) []byte {
	tokenHash := make([]byte, 8+blake2b.Size256)
	checksum := blake2b.Sum256([]byte(token[8:]))
	copy(tokenHash[:8], token[:8])
	copy(tokenHash[8:], checksum[:])
	return tokenHash
}

func getItemprops(body string) (url.Values, error) {
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	var node *html.Node
	nodes := []*html.Node{root}
	itemprops := make(url.Values)
	for len(nodes) > 0 {
		node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
		if node == nil {
			continue
		}
		hasItemprop := false
		var itempropKey, itempropValue string
		for _, attr := range node.Attr {
			if attr.Key == "itemprop" {
				hasItemprop = true
				itempropKey = attr.Val
				break
			}
		}
		if hasItemprop {
			attrs := make(map[string]string)
			for _, attr := range node.Attr {
				attrs[attr.Key] = attr.Val
			}
			// itemprop value reference:
			// https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/itemprop#values
			switch node.DataAtom {
			case atom.Meta:
				itempropValue = attrs["content"]
			case atom.Audio, atom.Embed, atom.Iframe, atom.Img, atom.Source, atom.Track, atom.Video:
				itempropValue = attrs["src"]
			case atom.A, atom.Area, atom.Link:
				itempropValue = attrs["href"]
			case atom.Object:
				itempropValue = attrs["data"]
			case atom.Data, atom.Meter, atom.Input:
				itempropValue = attrs["value"]
			default:
				var textContent strings.Builder
				var childNode *html.Node
				childNodes := []*html.Node{node.FirstChild}
				for len(childNodes) > 0 {
					childNode, childNodes = childNodes[len(childNodes)-1], childNodes[:len(childNodes)-1]
					if childNode == nil {
						continue
					}
					if childNode.Type == html.TextNode {
						textContent.WriteString(childNode.Data)
					}
					childNodes = append(childNodes, childNode.NextSibling, childNode.FirstChild)
				}
				itempropValue = strings.TrimSpace(textContent.String())
			}
			itemprops.Add(itempropKey, itempropValue)
		}
		nodes = append(nodes, node.NextSibling, node.FirstChild)
	}
	return itemprops, nil
}
