package nb5

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{AddSource: true})))
}

func Test_validateName(t *testing.T) {
	type TestTable struct {
		description string
		name        string
		wantErrs    []string
	}

	tests := []TestTable{{
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
		description: "ends in dot",
		name:        "foo.",
		wantErrs: []string{
			"cannot end in dot",
		},
	}, {
		description: "dot",
		name:        ".",
		wantErrs: []string{
			"cannot end in dot",
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
			gotErrs := validateName(nil, tt.name)
			if diff := testutil.Diff(gotErrs, tt.wantErrs); diff != "" {
				t.Error(testutil.Callers(), diff)
			}
		})
	}
}

func Test_GET_createFile(t *testing.T) {
	type Session struct {
		sessionTokenHash []byte
		data             []byte
	}
	type TestTable struct {
		description      string         // test description
		databaseSessions []Session      // sessions that the database starts off with
		rawQuery         string         // request GET query parameters
		cookies          []*http.Cookie // request cookies
		wantItemprops    url.Values     // itemprops extracted from parsing html response
	}

	var (
		sessionToken     = newToken(time.Now())
		sessionTokenHash = hashToken(sessionToken)
	)

	tests := []TestTable{{
		description: "basic",
		wantItemprops: url.Values{
			"parent_folder": []string{""},
			"name":          []string{""},
		},
	}, {
		description: "parent_folder and name provided",
		rawQuery:    "parent_folder=/foo/bar/&name=baz.md",
		wantItemprops: url.Values{
			"parent_folder": []string{"foo/bar"},
			"name":          []string{"baz.md"},
		},
	}, {
		description: "input errors",
		databaseSessions: []Session{{
			sessionTokenHash: sessionTokenHash,
			data: jsonify(map[string]any{
				"parent_folder": "",
				"parent_folder_errors": []string{
					"parent folder has to start with posts, notes, pages, templates or assets",
				},
				"name": "bAz#$%&.md",
				"name_errors": []string{
					"no uppercase letters [A-Z] allowed",
					"forbidden characters: #$%&",
				},
			}),
		}},
		cookies: []*http.Cookie{{
			Name:  "flash_session",
			Value: strings.TrimLeft(hex.EncodeToString(sessionToken), "0"),
		}},
		wantItemprops: url.Values{
			"parent_folder": []string{""},
			"parent_folder_errors": []string{
				"parent folder has to start with posts, notes, pages, templates or assets",
			},
			"name": []string{"bAz#$%&.md"},
			"name_errors": []string{
				"no uppercase letters [A-Z] allowed",
				"forbidden characters: #$%&",
			},
		},
	}, {
		description: "file already exists",
		databaseSessions: []Session{{
			sessionTokenHash: sessionTokenHash,
			data: jsonify(map[string]any{
				"parent_folder":  "assets/foo/bar",
				"name":           "baz.js",
				"already_exists": "/admin/assets/foo/bar/baz.js",
			}),
		}},
		cookies: []*http.Cookie{{
			Name:  "flash_session",
			Value: strings.TrimLeft(hex.EncodeToString(sessionToken), "0"),
		}},
		wantItemprops: url.Values{
			"parent_folder":  []string{"assets/foo/bar"},
			"name":           []string{"baz.js"},
			"already_exists": []string{"/admin/assets/foo/bar/baz.js"},
		},
	}, {
		description: "error",
		databaseSessions: []Session{{
			sessionTokenHash: sessionTokenHash,
			data: jsonify(map[string]any{
				"error": "lorem ipsum dolor sit amet",
			}),
		}},
		cookies: []*http.Cookie{{
			Name:  "flash_session",
			Value: strings.TrimLeft(hex.EncodeToString(sessionToken), "0"),
		}},
		wantItemprops: url.Values{
			"error":         []string{"lorem ipsum dolor sit amet"},
			"parent_folder": []string{""},
			"name":          []string{""},
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
			for _, session := range tt.databaseSessions {
				_, err := sq.Exec(nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format:  "INSERT INTO sessions (session_token_hash, data) VALUES ({}, {})",
					Values:  []any{session.sessionTokenHash, session.data},
				})
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
			}
			r, err := http.NewRequest("GET", "", nil)
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			if len(tt.cookies) > 0 {
				var b strings.Builder
				for _, cookie := range tt.cookies {
					if b.Len() > 0 {
						b.WriteString("; ")
					}
					b.WriteString(cookie.String())
				}
				r.Header.Set("Cookie", b.String())
			}
			r.URL.RawQuery = tt.rawQuery
			w := httptest.NewRecorder()
			nbrew.createFile(w, r, "")
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
			cookie, _ := r.Cookie("flash_session")
			if cookie != nil {
				sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
				var sessionTokenHash [8 + blake2b.Size256]byte
				checksum := blake2b.Sum256([]byte(sessionToken[8:]))
				copy(sessionTokenHash[:8], sessionToken[:8])
				copy(sessionTokenHash[8:], checksum[:])
				exists, err := sq.FetchExists(nbrew.DB, sq.CustomQuery{
					Format: "SELECT 1 FROM sessions WHERE session_token_hash = {}",
					Values: []any{sessionTokenHash[:]},
				})
				if exists {
					t.Errorf(testutil.Callers() + " session not cleared")
				}
			}
		})
	}
}

func Test_POST_createFile(t *testing.T) {
	type Request struct {
		ParentFolder string `json:"parent_folder,omitempty"`
		Name         string `json:"name,omitempty"`
	}
	type Response struct {
		ParentFolder       string   `json:"parent_folder,omitempty"`
		ParentFolderErrors []string `json:"parent_folder_errors,omitempty"`
		Name               string   `json:"name,omitempty"`
		NameErrors         []string `json:"name_errors,omitempty"`
		Error              []string `json:"error,omitempty"`
		AlreadyExists      string   `json:"already_exists,omitempty"`
	}
	type TestTable struct {
		description      string   // test description
		testFS           *TestFS  // Notebrew.FS
		multisiteMode    string   // Notebrew.MultisiteMode
		sitePrefix       string   // sitePrefix argument
		request          Request  // request payload
		wantResponse     Response // response payload
		wantLocation     string   // HTTP response Location header
		assertFileExists string   // file that should be asserted for existence if response has no errors
	}

	tests := []TestTable{{
		description: "empty",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			ParentFolder: "",
			Name:         "",
		},
		wantResponse: Response{
			ParentFolder: "",
			ParentFolderErrors: []string{
				"parent folder has to start with posts, notes, pages, templates or assets",
			},
			Name: "",
			NameErrors: []string{
				"cannot be empty",
			},
		},
	}, {
		description: "posts errors",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			ParentFolder: "/posts/foo/bar/",
			Name:         "bAz#$%&.exe",
		},
		wantResponse: Response{
			ParentFolder: "posts/foo/bar",
			ParentFolderErrors: []string{
				"not allowed to use this parent folder",
			},
			Name: "bAz#$%&.exe",
			NameErrors: []string{
				"no uppercase letters [A-Z] allowed",
				"forbidden characters: #$%&",
				"invalid extension (must end in .md)",
			},
		},
	}, {
		description: "pages errors",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			ParentFolder: "/pages/foo/bar/",
			Name:         "bAz#$%&.exe",
		},
		wantResponse: Response{
			ParentFolder: "pages/foo/bar",
			Name:         "bAz#$%&.exe",
			NameErrors: []string{
				"no uppercase letters [A-Z] allowed",
				"forbidden characters: #$%&",
				"invalid extension (must end in .html)",
			},
		},
	}, {
		description: "assets errors",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			ParentFolder: "/assets/foo/bar/",
			Name:         "bAz#$%&.exe",
		},
		wantResponse: Response{
			ParentFolder:       "assets/foo/bar",
			ParentFolderErrors: []string{},
			Name:               "bAz#$%&.exe",
			NameErrors: []string{
				"no uppercase letters [A-Z] allowed",
				"forbidden characters: #$%&",
				"invalid extension (must be one of: .html, .css, .js, .md, .txt, .jpeg, .jpg, .png, .gif, .svg, .ico, .eof, .ttf, .woff, .woff2, .csv, .tsv, .json, .xml, .toml, .yaml, .yml)",
			},
		},
	}, {
		description: "parent folder doesnt exist",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz.js",
		},
		wantResponse: Response{
			ParentFolder: "assets/foo/bar",
			ParentFolderErrors: []string{
				"parent folder does not exist",
			},
			Name: "baz.js",
		},
	}, {
		description: "file already exists",
		testFS: &TestFS{fstest.MapFS{
			"assets/foo/bar":        &fstest.MapFile{Mode: fs.ModeDir},
			"assets/foo/bar/baz.js": &fstest.MapFile{},
		}},
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz.js",
		},
		wantResponse: Response{
			ParentFolder:  "assets/foo/bar",
			Name:          "baz.js",
			AlreadyExists: "/admin/assets/foo/bar/baz.js",
		},
		assertFileExists: "assets/foo/bar/baz.js",
	}, {
		description: "file already exists (with sitePrefix)",
		testFS: &TestFS{fstest.MapFS{
			"~bokwoon/assets/foo/bar":        &fstest.MapFile{Mode: fs.ModeDir},
			"~bokwoon/assets/foo/bar/baz.js": &fstest.MapFile{},
		}},
		multisiteMode: "subdirectory",
		sitePrefix:    "~bokwoon",
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz.js",
		},
		wantResponse: Response{
			ParentFolder:  "assets/foo/bar",
			Name:          "baz.js",
			AlreadyExists: "/~bokwoon/admin/assets/foo/bar/baz.js",
		},
		assertFileExists: "~bokwoon/assets/foo/bar/baz.js",
	}, {
		description: "file created successfully",
		testFS: &TestFS{fstest.MapFS{
			"assets/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz.js",
		},
		wantResponse: Response{
			ParentFolder: "assets/foo/bar",
			Name:         "baz.js",
		},
		wantLocation:     "/admin/assets/foo/bar/baz.js",
		assertFileExists: "assets/foo/bar/baz.js",
	}, {
		description: "file created successfully (with sitePrefix)",
		testFS: &TestFS{fstest.MapFS{
			"~bokwoon/assets/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		multisiteMode: "subdirectory",
		sitePrefix:    "~bokwoon",
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz.js",
		},
		wantResponse: Response{
			ParentFolder: "assets/foo/bar",
			Name:         "baz.js",
		},
		wantLocation:     "/~bokwoon/admin/assets/foo/bar/baz.js",
		assertFileExists: "~bokwoon/assets/foo/bar/baz.js",
	}}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()
			// === JSON === //
			nbrew := &Notebrew{
				FS:            tt.testFS.Clone(),
				DB:            newDatabase(t),
				Dialect:       sq.DialectSQLite,
				Scheme:        "https://",
				AdminDomain:   "notebrew.com",
				ContentDomain: "notebrew.blog",
				MultisiteMode: tt.multisiteMode,
			}
			b, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r, err := http.NewRequest("POST", "", bytes.NewReader(b))
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r.Header = http.Header{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			}
			w := httptest.NewRecorder()
			nbrew.createFile(w, r, tt.sitePrefix)
			result := w.Result()
			if diff := testutil.Diff(result.StatusCode, http.StatusOK); diff != "" {
				t.Fatal(testutil.Callers(), diff, w.Body.String())
			}
			gotResponse := Response{}
			err = json.Unmarshal(w.Body.Bytes(), &gotResponse)
			if err != nil {
				t.Fatal(testutil.Callers(), err, w.Body.String())
			}
			if diff := testutil.Diff(gotResponse, tt.wantResponse); diff != "" {
				t.Fatal(testutil.Callers(), diff)
			}
			if len(gotResponse.Error) == 0 && len(gotResponse.ParentFolderErrors) == 0 && len(gotResponse.NameErrors) == 0 {
				fileInfo, err := fs.Stat(nbrew.FS, tt.assertFileExists)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf(testutil.Callers()+": %q: file was not created", tt.assertFileExists)
					} else {
						t.Fatal(testutil.Callers(), err)
					}
				}
				if fileInfo.IsDir() {
					t.Fatal(testutil.Callers(), "file was created but is a directory")
				}
			}
			// === HTML form === //
			nbrew = &Notebrew{
				FS:            tt.testFS.Clone(),
				DB:            newDatabase(t),
				Dialect:       sq.DialectSQLite,
				Scheme:        "https://",
				AdminDomain:   "notebrew.com",
				ContentDomain: "notebrew.blog",
				MultisiteMode: tt.multisiteMode,
			}
			values := url.Values{
				"parent_folder": []string{tt.request.ParentFolder},
				"name":          []string{tt.request.Name},
			}
			r, err = http.NewRequest("POST", "", strings.NewReader(values.Encode()))
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r.Header = http.Header{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			}
			w = httptest.NewRecorder()
			nbrew.createFile(w, r, tt.sitePrefix)
			result = w.Result()
			if diff := testutil.Diff(result.StatusCode, http.StatusFound); diff != "" {
				t.Fatal(testutil.Callers(), diff, w.Body.String())
			}
			gotLocation := result.Header.Get("location")
			if gotLocation == "/" {
				// http.Redirect converts empty strings to a "/" Location
				// header, so we treat "/" redirects as if it were an empty
				// string.
				gotLocation = ""
			}
			if diff := testutil.Diff(gotLocation, tt.wantLocation); diff != "" {
				t.Fatal(testutil.Callers(), diff, w.Body.String())
			}
			if gotLocation == "" {
				r, err = http.NewRequest("GET", "", nil)
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
				var b strings.Builder
				for _, cookie := range result.Cookies() {
					if b.Len() > 0 {
						b.WriteString("; ")
					}
					c := &http.Cookie{
						Name:  cookie.Name,
						Value: cookie.Value,
					}
					b.WriteString(c.String())
				}
				r.Header.Set("Cookie", b.String())
				gotResponse = Response{}
				ok, err := nbrew.getSession(r, "flash_session", &gotResponse)
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
				if !ok {
					t.Fatal(testutil.Callers(), "no session set")
				}
				if diff := testutil.Diff(gotResponse, tt.wantResponse); diff != "" {
					t.Fatal(testutil.Callers(), diff)
				}
			}
			if len(gotResponse.Error) == 0 && len(gotResponse.ParentFolderErrors) == 0 && len(gotResponse.NameErrors) == 0 {
				fileInfo, err := fs.Stat(nbrew.FS, tt.assertFileExists)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf(testutil.Callers()+": %q: file was not created", tt.assertFileExists)
					} else {
						t.Fatal(testutil.Callers(), err)
					}
				}
				if fileInfo.IsDir() {
					t.Fatal(testutil.Callers(), "file was created but is a directory")
				}
			}
		})
	}
}

func Test_GET_createFolder(t *testing.T) {
	type Session struct {
		sessionTokenHash []byte
		data             []byte
	}
	type TestTable struct {
		description      string         // test description
		databaseSessions []Session      // sessions that the database starts off with
		rawQuery         string         // request GET query parameters
		cookies          []*http.Cookie // request cookies
		wantItemprops    url.Values     // itemprops extracted from parsing html response
	}

	var (
		sessionToken     = newToken(time.Now())
		sessionTokenHash = hashToken(sessionToken)
	)

	tests := []TestTable{{
		description: "basic",
		wantItemprops: url.Values{
			"parent_folder": []string{""},
			"name":          []string{""},
		},
	}, {
		description: "parent_folder and name provided",
		rawQuery:    "parent_folder=/foo/bar/&name=baz.md",
		wantItemprops: url.Values{
			"parent_folder": []string{"foo/bar"},
			"name":          []string{"baz.md"},
		},
	}, {
		description: "input errors",
		databaseSessions: []Session{{
			sessionTokenHash: sessionTokenHash,
			data: jsonify(map[string]any{
				"parent_folder": "",
				"parent_folder_errors": []string{
					"parent folder has to start with posts, notes, pages, templates or assets",
				},
				"name": "bAz#$%&",
				"name_errors": []string{
					"no uppercase letters [A-Z] allowed",
					"forbidden characters: #$%&",
				},
			}),
		}},
		cookies: []*http.Cookie{{
			Name:  "flash_session",
			Value: strings.TrimLeft(hex.EncodeToString(sessionToken), "0"),
		}},
		wantItemprops: url.Values{
			"parent_folder": []string{""},
			"parent_folder_errors": []string{
				"parent folder has to start with posts, notes, pages, templates or assets",
			},
			"name": []string{"bAz#$%&"},
			"name_errors": []string{
				"no uppercase letters [A-Z] allowed",
				"forbidden characters: #$%&",
			},
		},
	}, {
		description: "folder already exists",
		databaseSessions: []Session{{
			sessionTokenHash: sessionTokenHash,
			data: jsonify(map[string]any{
				"parent_folder":  "assets/foo/bar",
				"name":           "baz",
				"already_exists": "/admin/assets/foo/bar/baz",
			}),
		}},
		cookies: []*http.Cookie{{
			Name:  "flash_session",
			Value: strings.TrimLeft(hex.EncodeToString(sessionToken), "0"),
		}},
		wantItemprops: url.Values{
			"parent_folder":  []string{"assets/foo/bar"},
			"name":           []string{"baz"},
			"already_exists": []string{"/admin/assets/foo/bar/baz"},
		},
	}, {
		description: "error",
		databaseSessions: []Session{{
			sessionTokenHash: sessionTokenHash,
			data: jsonify(map[string]any{
				"error": "lorem ipsum dolor sit amet",
			}),
		}},
		cookies: []*http.Cookie{{
			Name:  "flash_session",
			Value: strings.TrimLeft(hex.EncodeToString(sessionToken), "0"),
		}},
		wantItemprops: url.Values{
			"error":         []string{"lorem ipsum dolor sit amet"},
			"parent_folder": []string{""},
			"name":          []string{""},
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
			for _, session := range tt.databaseSessions {
				_, err := sq.Exec(nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format:  "INSERT INTO sessions (session_token_hash, data) VALUES ({}, {})",
					Values:  []any{session.sessionTokenHash, session.data},
				})
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
			}
			r, err := http.NewRequest("GET", "", nil)
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			if len(tt.cookies) > 0 {
				var b strings.Builder
				for _, cookie := range tt.cookies {
					if b.Len() > 0 {
						b.WriteString("; ")
					}
					b.WriteString(cookie.String())
				}
				r.Header.Set("Cookie", b.String())
			}
			r.URL.RawQuery = tt.rawQuery
			w := httptest.NewRecorder()
			nbrew.createFolder(w, r, "")
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
			cookie, _ := r.Cookie("flash_session")
			if cookie != nil {
				sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
				var sessionTokenHash [8 + blake2b.Size256]byte
				checksum := blake2b.Sum256([]byte(sessionToken[8:]))
				copy(sessionTokenHash[:8], sessionToken[:8])
				copy(sessionTokenHash[8:], checksum[:])
				exists, err := sq.FetchExists(nbrew.DB, sq.CustomQuery{
					Format: "SELECT 1 FROM sessions WHERE session_token_hash = {}",
					Values: []any{sessionTokenHash[:]},
				})
				if exists {
					t.Errorf(testutil.Callers() + " session not cleared")
				}
			}
		})
	}
}

func Test_POST_createFolder(t *testing.T) {
	type Request struct {
		ParentFolder string `json:"parent_folder,omitempty"`
		Name         string `json:"name,omitempty"`
	}
	type Response struct {
		ParentFolder       string   `json:"parent_folder,omitempty"`
		ParentFolderErrors []string `json:"parent_folder_errors,omitempty"`
		Name               string   `json:"name,omitempty"`
		NameErrors         []string `json:"name_errors,omitempty"`
		Error              []string `json:"error,omitempty"`
		AlreadyExists      string   `json:"already_exists,omitempty"`
	}
	type TestTable struct {
		description        string   // test description
		testFS             *TestFS  // Notebrew.FS
		multisiteMode      string   // Notebrew.MultisiteMode
		sitePrefix         string   // sitePrefix argument
		request            Request  // request payload
		wantResponse       Response // response payload
		wantLocation       string   // HTTP response Location header
		assertFolderExists string   // folder that should be asserted for existence if response has no errors
	}

	tests := []TestTable{{
		description: "empty",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			ParentFolder: "",
			Name:         "",
		},
		wantResponse: Response{
			ParentFolder: "",
			ParentFolderErrors: []string{
				"parent folder has to start with posts, notes, pages, templates or assets",
			},
			Name: "",
			NameErrors: []string{
				"cannot be empty",
			},
		},
	}, {
		description: "posts errors",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			ParentFolder: "/posts/foo/bar/",
			Name:         "bAz#$%&",
		},
		wantResponse: Response{
			ParentFolder: "posts/foo/bar",
			ParentFolderErrors: []string{
				"not allowed to use this parent folder",
			},
			Name: "bAz#$%&",
			NameErrors: []string{
				"no uppercase letters [A-Z] allowed",
				"forbidden characters: #$%&",
			},
		},
	}, {
		description: "parent folder doesnt exist",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz",
		},
		wantResponse: Response{
			ParentFolder: "assets/foo/bar",
			ParentFolderErrors: []string{
				"parent folder does not exist",
			},
			Name: "baz",
		},
	}, {
		description: "folder already exists",
		testFS: &TestFS{fstest.MapFS{
			"assets/foo/bar/baz": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz",
		},
		wantResponse: Response{
			ParentFolder:  "assets/foo/bar",
			Name:          "baz",
			AlreadyExists: "/admin/assets/foo/bar/baz",
		},
		assertFolderExists: "assets/foo/bar/baz",
	}, {
		description: "file with same name already exists",
		testFS: &TestFS{fstest.MapFS{
			"assets/foo/bar/baz": &fstest.MapFile{},
		}},
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz",
		},
		wantResponse: Response{
			ParentFolder: "assets/foo/bar",
			Name:         "baz",
			NameErrors: []string{
				"file with the same name already exists",
			},
		},
	}, {
		description: "folder already exists (with sitePrefix)",
		testFS: &TestFS{fstest.MapFS{
			"~bokwoon/assets/foo/bar/baz": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		multisiteMode: "subdirectory",
		sitePrefix:    "~bokwoon",
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz",
		},
		wantResponse: Response{
			ParentFolder:  "assets/foo/bar",
			Name:          "baz",
			AlreadyExists: "/~bokwoon/admin/assets/foo/bar/baz",
		},
		assertFolderExists: "~bokwoon/assets/foo/bar/baz",
	}, {
		description: "folder created successfully",
		testFS: &TestFS{fstest.MapFS{
			"assets/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz",
		},
		wantResponse: Response{
			ParentFolder: "assets/foo/bar",
			Name:         "baz",
		},
		wantLocation:       "/admin/assets/foo/bar/baz/",
		assertFolderExists: "assets/foo/bar/baz",
	}, {
		description: "folder created successfully (with sitePrefix)",
		testFS: &TestFS{fstest.MapFS{
			"~bokwoon/assets/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		multisiteMode: "subdirectory",
		sitePrefix:    "~bokwoon",
		request: Request{
			ParentFolder: "assets/foo/bar",
			Name:         "baz",
		},
		wantResponse: Response{
			ParentFolder: "assets/foo/bar",
			Name:         "baz",
		},
		wantLocation:       "/~bokwoon/admin/assets/foo/bar/baz/",
		assertFolderExists: "~bokwoon/assets/foo/bar/baz",
	}}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()
			// === JSON === //
			nbrew := &Notebrew{
				FS:            tt.testFS.Clone(),
				DB:            newDatabase(t),
				Dialect:       sq.DialectSQLite,
				Scheme:        "https://",
				AdminDomain:   "notebrew.com",
				ContentDomain: "notebrew.blog",
				MultisiteMode: tt.multisiteMode,
			}
			b, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r, err := http.NewRequest("POST", "", bytes.NewReader(b))
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r.Header = http.Header{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			}
			w := httptest.NewRecorder()
			nbrew.createFolder(w, r, tt.sitePrefix)
			result := w.Result()
			if diff := testutil.Diff(result.StatusCode, http.StatusOK); diff != "" {
				t.Fatal(testutil.Callers(), diff, w.Body.String())
			}
			gotResponse := Response{}
			err = json.Unmarshal(w.Body.Bytes(), &gotResponse)
			if err != nil {
				t.Fatal(testutil.Callers(), err, w.Body.String())
			}
			if diff := testutil.Diff(gotResponse, tt.wantResponse); diff != "" {
				t.Fatal(testutil.Callers(), diff)
			}
			if len(gotResponse.Error) == 0 && len(gotResponse.ParentFolderErrors) == 0 && len(gotResponse.NameErrors) == 0 {
				fileInfo, err := fs.Stat(nbrew.FS, tt.assertFolderExists)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf(testutil.Callers()+": %q: file was not created", tt.assertFolderExists)
					} else {
						t.Fatal(testutil.Callers(), err)
					}
				}
				if !fileInfo.IsDir() {
					t.Fatal(testutil.Callers(), "file was created but is not a directory")
				}
			}
			// === HTML form === //
			nbrew = &Notebrew{
				FS:            tt.testFS.Clone(),
				DB:            newDatabase(t),
				Dialect:       sq.DialectSQLite,
				Scheme:        "https://",
				AdminDomain:   "notebrew.com",
				ContentDomain: "notebrew.blog",
				MultisiteMode: tt.multisiteMode,
			}
			values := url.Values{
				"parent_folder": []string{tt.request.ParentFolder},
				"name":          []string{tt.request.Name},
			}
			r, err = http.NewRequest("POST", "", strings.NewReader(values.Encode()))
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r.Header = http.Header{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			}
			w = httptest.NewRecorder()
			nbrew.createFolder(w, r, tt.sitePrefix)
			result = w.Result()
			if diff := testutil.Diff(result.StatusCode, http.StatusFound); diff != "" {
				t.Fatal(testutil.Callers(), diff, w.Body.String())
			}
			gotLocation := result.Header.Get("location")
			if gotLocation == "/" {
				// http.Redirect converts empty strings to a "/" Location
				// header, so we treat "/" redirects as if it were an empty
				// string.
				gotLocation = ""
			}
			if diff := testutil.Diff(gotLocation, tt.wantLocation); diff != "" {
				t.Fatal(testutil.Callers(), diff, w.Body.String())
			}
			if gotLocation == "" {
				r, err = http.NewRequest("GET", "", nil)
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
				var b strings.Builder
				for _, cookie := range result.Cookies() {
					if b.Len() > 0 {
						b.WriteString("; ")
					}
					c := &http.Cookie{
						Name:  cookie.Name,
						Value: cookie.Value,
					}
					b.WriteString(c.String())
				}
				r.Header.Set("Cookie", b.String())
				gotResponse = Response{}
				ok, err := nbrew.getSession(r, "flash_session", &gotResponse)
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
				if !ok {
					t.Fatal(testutil.Callers(), "no session set")
				}
				if diff := testutil.Diff(gotResponse, tt.wantResponse); diff != "" {
					t.Fatal(testutil.Callers(), diff)
				}
			}
			if len(gotResponse.Error) == 0 && len(gotResponse.ParentFolderErrors) == 0 && len(gotResponse.NameErrors) == 0 {
				fileInfo, err := fs.Stat(nbrew.FS, tt.assertFolderExists)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf(testutil.Callers()+": %q: file was not created", tt.assertFolderExists)
					} else {
						t.Fatal(testutil.Callers(), err)
					}
				}
				if !fileInfo.IsDir() {
					t.Fatal(testutil.Callers(), "file was created but is not a directory")
				}
			}
		})
	}
}

func Test_GET_rename(t *testing.T) {
	type Session struct {
		sessionTokenHash []byte
		data             []byte
	}
	type TestTable struct {
		description      string         // test description
		databaseSessions []Session      // sessions that the database starts off with
		rawQuery         string         // request GET query parameters
		cookies          []*http.Cookie // request cookies
		wantItemprops    url.Values     // itemprops extracted from parsing html response
	}
}

// {postID} | {noteID} automatically generated  (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and parent_folder_path + file_name)
// extract into separate function that tests *all* paths for a specific error condition:
// - invalid JSON/url encoded values
// - invalid HTTP methods
// - nonexistent paths (404)
// - missing or invalid authentication token
// - using os.DirFS instead of TestFS causing ErrUnwritable

type TestFS struct {
	fstest.MapFS
}

func (fsys *TestFS) Clone() *TestFS {
	mapFS := make(fstest.MapFS)
	for name, file := range fsys.MapFS {
		mapFS[name] = &fstest.MapFile{
			Data:    file.Data,
			Mode:    file.Mode,
			ModTime: file.ModTime,
			Sys:     file.Sys,
		}
	}
	return &TestFS{mapFS}
}

func (fsys *TestFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
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

func (fsys *TestFS) MkdirAll(path string, perm fs.FileMode) error {
	if !fs.ValidPath(path) {
		return &fs.PathError{Op: "mkdirall", Path: path, Err: fs.ErrInvalid}
	}
	fsys.MapFS[path] = &fstest.MapFile{
		Mode:    fs.ModeDir,
		ModTime: time.Now(),
	}
	return nil
}

func (fsys *TestFS) RemoveAll(path string) error {
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

func (fsys *TestFS) Move(oldpath, newpath string) error {
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

// getItemprops trawls through a HTML body and extracts all itemprop names and
// values. The name of an itemprop is whatever is in the itemprop attribute,
// while the value of an itemprop is either the content attribute, src
// attribute, href attribute, data attribute, value attribute or textContent of
// an element (as defined in
// https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/itemprop#values).
// An itemprop name may appear multiple times, in which case its value is
// aggregated into a list.
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
		var itempropName sql.NullString
		for _, attr := range node.Attr {
			if attr.Key == "itemprop" {
				itempropName = sql.NullString{
					String: attr.Val,
					Valid:  true,
				}
				break
			}
		}
		if itempropName.Valid {
			attrs := make(map[string]string)
			for _, attr := range node.Attr {
				attrs[attr.Key] = attr.Val
			}
			// itemprop value reference:
			// https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/itemprop#values
			switch node.DataAtom {
			case atom.Meta:
				itemprops.Add(itempropName.String, attrs["content"])
			case atom.Audio, atom.Embed, atom.Iframe, atom.Img, atom.Source, atom.Track, atom.Video:
				itemprops.Add(itempropName.String, attrs["src"])
			case atom.A, atom.Area, atom.Link:
				itemprops.Add(itempropName.String, attrs["href"])
			case atom.Object:
				itemprops.Add(itempropName.String, attrs["data"])
			case atom.Data, atom.Meter, atom.Input:
				itemprops.Add(itempropName.String, attrs["value"])
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
				itemprops.Add(itempropName.String, strings.TrimSpace(textContent.String()))
			}
		}
		nodes = append(nodes, node.NextSibling, node.FirstChild)
	}
	return itemprops, nil
}

func jsonify(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
