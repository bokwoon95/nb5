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
		description: "dot",
		path:        "foo/bar/./baz",
		wantErrs: []string{
			"name(s) cannot end in dot: .",
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

func Test_GET_create(t *testing.T) {
	type TestTable struct {
		description   string           // test description
		seedQueries   []sq.CustomQuery // SQL queries to seed database with
		header        http.Header      // request header
		rawQuery      string           // request GET query parameters
		wantItemprops url.Values       // itemprops extracted from parsing html response
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
		rawQuery:    "folder_path=foo/bar&file_name=baz.md&file_path=xxx",
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
			r, err := http.NewRequest("GET", "", nil)
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

func Test_POST_create(t *testing.T) {
	type Request struct {
		FilePath   string `json:"file_path,omitempty"`
		FolderPath string `json:"folder_path,omitempty"`
		FileName   string `json:"file_name,omitempty"`
	}
	type Response struct {
		ResourceAlreadyExists string   `json:"resource_already_exists,omitempty"`
		Errors                []string `json:"errors,omitempty"`
		FolderPath            string   `json:"folder_path,omitempty"`
		FolderPathErrors      []string `json:"folder_path_errors,omitempty"`
		FileName              string   `json:"file_name,omitempty"`
		FileNameErrors        []string `json:"file_name_errors,omitempty"`
		FilePath              string   `json:"file_path,omitempty"`
		FilePathErrors        []string `json:"file_path_errors,omitempty"`
	}
	type TestTable struct {
		description          string   // test description
		testFS               *TestFS  // Notebrew.FS
		multisiteMode        string   // Notebrew.MultisiteMode
		sitePrefix           string   // sitePrefix argument
		request              Request  // request payload
		response             Response // response payload
		wantLocation         string   // HTTP response Location header
		assertFilePathExists string   // file path that should be asserted for existence if response had no errors
	}

	tests := []TestTable{{
		description: "missing arguments",
		testFS:      &TestFS{fstest.MapFS{}},
		request:     Request{},
		response: Response{
			Errors: []string{"missing arguments"},
		},
	}, {
		description: "name validation error",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			FilePath:   "/FOO///BAR/baz#$%&.md",
			FolderPath: "/FOO///BAR/",
			FileName:   "baz#$%&.md",
		},
		response: Response{
			FilePath: "/FOO///BAR/baz#$%&.md",
			FilePathErrors: []string{
				"cannot have leading slash",
				"cannot have multiple slashes next to each other",
				"no uppercase letters [A-Z] allowed",
				"forbidden characters: #$%&",
			},
			FolderPath: "/FOO///BAR/",
			FolderPathErrors: []string{
				"cannot have leading slash",
				"cannot have trailing slash",
				"cannot have multiple slashes next to each other",
				"no uppercase letters [A-Z] allowed",
			},
			FileName: "baz#$%&.md",
			FileNameErrors: []string{
				"forbidden characters: #$%&",
			},
		},
	}, {
		description: "path doesn't start with posts, notes, pages, templates or assets",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			FilePath:   "foo/bar/baz.md",
			FolderPath: "foo/bar",
			FileName:   "baz.md",
		},
		response: Response{
			FilePath: "foo/bar/baz.md",
			FilePathErrors: []string{
				"path has to start with posts, notes, pages, templates or assets",
			},
			FolderPath: "foo/bar",
			FolderPathErrors: []string{
				"path has to start with posts, notes, pages, templates or assets",
			},
			FileName: "baz.md",
		},
	}, {
		description: "post path cannot be created",
		testFS: &TestFS{fstest.MapFS{
			"posts/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			FilePath:   "posts/foo/bar/baz.md",
			FolderPath: "posts/foo/bar",
			FileName:   "baz.md",
		},
		response: Response{
			FilePath: "posts/foo/bar/baz.md",
			FilePathErrors: []string{
				"cannot create a file here",
			},
			FolderPath: "posts/foo/bar",
			FolderPathErrors: []string{
				"cannot create a file here",
			},
			FileName: "baz.md",
		},
	}, {
		description: "note path cannot be created",
		testFS: &TestFS{fstest.MapFS{
			"notes/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			FilePath:   "notes/foo/bar/baz.md",
			FolderPath: "notes/foo/bar",
			FileName:   "baz.md",
		},
		response: Response{
			FilePath: "notes/foo/bar/baz.md",
			FilePathErrors: []string{
				"cannot create a file here",
			},
			FolderPath: "notes/foo/bar",
			FolderPathErrors: []string{
				"cannot create a file here",
			},
			FileName: "baz.md",
		},
	}, {
		description: "post filename doesnt end in .md",
		testFS: &TestFS{fstest.MapFS{
			"posts": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			FilePath:   "posts/baz.sh",
			FolderPath: "posts",
			FileName:   "baz.sh",
		},
		response: Response{
			FilePath: "posts/baz.sh",
			FilePathErrors: []string{
				"invalid extension (must end in .md)",
			},
			FolderPath: "posts",
			FileName:   "baz.sh",
			FileNameErrors: []string{
				"invalid extension (must end in .md)",
			},
		},
	}, {
		description: "note filename doesnt end in .md",
		testFS: &TestFS{fstest.MapFS{
			"notes": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			FilePath:   "notes/baz.sh",
			FolderPath: "notes",
			FileName:   "baz.sh",
		},
		response: Response{
			FilePath: "notes/baz.sh",
			FilePathErrors: []string{
				"invalid extension (must end in .md)",
			},
			FolderPath: "notes",
			FileName:   "baz.sh",
			FileNameErrors: []string{
				"invalid extension (must end in .md)",
			},
		},
	}, {
		description: "page filename doesnt end in .html",
		testFS: &TestFS{fstest.MapFS{
			"pages/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			FilePath:   "pages/foo/bar/baz.sh",
			FolderPath: "pages/foo/bar",
			FileName:   "baz.sh",
		},
		response: Response{
			FilePath: "pages/foo/bar/baz.sh",
			FilePathErrors: []string{
				"invalid extension (must end in .html)",
			},
			FolderPath: "pages/foo/bar",
			FileName:   "baz.sh",
			FileNameErrors: []string{
				"invalid extension (must end in .html)",
			},
		},
	}, {
		description: "template filename doesnt end in .html",
		testFS: &TestFS{fstest.MapFS{
			"templates/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			FilePath:   "templates/foo/bar/baz.sh",
			FolderPath: "templates/foo/bar",
			FileName:   "baz.sh",
		},
		response: Response{
			FilePath: "templates/foo/bar/baz.sh",
			FilePathErrors: []string{
				"invalid extension (must end in .html)",
			},
			FolderPath: "templates/foo/bar",
			FileName:   "baz.sh",
			FileNameErrors: []string{
				"invalid extension (must end in .html)",
			},
		},
	}, {
		description: "asset filename doesnt have valid extension",
		testFS: &TestFS{fstest.MapFS{
			"assets/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			FilePath:   "assets/foo/bar/baz.sh",
			FolderPath: "assets/foo/bar",
			FileName:   "baz.sh",
		},
		response: Response{
			FilePath: "assets/foo/bar/baz.sh",
			FilePathErrors: []string{
				"invalid extension (must be one of: .html, .css, .js, .md, .txt, .jpeg, .jpg, .png, .gif, .svg, .ico, .eof, .ttf, .woff, .woff2, .csv, .tsv, .json, .xml, .toml, .yaml, .yml)",
			},
			FolderPath: "assets/foo/bar",
			FileName:   "baz.sh",
			FileNameErrors: []string{
				"invalid extension (must be one of: .html, .css, .js, .md, .txt, .jpeg, .jpg, .png, .gif, .svg, .ico, .eof, .ttf, .woff, .woff2, .csv, .tsv, .json, .xml, .toml, .yaml, .yml)",
			},
		},
	}, {
		description: "parent folder doesnt exist",
		testFS:      &TestFS{fstest.MapFS{}},
		request: Request{
			FilePath:   "assets/foo/bar/baz.js",
			FolderPath: "assets/foo/bar",
			FileName:   "baz.js",
		},
		response: Response{
			FilePath: "assets/foo/bar/baz.js",
			FilePathErrors: []string{
				"parent folder does not exist",
			},
			FolderPath: "assets/foo/bar",
			FolderPathErrors: []string{
				"parent folder does not exist",
			},
			FileName: "baz.js",
		},
	}, {
		description: "file already exists",
		testFS: &TestFS{fstest.MapFS{
			"assets/foo/bar":        &fstest.MapFile{Mode: fs.ModeDir},
			"assets/foo/bar/baz.js": &fstest.MapFile{},
		}},
		request: Request{
			FilePath:   "assets/foo/bar/baz.js",
			FolderPath: "assets/foo/bar",
			FileName:   "baz.js",
		},
		response: Response{
			ResourceAlreadyExists: "/admin/assets/foo/bar/baz.js",
			FilePath:              "assets/foo/bar/baz.js",
			FolderPath:            "assets/foo/bar",
			FileName:              "baz.js",
		},
		assertFilePathExists: "assets/foo/bar/baz.js",
	}, {
		description: "file already exists (with sitePrefix)",
		testFS: &TestFS{fstest.MapFS{
			"~bokwoon/assets/foo/bar":        &fstest.MapFile{Mode: fs.ModeDir},
			"~bokwoon/assets/foo/bar/baz.js": &fstest.MapFile{},
		}},
		multisiteMode: "subdirectory",
		sitePrefix:    "~bokwoon",
		request: Request{
			FilePath:   "assets/foo/bar/baz.js",
			FolderPath: "assets/foo/bar",
			FileName:   "baz.js",
		},
		response: Response{
			ResourceAlreadyExists: "/~bokwoon/admin/assets/foo/bar/baz.js",
			FilePath:              "assets/foo/bar/baz.js",
			FolderPath:            "assets/foo/bar",
			FileName:              "baz.js",
		},
		assertFilePathExists: "~bokwoon/assets/foo/bar/baz.js",
	}, {
		description: "file created successfully",
		testFS: &TestFS{fstest.MapFS{
			"assets/foo/bar": &fstest.MapFile{Mode: fs.ModeDir},
		}},
		request: Request{
			FilePath:   "assets/foo/bar/baz.js",
			FolderPath: "assets/foo/bar",
			FileName:   "baz.js",
		},
		response: Response{
			FilePath:   "assets/foo/bar/baz.js",
			FolderPath: "assets/foo/bar",
			FileName:   "baz.js",
		},
		wantLocation:         "/admin/assets/foo/bar/baz.js",
		assertFilePathExists: "assets/foo/bar/baz.js",
	}}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()
			// === JSON, file_path === //
			nbrew := &Notebrew{
				FS:            tt.testFS.Clone(),
				DB:            newDatabase(t),
				Dialect:       sq.DialectSQLite,
				Scheme:        "https://",
				AdminDomain:   "notebrew.com",
				ContentDomain: "notebrew.blog",
				MultisiteMode: tt.multisiteMode,
			}
			b, err := json.Marshal(Request{
				FilePath: tt.request.FilePath,
			})
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
			nbrew.create(w, r, tt.sitePrefix)
			result := w.Result()
			if diff := testutil.Diff(result.StatusCode, http.StatusOK); diff != "" {
				t.Fatal(testutil.Callers(), diff, w.Body.String())
			}
			gotResponse := Response{}
			err = json.Unmarshal(w.Body.Bytes(), &gotResponse)
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			wantResponse := Response{
				ResourceAlreadyExists: tt.response.ResourceAlreadyExists,
				Errors:                tt.response.Errors,
				FilePath:              tt.response.FilePath,
				FilePathErrors:        tt.response.FilePathErrors,
			}
			if diff := testutil.Diff(gotResponse, wantResponse); diff != "" {
				t.Fatal(testutil.Callers(), diff)
			}
			if len(gotResponse.Errors) == 0 && len(gotResponse.FilePathErrors) == 0 && len(gotResponse.FolderPathErrors) == 0 && len(gotResponse.FileNameErrors) == 0 {
				_, err := fs.Stat(nbrew.FS, tt.assertFilePathExists)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf(testutil.Callers()+": %q: file was not created", tt.assertFilePathExists)
					} else {
						t.Fatal(testutil.Callers(), err)
					}
				}
			}
			// === JSON, folder_path + file_name === //
			nbrew = &Notebrew{
				FS:            tt.testFS.Clone(),
				DB:            newDatabase(t),
				Dialect:       sq.DialectSQLite,
				Scheme:        "https://",
				AdminDomain:   "notebrew.com",
				ContentDomain: "notebrew.blog",
				MultisiteMode: tt.multisiteMode,
			}
			b, err = json.Marshal(Request{
				FolderPath: tt.request.FolderPath,
				FileName:   tt.request.FileName,
			})
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r, err = http.NewRequest("POST", "", bytes.NewReader(b))
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r.Header = http.Header{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			}
			w = httptest.NewRecorder()
			nbrew.create(w, r, tt.sitePrefix)
			result = w.Result()
			if diff := testutil.Diff(result.StatusCode, http.StatusOK); diff != "" {
				t.Fatal(testutil.Callers(), diff, w.Body.String())
			}
			gotResponse = Response{}
			err = json.Unmarshal(w.Body.Bytes(), &gotResponse)
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			wantResponse = Response{
				ResourceAlreadyExists: tt.response.ResourceAlreadyExists,
				Errors:                tt.response.Errors,
				FolderPath:            tt.response.FolderPath,
				FolderPathErrors:      tt.response.FolderPathErrors,
				FileName:              tt.response.FileName,
				FileNameErrors:        tt.response.FileNameErrors,
			}
			if diff := testutil.Diff(gotResponse, wantResponse); diff != "" {
				t.Error(testutil.Callers(), diff)
			}
			if len(gotResponse.Errors) == 0 && len(gotResponse.FilePathErrors) == 0 && len(gotResponse.FolderPathErrors) == 0 && len(gotResponse.FileNameErrors) == 0 {
				_, err := fs.Stat(nbrew.FS, tt.assertFilePathExists)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf(testutil.Callers()+": %q: file was not created", tt.assertFilePathExists)
					} else {
						t.Fatal(testutil.Callers(), err)
					}
				}
			}
			// === HTML form, file_path === //
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
				"file_path": []string{tt.request.FilePath},
			}
			r, err = http.NewRequest("POST", "", strings.NewReader(values.Encode()))
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r.Header = http.Header{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			}
			w = httptest.NewRecorder()
			nbrew.create(w, r, tt.sitePrefix)
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
				r, err := http.NewRequest("GET", "", nil)
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
				var gotResponse Response
				ok, err := nbrew.getSession(r, "flash_session", &gotResponse)
				if err != nil {
					t.Fatal(testutil.Callers(), err)
				}
				if !ok {
					t.Fatal(testutil.Callers(), "no session set")
				}
				wantResponse := Response{
					ResourceAlreadyExists: tt.response.ResourceAlreadyExists,
					Errors:                tt.response.Errors,
					FilePath:              tt.response.FilePath,
					FilePathErrors:        tt.response.FilePathErrors,
				}
				if diff := testutil.Diff(gotResponse, wantResponse); diff != "" {
					t.Fatal(testutil.Callers(), diff)
				}
			}
			if len(gotResponse.Errors) == 0 && len(gotResponse.FilePathErrors) == 0 && len(gotResponse.FolderPathErrors) == 0 && len(gotResponse.FileNameErrors) == 0 {
				_, err := fs.Stat(nbrew.FS, tt.assertFilePathExists)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf(testutil.Callers()+": %q: file was not created", tt.assertFilePathExists)
					} else {
						t.Fatal(testutil.Callers(), err)
					}
				}
			}
			// === HTML form, folder_path + file_name === //
			nbrew = &Notebrew{
				FS:            tt.testFS.Clone(),
				DB:            newDatabase(t),
				Dialect:       sq.DialectSQLite,
				Scheme:        "https://",
				AdminDomain:   "notebrew.com",
				ContentDomain: "notebrew.blog",
				MultisiteMode: tt.multisiteMode,
			}
			values = url.Values{
				"folder_path": []string{tt.request.FolderPath},
				"file_name":   []string{tt.request.FileName},
			}
			r, err = http.NewRequest("POST", "", strings.NewReader(values.Encode()))
			if err != nil {
				t.Fatal(testutil.Callers(), err)
			}
			r.Header = http.Header{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			}
			w = httptest.NewRecorder()
			nbrew.create(w, r, tt.sitePrefix)
			result = w.Result()
			if diff := testutil.Diff(result.StatusCode, http.StatusFound); diff != "" {
				t.Fatal(testutil.Callers(), diff, w.Body.String())
			}
			gotLocation = result.Header.Get("location")
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
				wantResponse = Response{
					ResourceAlreadyExists: tt.response.ResourceAlreadyExists,
					Errors:                tt.response.Errors,
					FolderPath:            tt.response.FolderPath,
					FolderPathErrors:      tt.response.FolderPathErrors,
					FileName:              tt.response.FileName,
					FileNameErrors:        tt.response.FileNameErrors,
				}
				if diff := testutil.Diff(gotResponse, wantResponse); diff != "" {
					t.Fatal(testutil.Callers(), diff)
				}
			}
			if len(gotResponse.Errors) == 0 && len(gotResponse.FilePathErrors) == 0 && len(gotResponse.FolderPathErrors) == 0 && len(gotResponse.FileNameErrors) == 0 {
				_, err := fs.Stat(nbrew.FS, tt.assertFilePathExists)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf(testutil.Callers()+": %q: file was not created", tt.assertFilePathExists)
					} else {
						t.Fatal(testutil.Callers(), err)
					}
				}
			}
		})
	}
}

func Test_POST_create_autogenerateID(t *testing.T) {
	// {postID} | {noteID} automatically generated  (both Content-Type, Accept headers, multisitemode subdirectory) (both file_path and folder_path + file_name)
}

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

func (fsys *TestFS) OpenWriter(name string) (io.WriteCloser, error) {
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
