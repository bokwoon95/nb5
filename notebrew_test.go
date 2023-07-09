package nb5

import (
	"io"
	"net/http"
	"testing"

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

// TODO: a mock file system that we can use in tests

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
