package nb5

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/template/parse"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/sq"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/exp/slog"
)

//go:embed html static
var embedFS embed.FS

var rootFS fs.FS = os.DirFS(".")

var bufPool = sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

// TODO: Use a gzipPool with compression level 4 instead of instantiating a new gzipWriter every time.
var gzipPool sync.Pool

// ErrUnwritable indicates that the filesystem cannot be written to.
//
// It is returned by the functions OpenWriter, RemoveAll and WalkDir to
// indicate that the underlying fs.FS does not support the method.
var ErrUnwritable = errors.New("filesystem cannot be written to")

// Notebrew represents a notebrew instance.
type Notebrew struct {
	// FS is the file system associated with the notebrew instance.
	FS fs.FS

	// DB is the database associated with the notebrew instance.
	DB *sql.DB

	// Dialect is dialect of the database. Only sqlite, postgres and mysql
	// databases are supported.
	Dialect string

	Scheme string // http:// | https://

	AdminDomain string // localhost:6444, example.com

	ContentDomain string // localhost:6444, example.com

	// NOTE: Document that AdminURL and ContentURL must either be prefixed with
	// https:// (if online) or http:// (if offline). And their http/https
	// status must be in sync, one cannot be http while the other is https.

	MultisiteMode string // subdomain | subdirectory

	// ErrorCode translates a database error into an dialect-specific error
	// code. If the error is not a database error or if no underlying
	// implementation is provided, ErrorCode returns an empty string.
	ErrorCode func(error) string

	CompressGeneratedHTML bool
}

// WriteFS is the interface implemented by a file system that can be written
// to.
type WriteFS interface {
	fs.FS

	// OpenWriter opens an io.WriteCloser that represents an instance of a file
	// that can be written to. If the file doesn't exist, it should be created.
	// If the file exists, its should be truncated.
	OpenWriter(name string) (io.WriteCloser, error)
}

// MkdirAllFS is the interface implemented by a file system that can create
// directories.
type MkdirAllFS interface {
	fs.FS

	// MkdirAll creates a directory named path, along with any necessary
	// parents, and returns nil, or else returns an error. The permission bits
	// perm (before umask) are used for all directories that MkdirAll creates.
	// If path is already a directory, MkdirAll does nothing and returns nil.
	MkdirAll(path string, perm fs.FileMode) error
}

// RemoveAllFS is the interface implemented by a file system that can remove
// files.
type RemoveAllFS interface {
	fs.FS

	// RemoveAll removes all files with prefix matching the path. If there are
	// no files matching the path, RemoveAll returns nil.
	RemoveAll(path string) error
}

type MoveFS interface {
	fs.FS

	Move(oldpath, newpath string) error
}

// OpenWriter opens an io.WriteCloser from the file system that represents an
// instance of a file that can be written to. If the file doesn't exist, it
// should be created.
func OpenWriter(fsys fs.FS, name string) (io.WriteCloser, error) {
	if fsys, ok := fsys.(WriteFS); ok {
		return fsys.OpenWriter(name)
	}
	return nil, ErrUnwritable
}

// WriteFile writes the data into a file in the file system.
func WriteFile(fsys fs.FS, name string, data []byte) error {
	writer, err := OpenWriter(fsys, name)
	if err != nil {
		return err
	}
	defer writer.Close()
	_, err = writer.Write(data)
	if err != nil {
		return err
	}
	return writer.Close()
}

// MkdirAll creates a directory named path, along with any necessary parents,
// and returns nil, or else returns an error. The permission bits perm (before
// umask) are used for all directories that MkdirAll creates. If path is
// already a directory, MkdirAll does nothing and returns nil.
func MkdirAll(fsys fs.FS, path string, perm fs.FileMode) error {
	if fsys, ok := fsys.(MkdirAllFS); ok {
		return fsys.MkdirAll(path, perm)
	}
	return ErrUnwritable
}

// RemoveAll removes all files from the file system with prefix matching the
// path. If there are no files matching the path, RemoveAll returns nil.
func RemoveAll(fsys fs.FS, path string) error {
	if fsys, ok := fsys.(RemoveAllFS); ok {
		return fsys.RemoveAll(path)
	}
	return ErrUnwritable
}

// TODO: Document this.
func Move(fsys fs.FS, oldpath, newpath string) error {
	if fsys, ok := fsys.(MoveFS); ok {
		return fsys.Move(oldpath, newpath)
	}
	return ErrUnwritable
}

func (nbrew *Notebrew) IsKeyViolation(err error) bool {
	if err == nil || nbrew.ErrorCode == nil {
		return false
	}
	errcode := nbrew.ErrorCode(err)
	switch nbrew.Dialect {
	case "sqlite":
		return errcode == "1555" || errcode == "2067" // SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE
	case "postgres":
		return errcode == "23505" // unique_violation
	case "mysql":
		return errcode == "1062" // ER_DUP_ENTRY
	case "sqlserver":
		return errcode == "2627"
	default:
		return false
	}
}

func (nbrew *Notebrew) IsForeignKeyViolation(err error) bool {
	if err == nil || nbrew.ErrorCode == nil {
		return false
	}
	errcode := nbrew.ErrorCode(err)
	switch nbrew.Dialect {
	case "sqlite":
		return errcode == "787" //  SQLITE_CONSTRAINT_FOREIGNKEY
	case "postgres":
		return errcode == "23503" // foreign_key_violation
	case "mysql":
		return errcode == "1216" // ER_NO_REFERENCED_ROW
	case "sqlserver":
		return errcode == "547"
	default:
		return false
	}
}

type dirFS string

func DirFS(dir string) fs.FS {
	return dirFS(dir)
}

func (dir dirFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.ToSlash(filepath.Join(string(dir), name))
	return os.Open(name)
}

func (dir dirFS) OpenWriter(name string) (io.WriteCloser, error) {
	var err error
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open_writer", Path: name, Err: fs.ErrInvalid}
	}
	tempDir := filepath.Join(os.TempDir(), "notebrew_temp_dir")
	err = os.MkdirAll(tempDir, 0755)
	if err != nil {
		return nil, err
	}
	f := &tempFileWrapper{
		destFilename: filepath.ToSlash(filepath.Join(string(dir), name)),
	}
	f.tempFile, err = os.CreateTemp(tempDir, "*")
	if err != nil {
		return nil, err
	}
	fileinfo, err := f.tempFile.Stat()
	if err != nil {
		return nil, err
	}
	f.tempFilename = filepath.ToSlash(filepath.Join(tempDir, fileinfo.Name()))
	return f, nil
}

func (dir dirFS) MkdirAll(path string, perm fs.FileMode) error {
	if !fs.ValidPath(path) {
		return &fs.PathError{Op: "mkdir_all", Path: path, Err: fs.ErrInvalid}
	}
	path = filepath.ToSlash(filepath.Join(string(dir), path))
	return os.MkdirAll(path, perm)
}

func (dir dirFS) RemoveAll(path string) error {
	if !fs.ValidPath(path) {
		return &fs.PathError{Op: "remove_all", Path: path, Err: fs.ErrInvalid}
	}
	path = filepath.ToSlash(filepath.Join(string(dir), path))
	return os.RemoveAll(path)
}

func (dir dirFS) Move(oldpath, newpath string) error {
	if !fs.ValidPath(oldpath) {
		return &fs.PathError{Op: "move", Path: oldpath, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newpath) {
		return &fs.PathError{Op: "move", Path: newpath, Err: fs.ErrInvalid}
	}
	oldpath = filepath.ToSlash(filepath.Join(string(dir), oldpath))
	newpath = filepath.ToSlash(filepath.Join(string(dir), newpath))
	oldFileInfo, err := os.Stat(oldpath)
	if err != nil {
		return err
	}
	newFileInfo, err := os.Stat(newpath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return os.Rename(oldpath, newpath)
		}
		return err
	}
	if !oldFileInfo.IsDir() && newFileInfo.IsDir() {
		if runtime.GOOS == "windows" {
			return exec.Command("move", oldpath, newpath).Run()
		}
		return exec.Command("mv", oldpath, newpath).Run()
	}
	return os.Rename(oldpath, newpath)
}

type tempFileWrapper struct {
	// tempFile is temporary file being written to.
	tempFile *os.File

	// tempFilename is the filename of the temporary file being written to.
	tempFilename string

	// destFilename is the destination filename that the temporary file should
	// be renamed to once writing is complete.
	destFilename string

	// writeFailed tracks if any of the writes to the tempFile failed.
	writeFailed bool
}

func (f *tempFileWrapper) Write(p []byte) (n int, err error) {
	n, err = f.tempFile.Write(p)
	if err != nil {
		f.writeFailed = true
	}
	return n, err
}

func (f *tempFileWrapper) Close() error {
	if f.tempFile == nil {
		return fmt.Errorf("already closed")
	}
	defer func() {
		f.tempFile = nil
		os.Remove(f.tempFilename)
	}()
	err := f.tempFile.Close()
	if err != nil {
		return err
	}
	if f.writeFailed {
		return nil
	}
	return os.Rename(f.tempFilename, f.destFilename)
}

func ParseTemplate(fsys fs.FS, funcMap template.FuncMap, text string) (*template.Template, error) {
	primaryTemplate, err := template.New("").Funcs(funcMap).Parse(text)
	if err != nil {
		return nil, err
	}
	primaryTemplates := primaryTemplate.Templates()
	sort.SliceStable(primaryTemplates, func(i, j int) bool {
		return primaryTemplates[j].Name() < primaryTemplates[i].Name()
	})
	for _, primaryTemplate := range primaryTemplates {
		name := primaryTemplate.Name()
		if strings.HasSuffix(name, ".html") {
			return nil, fmt.Errorf("define %q: defined template name cannot end in .html", name)
		}
	}
	var errmsgs []string
	var currentNode parse.Node
	var nodeStack []parse.Node
	var currentTemplate *template.Template
	templateStack := primaryTemplates
	finalTemplate := template.New("").Funcs(funcMap)
	visited := make(map[string]struct{})
	for len(templateStack) > 0 {
		currentTemplate, templateStack = templateStack[len(templateStack)-1], templateStack[:len(templateStack)-1]
		if currentTemplate.Tree == nil {
			continue
		}
		if cap(nodeStack) < len(currentTemplate.Tree.Root.Nodes) {
			nodeStack = make([]parse.Node, 0, len(currentTemplate.Tree.Root.Nodes))
		}
		for i := len(currentTemplate.Tree.Root.Nodes) - 1; i >= 0; i-- {
			nodeStack = append(nodeStack, currentTemplate.Tree.Root.Nodes[i])
		}
		for len(nodeStack) > 0 {
			currentNode, nodeStack = nodeStack[len(nodeStack)-1], nodeStack[:len(nodeStack)-1]
			switch node := currentNode.(type) {
			case *parse.ListNode:
				if node == nil {
					continue
				}
				for i := len(node.Nodes) - 1; i >= 0; i-- {
					nodeStack = append(nodeStack, node.Nodes[i])
				}
			case *parse.BranchNode:
				nodeStack = append(nodeStack, node.ElseList, node.List)
			case *parse.RangeNode:
				nodeStack = append(nodeStack, node.ElseList, node.List)
			case *parse.TemplateNode:
				if !strings.HasSuffix(node.Name, ".html") {
					continue
				}
				filename := node.Name
				if _, ok := visited[filename]; ok {
					continue
				}
				visited[filename] = struct{}{}
				file, err := fsys.Open(filename)
				if errors.Is(err, fs.ErrNotExist) {
					errmsgs = append(errmsgs, fmt.Sprintf("%s: %s does not exist", currentTemplate.Name(), node.String()))
					continue
				}
				if err != nil {
					return nil, err
				}
				fileinfo, err := file.Stat()
				if err != nil {
					return nil, err
				}
				var b strings.Builder
				b.Grow(int(fileinfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return nil, err
				}
				file.Close()
				text := b.String()
				newTemplate, err := template.New(filename).Funcs(funcMap).Parse(text)
				if err != nil {
					return nil, err
				}
				newTemplates := newTemplate.Templates()
				sort.SliceStable(newTemplates, func(i, j int) bool {
					return newTemplates[j].Name() < newTemplates[i].Name()
				})
				for _, newTemplate := range newTemplates {
					name := newTemplate.Name()
					if name != filename && strings.HasSuffix(name, ".html") {
						return nil, fmt.Errorf("define %q: defined template name cannot end in .html", name)
					}
					_, err = finalTemplate.AddParseTree(name, newTemplate.Tree)
					if err != nil {
						return nil, err
					}
					templateStack = append(templateStack, newTemplate)
				}
			}
		}
	}
	if len(errmsgs) > 0 {
		return nil, fmt.Errorf("invalid template references:\n" + strings.Join(errmsgs, "\n"))
	}
	for _, primaryTemplate := range primaryTemplates {
		_, err = finalTemplate.AddParseTree(primaryTemplate.Name(), primaryTemplate.Tree)
		if err != nil {
			return nil, err
		}
	}
	return finalTemplate, nil
}

func (nbrew *Notebrew) notFound(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// TODO: search the user's 400.html template and render that if found.
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	http.Error(w, "404 Not Found", http.StatusNotFound)
}

func readFile(fsys fs.FS, name string) (string, error) {
	file, err := fsys.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	var size int
	if info, err := file.Stat(); err == nil {
		size64 := info.Size()
		if int64(int(size64)) == size64 {
			size = int(size64)
		}
	}
	var b strings.Builder
	b.Grow(size)
	_, err = io.Copy(&b, file)
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

func validatePath(path string) error {
	name, names, _ := strings.Cut(strings.Trim(path, "/"), "/")
	for name != "" {
		err := validateName(name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		name, names, _ = strings.Cut(strings.Trim(names, "/"), "/")
	}
	return nil
}

func validateName(name string) error {
	i := strings.IndexAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if i > 0 {
		return fmt.Errorf("no uppercase letters [A-Z] allowed")
	}
	i = strings.IndexAny(name, " !\";#$%&'()*+,./:;<>=?[]\\^`{}|~")
	if i > 0 {
		char, _ := utf8.DecodeRuneInString(name[i:])
		return fmt.Errorf("forbidden character: %c", char)
	}
	switch name {
	case "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5",
		"com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
		"lpt6", "lpt7", "lpt8", "lpt9":
		return fmt.Errorf("forbidden name")
	}
	return nil
}

type contextKey struct{}

var loggerKey = &contextKey{}

func WithAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	logger, ok := ctx.Value(loggerKey).(*slog.Logger)
	if !ok {
		logger = slog.Default()
	}
	args := make([]any, len(attrs))
	for i, attr := range attrs {
		args[i] = attr
	}
	return context.WithValue(ctx, loggerKey, logger.With(args...))
}

func Log(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	logger, ok := ctx.Value(loggerKey).(*slog.Logger)
	if !ok {
		logger = slog.Default()
	}
	logger.LogAttrs(ctx, level, msg, attrs...)
}

func (nbrew *Notebrew) create(w http.ResponseWriter, r *http.Request, stack string, sitePrefix string) {
	r = r.WithContext(WithAttrs(
		r.Context(),
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("sitePrefix", sitePrefix),
	))
	if nbrew.DB == nil {
		nbrew.notFound(w, r)
		return
	}
	segment, _, _ := strings.Cut(strings.Trim(stack, "/"), "/")
	if segment != "" {
		nbrew.notFound(w, r)
		return
	}
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("400 Bad Request: %s", err), http.StatusBadRequest)
	}
	// cookie: authentication_token=xxx; session_token=xxx;
	type Data struct {
		FolderPath string     `json:"folder_path,omitempty"`
		FileName   string     `json:"file_name,omitempty"`
		FilePath   string     `json:"file_path,omitempty"`
		Errmsgs    url.Values `json:"errmsgs,omitempty"`
	}
	switch r.Method {
	case "GET":
		var data Data
		cookie, _ := r.Cookie("session_token")
		if cookie != nil {
			http.SetCookie(w, &http.Cookie{
				Path:     r.URL.Path,
				Name:     "session_token",
				Value:    "",
				Secure:   nbrew.Scheme == "https://",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   -1,
			})
			sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
			if err == nil {
				var sessionTokenHash [8 + blake2b.Size256]byte
				checksum := blake2b.Sum256([]byte(sessionToken[8:]))
				copy(sessionTokenHash[:8], sessionToken[:8])
				copy(sessionTokenHash[8:], checksum[:])
				createdAt := time.Unix(int64(binary.BigEndian.Uint64(sessionToken[:8])), 0)
				if time.Now().Sub(createdAt) <= 5*time.Minute {
					b, err := sq.FetchOneContext(r.Context(), nbrew.DB, sq.CustomQuery{
						Dialect: nbrew.Dialect,
						Format:  "SELECT {*} FROM sessions WHERE session_token_hash = {sessionTokenHash}",
						Values: []any{
							sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
						},
					}, func(row *sq.Row) []byte {
						return row.Bytes("data")
					})
					if err != nil {
						Log(r.Context(), slog.LevelError, err.Error())
					} else {
						err = json.Unmarshal(b, &data)
						if err != nil {
							Log(r.Context(), slog.LevelError, err.Error())
						}
					}
				}
				_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format:  "DELETE FROM sessions WHERE session_token_hash = {sessionTokenHash}",
					Values: []any{
						sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
					},
				})
				if err != nil {
					Log(r.Context(), slog.LevelError, err.Error())
				}
			}
		}
		data.FolderPath = strings.Trim(path.Clean(r.Form.Get("folder_path")), "/")
		err = validatePath(data.FolderPath)
		if err != nil {
			redirectURL := *r.URL
			redirectURL.RawQuery = ""
			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			return
		}
		tmpl, err := template.ParseFS(rootFS, "html/create.html")
		if err != nil {
			Log(r.Context(), slog.LevelError, err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		err = tmpl.Execute(buf, &data)
		if err != nil {
			Log(r.Context(), slog.LevelError, err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf.WriteTo(w)
	case "POST":
		type Response struct {
			Data       Data   `json:"data"`
			StatusCode int    `json:"status_code,omitempty"`
			Errmsg     string `json:"errmsg,omitempty"`
		}
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			isJSON := false
			for _, contentType := range r.Header["Accept"] {
				if contentType == "text/html" {
					break
				}
				if contentType == "application/json" {
					isJSON = true
					break
				}
			}
			if isJSON {
				b, err := json.Marshal(&response)
				if err != nil {
					Log(r.Context(), slog.LevelError, err.Error())
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
				w.Write(b)
				return
			}
			if len(response.Data.Errmsgs) == 0 {
				// TODO: means no errors, 302 redirect to resource.
				http.Redirect(w, r, "", http.StatusFound)
				return
			}
			if response.StatusCode != 0 {
				msg := fmt.Sprintf("%d %s: %s", response.StatusCode, http.StatusText(response.StatusCode), response.Errmsg)
				http.Error(w, msg, response.StatusCode)
				return
			}
			queryParams := make(url.Values)
			if r.Form.Has("folder_path") {
				queryParams.Set("folder_path", r.Form.Get("folder_path"))
			}
			redirectURL := *r.URL
			redirectURL.RawQuery = queryParams.Encode()
			var sessionToken [8 + 16]byte
			binary.BigEndian.PutUint64(sessionToken[:8], uint64(time.Now().Unix()))
			_, err = rand.Read(sessionToken[8:])
			if err != nil {
				Log(r.Context(), slog.LevelError, err.Error())
				http.Redirect(w, r, redirectURL.String(), http.StatusFound)
				return
			}
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256([]byte(sessionToken[8:]))
			copy(sessionTokenHash[:8], sessionToken[:8])
			copy(sessionTokenHash[8:], checksum[:])
			data, err := json.Marshal(&response.Data)
			if err != nil {
				Log(r.Context(), slog.LevelError, err.Error())
				http.Redirect(w, r, redirectURL.String(), http.StatusFound)
				return
			}
			_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format:  "INSERT INTO sessions (session_token_hash, payload) VALUES ({sessionTokenHash}, {payload})",
				Values: []any{
					sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
					sq.BytesParam("data", data),
				},
			})
			if err != nil {
				Log(r.Context(), slog.LevelError, err.Error())
				http.Redirect(w, r, redirectURL.String(), http.StatusFound)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Path:     r.URL.Path,
				Name:     "session_token",
				Value:    strings.TrimLeft(hex.EncodeToString(sessionToken[:]), "0"),
				Secure:   nbrew.Scheme == "https://",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		}
		var response Response
		response.Data.Errmsgs = make(url.Values)
		if r.Form.Has("folder_path") {
			response.Data.FolderPath = strings.Trim(path.Clean(r.Form.Get("folder_path")), "/")
			if response.Data.FolderPath == "" {
				response.StatusCode = http.StatusBadRequest
				response.Errmsg = "folder_path cannot be empty"
				writeResponse(w, r, response)
				return
			}
			err := validatePath(response.Data.FolderPath)
			if err != nil {
				response.StatusCode = http.StatusBadRequest
				response.Errmsg = fmt.Sprintf("%s: %v", response.Data.FolderPath, err)
				writeResponse(w, r, response)
				return
			}
			response.Data.FileName = strings.Trim(path.Clean(r.Form.Get("file_name")), "/")
			if response.Data.FileName == "" {
				response.Data.Errmsgs.Set("file_name", "cannot be empty")
				writeResponse(w, r, response)
				return
			}
			err = validateName(response.Data.FileName)
			if err != nil {
				response.Data.Errmsgs.Set("file_name", err.Error())
				writeResponse(w, r, response)
				return
			}
			response.Data.FilePath = path.Join(response.Data.FolderPath, response.Data.FileName)
		} else {
			response.Data.FilePath = strings.Trim(path.Clean(r.Form.Get("file_path")), "/")
			if response.Data.FilePath == "" {
				response.Data.Errmsgs.Set("file_path", "cannot be empty")
				writeResponse(w, r, response)
			}
			err = validatePath(response.Data.FilePath)
			if err != nil {
				response.Data.Errmsgs.Set("file_path", err.Error())
				writeResponse(w, r, response)
				return
			}
		}
		resource, _, _ := strings.Cut(response.Data.FilePath, "/")
		switch resource {
		case "posts":
		case "pages":
		case "notes":
		case "templates":
		case "assets":
		default:
			response.StatusCode = http.StatusBadRequest
			response.Errmsg = "path has to start with posts, pages, notes, templates or assets"
			writeResponse(w, r, response)
			return
		}
		// TODO: first make sure either folder_path or file_path starts with one of the valid prefixes.
		// TODO: then validate the path format - for posts and notes, must be {postID} or {category}/{postID}. {postID} can be empty, just generate one server side. For everything else, path must not be empty (after the prefix) and must have a valid extension (html, css, js, jpeg, jpg, gif, etc).

		// TODO: We need to validate "dir" and "filename" separately. Maybe
		// split it out into either ("dir" and "filename") or "filepath"? If
		// filepath is present, go with that. Otherwise use filepath :=
		// path.Join(dir, filename). There is a possibility that we get a bad
		// dir but the user can't do anything about it because they're not
		// savvy enough to edit the query string directly (we're not exposing
		// dir as a HTML form input field). Maybe if the GET request notices
		// dir is not valid, it scrubs the dir query param and the form falls
		// back to "filepath" mode? Yes, do that. That way, we don't ever need
		// to expose error sessions on the dir field because if present it's
		// always valid (otherwise it would be scrubbed).
		//
		// And if the POST side receives a bad dir, it joins the dir and the
		// filename and redirects to a form without "dir" (in "filepath" mode).

		// Step 1: Validate the name (starts with posts, notes, pages, templates or assets) (no forbidden characters)
		// Step 2: Validate the name format. (the right number of segments, the right file extensions) (if postID or noteID is missing, here is the step to automatically generate a new one)
		// Step 3: OpenWriter and close it immediately, then redirect the user to the corresponding resource path.
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (nbrew *Notebrew) newSession()
