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
	"mime"
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

	"github.com/bokwoon95/sq"
	"github.com/oklog/ulid/v2"
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

func (nbrew *Notebrew) notFound(w http.ResponseWriter, r *http.Request, sitePrefix string) {
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

func validatePath(path string, allowExtension bool) (errs []string) {
	if path == "" {
		errs = append(errs, "cannot be empty")
	}
	if strings.HasPrefix(path, "/") {
		errs = append(errs, "cannot have leading slash")
	}
	if strings.HasSuffix(path, "/") {
		errs = append(errs, "cannot have trailing slash")
	}
	if strings.Contains(path, "//") {
		errs = append(errs, "cannot have multiple slashes next to each other")
	}
	dotCount := strings.Count(path, ".")
	if allowExtension && dotCount > 1 {
		errs = append(errs, "too many periods (only one allowed in the extension)")
	} else if dotCount > 0 {
		errs = append(errs, "no periods allowed")
	}
	i := strings.IndexAny(path, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if i > 0 {
		errs = append(errs, "no uppercase letters [A-Z] allowed")
	}
	var b strings.Builder
	str := path
	const forbiddenChars = " !\";#$%&'()*+,:;<>=?[]\\^`{}|~"
	for i := strings.IndexAny(str, forbiddenChars); i >= 0; i = strings.IndexAny(str, forbiddenChars) {
		b.WriteByte(str[i])
		str = str[i+1:]
	}
	if b.Len() > 0 {
		errs = append(errs, "forbidden characters: "+b.String())
	}
	var names []string
	str = path
	for name, str, _ := strings.Cut(str, "/"); name != ""; name, str, _ = strings.Cut(str, "/") {
		switch strings.ToLower(name) {
		// Windows forbidden file names.
		case "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5",
			"com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
			"lpt6", "lpt7", "lpt8", "lpt9":
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		errs = append(errs, "forbidden names: "+strings.Join(names, ", "))
	}
	return errs
}

func validateName(name string) (errs []string) {
	const forbiddenChars = " !\";#$%&'()*+,./:;<>=?[]\\^`{}|~"
	if name == "" {
		errs = append(errs, "cannot be empty")
	}
	dotCount := strings.Count(name, ".")
	if dotCount > 1 {
		errs = append(errs, "too many periods (only one allowed in the extension)")
	}
	i := strings.IndexAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if i > 0 {
		errs = append(errs, "no uppercase letters [A-Z] allowed")
	}
	var b strings.Builder
	tempName := name
	for i := strings.IndexAny(tempName, forbiddenChars); i >= 0; i = strings.IndexAny(tempName, forbiddenChars) {
		b.WriteByte(tempName[i])
		tempName = tempName[i+1:]
	}
	if b.Len() > 0 {
		errs = append(errs, "forbidden characters: "+b.String())
	}
	switch strings.ToLower(name) {
	// Windows forbidden file names.
	case "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5",
		"com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
		"lpt6", "lpt7", "lpt8", "lpt9":
		errs = append(errs, "forbidden name: "+name)
	}
	return errs
}

type contextKey struct{}

var loggerKey = &contextKey{}

func (nbrew *Notebrew) create(w http.ResponseWriter, r *http.Request, stack string, sitePrefix string) {
	type Data struct {
		FolderPath string `json:"folder_path,omitempty"`

		FileName string `json:"file_name,omitempty"`

		FilePath string `json:"file_path,omitempty"`

		Errors url.Values `json:"errors,omitempty"`
	}

	logger, ok := r.Context().Value(loggerKey).(*slog.Logger)
	if !ok {
		logger = slog.Default()
	}
	logger = logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("sitePrefix", sitePrefix),
	)
	r = r.WithContext(context.WithValue(r.Context(), loggerKey, logger))
	if nbrew.DB == nil {
		nbrew.notFound(w, r, sitePrefix)
		return
	}

	segment, _, _ := strings.Cut(strings.Trim(stack, "/"), "/")
	if segment != "" {
		nbrew.notFound(w, r, sitePrefix)
		return
	}

	switch r.Method {
	case "GET":
		var data Data
		var sessionTokenHash []byte
		cookie, _ := r.Cookie("flash_session")
		if cookie != nil {
			http.SetCookie(w, &http.Cookie{
				Path:     r.URL.Path,
				Name:     "flash_session",
				Value:    "",
				Secure:   nbrew.Scheme == "https://",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   -1,
			})
			sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
			if err == nil {
				sessionTokenHash = make([]byte, 8+blake2b.Size256)
				checksum := blake2b.Sum256([]byte(sessionToken[8:]))
				copy(sessionTokenHash[:8], sessionToken[:8])
				copy(sessionTokenHash[8:], checksum[:])
			}
		}
		if sessionTokenHash != nil {
			defer func() {
				_, err := sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format:  "DELETE FROM sessions WHERE session_token_hash = {sessionTokenHash}",
					Values: []any{
						sq.BytesParam("sessionTokenHash", sessionTokenHash),
					},
				})
				if err != nil {
					logger.Error(err.Error())
				}
			}()
		}
		err := r.ParseForm()
		if err != nil {
			http.Error(w, fmt.Sprintf("400 Bad Request: %s", err), http.StatusBadRequest)
			return
		}
		if len(r.Form) > 0 {
			data.FolderPath = r.Form.Get("folder_path")
			data.FileName = r.Form.Get("file_name")
			data.FilePath = r.Form.Get("file_path")
		} else if sessionTokenHash != nil {
			createdAt := time.Unix(int64(binary.BigEndian.Uint64(sessionTokenHash[:8])), 0)
			if time.Now().Sub(createdAt) <= 5*time.Minute {
				data, err = sq.FetchOneContext(r.Context(), nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format:  "SELECT {*} FROM sessions WHERE session_token_hash = {sessionTokenHash}",
					Values: []any{
						sq.BytesParam("sessionTokenHash", sessionTokenHash),
					},
				}, func(row *sq.Row) Data {
					row.JSON(&data, "data")
					return data
				})
				if err != nil {
					logger.Error(err.Error())
				}
			}
		}
		tmpl, err := template.ParseFS(rootFS, "html/create.html")
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		err = tmpl.Execute(buf, &data)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf.WriteTo(w)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, data Data) {
			accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
			if accept == "application/json" {
				b, err := json.Marshal(&data)
				if err != nil {
					logger.Error(err.Error())
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
				w.Write(b)
				return
			}
			if len(data.Errors) == 0 {
				filePath := data.FilePath
				if filePath == "" {
					filePath = path.Join(data.FolderPath, data.FileName)
				}
				var redirectURL string
				if nbrew.MultisiteMode == "subdirectory" {
					redirectURL = "/" + path.Join(sitePrefix, "admin", filePath)
				} else {
					redirectURL = "/" + path.Join("admin", filePath)
				}
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			if len(data.Errors[""]) > 0 {
				http.Error(w, strings.Join(data.Errors[""], "\n"), http.StatusBadRequest)
				return
			}
			var sessionToken [8 + 16]byte
			binary.BigEndian.PutUint64(sessionToken[:8], uint64(time.Now().Unix()))
			_, err := rand.Read(sessionToken[8:])
			if err != nil {
				logger.Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256([]byte(sessionToken[8:]))
			copy(sessionTokenHash[:8], sessionToken[:8])
			copy(sessionTokenHash[8:], checksum[:])
			dataBytes, err := json.Marshal(&data)
			if err != nil {
				logger.Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format:  "INSERT INTO sessions (session_token_hash, payload) VALUES ({sessionTokenHash}, {payload})",
				Values: []any{
					sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
					sq.BytesParam("data", dataBytes),
				},
			})
			if err != nil {
				logger.Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Path:     r.URL.Path,
				Name:     "flash_session",
				Value:    strings.TrimLeft(hex.EncodeToString(sessionToken[:]), "0"),
				Secure:   nbrew.Scheme == "https://",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			r.URL.RawQuery = ""
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		}
		var data Data
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType == "application/json" {
			err := json.NewDecoder(r.Body).Decode(&data)
			if err != nil {
				var syntaxErr *json.SyntaxError
				if errors.As(err, &syntaxErr) {
					http.Error(w, "400 Bad Request: invalid JSON", http.StatusBadRequest)
					return
				}
				logger.Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
		} else {
			err := r.ParseForm()
			if err != nil {
				http.Error(w, fmt.Sprintf("400 Bad Request: %s", err), http.StatusBadRequest)
				return
			}
			data.FolderPath = r.Form.Get("folder_path")
			data.FileName = r.Form.Get("file_name")
			data.FilePath = r.Form.Get("file_path")
		}

		// filePathProvided tracks whether the user provided file_path or
		// folder_path and file_name.
		var filePathProvided bool

		// filePath is the path of the file to create, obtained from either
		// file_path or path.Join(folder_path, file_name).
		var filePath string

		// ext is the extension of the file.
		var ext string

		data.Errors = make(url.Values)

		if data.FilePath == "" && data.FolderPath == "" && data.FileName == "" {
			data.Errors.Add("", "either file_path or folder_path and file_name must be provided")
		} else if data.FilePath != "" {
			filePathProvided = true
			filePath = data.FilePath
			ext = filepath.Ext(data.FilePath)
			data.FolderPath = ""
			data.FileName = ""
			errs := validatePath(strings.TrimSuffix(data.FilePath, ext), true)
			if len(errs) > 0 {
				data.Errors["file_path"] = errs
			}
		} else {
			filePathProvided = false
			filePath = path.Join(data.FolderPath, data.FileName)
			ext = filepath.Ext(data.FileName)
			data.FilePath = ""
			errs := validatePath(data.FolderPath, false)
			if len(errs) > 0 {
				data.Errors["folder_path"] = errs
			}
			errs = validateName(strings.TrimSuffix(data.FileName, ext))
			if len(errs) > 0 {
				data.Errors["file_name"] = errs
			}
		}
		if len(data.Errors) > 0 {
			writeResponse(w, r, data)
			return
		}

		head, tail, _ := strings.Cut(filePath, "/")
		switch head {
		case "posts", "notes":
			if strings.Count(tail, "/") > 1 {
				const errmsg = "cannot create a file here"
				if filePathProvided {
					data.Errors.Add("file_path", errmsg)
				} else {
					data.Errors.Add("folder_path", errmsg)
				}
				writeResponse(w, r, data)
				return
			}
			if tail == "" {
				filePath = path.Join(filePath, strings.ToLower(ulid.Make().String())+".md")
				ext = ".md"
			} else if !strings.Contains(tail, "/") && !strings.HasSuffix(tail, ".md") {
				_, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, "posts", tail))
				if err == nil {
					filePath = path.Join(filePath, strings.ToLower(ulid.Make().String())+".md")
					ext = ".md"
				}
			}
			if ext != ".md" {
				const errmsg = "invalid extension (must end in .md)"
				if filePathProvided {
					data.Errors.Add("file_path", errmsg)
				} else {
					data.Errors.Add("file_name", errmsg)
				}
				writeResponse(w, r, data)
				return
			}
		case "pages", "templates":
			if ext != ".html" {
				const errmsg = "invalid extension (must end in .html)"
				if filePathProvided {
					data.Errors.Add("file_path", errmsg)
				} else {
					data.Errors.Add("file_name", errmsg)
				}
				writeResponse(w, r, data)
				return
			}
		case "assets":
			allowedExts := []string{
				".html", ".css", ".js", ".md", ".txt",
				".jpeg", ".jpg", ".png", ".gif", ".svg", ".ico",
				".eof", ".ttf", ".woff", ".woff2",
				".csv", ".tsv", ".json", ".xml", ".toml", ".yaml", ".yml",
			}
			match := false
			for _, allowedExt := range allowedExts {
				if ext == allowedExt {
					match = true
					break
				}
			}
			if !match {
				errmsg := fmt.Sprintf("invalid extension (must end in one of: %s)", strings.Join(allowedExts, ", "))
				if filePathProvided {
					data.Errors.Add("file_path", errmsg)
				} else {
					data.Errors.Add("file_name", errmsg)
				}
				writeResponse(w, r, data)
				return
			}
		default:
			const errmsg = "path has to start with posts, notes, pages, templates or assets"
			if filePathProvided {
				data.Errors.Add("file_path", errmsg)
			} else {
				data.Errors.Add("folder_path", errmsg)
			}
			writeResponse(w, r, data)
			return
		}

		_, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, filepath.Dir(filePath)))
		if err != nil {
			errmsg := err.Error()
			if errors.Is(err, fs.ErrNotExist) {
				errmsg = "parent folder does not exist"
			}
			if filePathProvided {
				data.Errors.Add("file_path", errmsg)
			} else {
				data.Errors.Add("folder_path", errmsg)
			}
			writeResponse(w, r, data)
			return
		}

		writer, err := OpenWriter(nbrew.FS, filePath)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		err = writer.Close()
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		writeResponse(w, r, data)
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (nbrew *Notebrew) newSession() {
}
