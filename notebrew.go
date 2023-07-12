package nb5

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
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

func validateName(name string) (errmsgs []string) {
	if name == "" {
		return []string{"cannot be empty"}
	}
	if strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		errmsgs = append(errmsgs, "no uppercase letters [A-Z] allowed")
	}
	const forbiddenChars = " !\";#$%&'()*+,/:;<>=?[]\\^`{}|~"
	var b strings.Builder
	str := name
	written := make(map[byte]struct{})
	for i := strings.IndexAny(str, forbiddenChars); i >= 0; i = strings.IndexAny(str, forbiddenChars) {
		char := str[i]
		if _, ok := written[char]; !ok {
			written[char] = struct{}{}
			b.WriteByte(char)
		}
		str = str[i+1:]
	}
	if b.Len() > 0 {
		errmsgs = append(errmsgs, "forbidden characters: "+b.String())
	}
	switch strings.ToLower(name) {
	// Windows forbidden file names.
	case "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5",
		"com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
		"lpt6", "lpt7", "lpt8", "lpt9":
		errmsgs = append(errmsgs, "forbidden name")
	}
	return errmsgs
}

func validatePath(path string) (errmsgs []string) {
	if path == "" {
		return []string{"cannot be empty"}
	}
	if strings.HasPrefix(path, "/") {
		errmsgs = append(errmsgs, "cannot have leading slash")
	}
	if strings.HasSuffix(path, "/") {
		errmsgs = append(errmsgs, "cannot have trailing slash")
	}
	if strings.Contains(path, "//") {
		errmsgs = append(errmsgs, "cannot have multiple slashes next to each other")
	}
	if strings.ContainsAny(path, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		errmsgs = append(errmsgs, "no uppercase letters [A-Z] allowed")
	}
	const forbiddenChars = " !\";#$%&'()*+,:;<>=?[]\\^`{}|~"
	var b strings.Builder
	str := path
	written := make(map[byte]struct{})
	for i := strings.IndexAny(str, forbiddenChars); i >= 0; i = strings.IndexAny(str, forbiddenChars) {
		char := str[i]
		if _, ok := written[char]; !ok {
			written[char] = struct{}{}
			b.WriteByte(char)
		}
		str = str[i+1:]
	}
	if b.Len() > 0 {
		errmsgs = append(errmsgs, "forbidden characters: "+b.String())
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
		errmsgs = append(errmsgs, "forbidden name(s): "+strings.Join(names, ", "))
	}
	return errmsgs
}

type contextKey struct{}

var loggerKey = &contextKey{}

func (nbrew *Notebrew) create(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	type Data struct {
		Errors []string `json:"errors,omitempty"`

		FolderPath       string   `json:"folder_path,omitempty"`
		FolderPathErrors []string `json:"folder_path_errors,omitempty"`

		FileName       string   `json:"file_name,omitempty"`
		FileNameErrors []string `json:"file_name_errors,omitempty"`

		FilePath       string   `json:"file_path,omitempty"`
		FilePathErrors []string `json:"file_path_errors,omitempty"`
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

	switch r.Method {
	case "GET":
		err := r.ParseForm()
		if err != nil {
			http.Error(w, fmt.Sprintf("400 Bad Request: %s", err), http.StatusBadRequest)
			return
		}
		var data Data
		if len(r.Form) > 0 {
			data.FolderPath = r.Form.Get("folder_path")
			data.FileName = r.Form.Get("file_name")
			data.FilePath = r.Form.Get("file_path")
		} else {
			_, err := nbrew.getSession(w, r, "flash_session", &data)
			if err != nil {
				logger.Error(err.Error())
			}
		}
		nbrew.clearSession(w, r, "flash_session")
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
			if len(data.Errors) > 0 ||
				len(data.FilePathErrors) > 0 ||
				len(data.FolderPathErrors) > 0 ||
				len(data.FileNameErrors) > 0 {
				err := nbrew.setSession(w, r, data, &http.Cookie{
					Path:     r.URL.Path,
					Name:     "flash_session",
					Secure:   nbrew.Scheme == "https://",
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
				if err != nil {
					logger.Error(err.Error())
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
				r.URL.RawQuery = ""
				http.Redirect(w, r, r.URL.String(), http.StatusFound)
				return
			}
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

		if data.FilePath == "" && data.FolderPath == "" && data.FileName == "" {
			data.Errors = []string{"no values provided"}
			writeResponse(w, r, data)
			return
		}

		// filePathProvidedByUser tracks whether the user provided file_path or
		// folder_path and file_name.
		var filePathProvidedByUser bool

		// filePath is the path of the file to create, obtained from either
		// file_path or path.Join(folder_path, file_name).
		var filePath string

		if data.FilePath != "" {
			filePathProvidedByUser = true
			filePath = data.FilePath
			data.FolderPath = ""
			data.FileName = ""
			data.FilePathErrors = validatePath(data.FilePath)
			if len(data.FilePathErrors) > 0 {
				writeResponse(w, r, data)
				return
			}
		} else {
			filePathProvidedByUser = false
			filePath = path.Join(data.FolderPath, data.FileName)
			data.FilePath = ""
			data.FolderPathErrors = validatePath(data.FolderPath)
			data.FileNameErrors = validateName(data.FileName)
			if len(data.FolderPathErrors) > 0 || len(data.FileNameErrors) > 0 {
				writeResponse(w, r, data)
				return
			}
		}

		head, tail, _ := strings.Cut(filePath, "/")
		switch head {
		case "posts", "notes":
			slashCount := strings.Count(tail, "/")
			if slashCount > 1 {
				const errmsg = "cannot create a file here"
				if filePathProvidedByUser {
					data.FilePathErrors = append(data.FilePathErrors, errmsg)
				} else {
					data.FolderPathErrors = append(data.FolderPathErrors, errmsg)
				}
				writeResponse(w, r, data)
				return
			}
			if tail == "" || (!strings.Contains(tail, "/") && filepath.Ext(tail) == "") {
				filePath += "/" + strings.ToLower(ulid.Make().String()) + ".md"
			}
			if filepath.Ext(filePath) != ".md" {
				const errmsg = "invalid extension (must end in .md)"
				if filePathProvidedByUser {
					data.FilePathErrors = append(data.FilePathErrors, errmsg)
				} else {
					data.FileNameErrors = append(data.FileNameErrors, errmsg)
				}
				writeResponse(w, r, data)
				return
			}
		case "pages", "templates":
			if filepath.Ext(filePath) != ".html" {
				const errmsg = "invalid extension (must end in .html)"
				if filePathProvidedByUser {
					data.FilePathErrors = append(data.FilePathErrors, errmsg)
				} else {
					data.FileNameErrors = append(data.FileNameErrors, errmsg)
				}
				writeResponse(w, r, data)
				return
			}
		case "assets":
			ext := filepath.Ext(filePath)
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
				if filePathProvidedByUser {
					data.FilePathErrors = append(data.FilePathErrors, errmsg)
				} else {
					data.FileNameErrors = append(data.FileNameErrors, errmsg)
				}
				writeResponse(w, r, data)
				return
			}
		default:
			const errmsg = "path has to start with posts, notes, pages, templates or assets"
			if filePathProvidedByUser {
				data.FilePathErrors = append(data.FilePathErrors, errmsg)
			} else {
				data.FolderPathErrors = append(data.FolderPathErrors, errmsg)
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
			if filePathProvidedByUser {
				data.FilePathErrors = append(data.FilePathErrors, errmsg)
			} else {
				data.FolderPathErrors = append(data.FolderPathErrors, errmsg)
			}
			writeResponse(w, r, data)
			return
		}

		writer, err := OpenWriter(nbrew.FS, filePath)
		if err != nil {
			if errors.Is(err, ErrUnwritable) {
				data.Errors = append(data.Errors, err.Error())
				writeResponse(w, r, data)
				return
			}
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

func (nbrew *Notebrew) setSession(w http.ResponseWriter, r *http.Request, v any, cookie *http.Cookie) error {
	dataBytes, ok := v.([]byte)
	if !ok {
		var err error
		dataBytes, err = json.Marshal(v)
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
	}
	if nbrew.DB == nil {
		cookie.Value = base64.URLEncoding.EncodeToString(dataBytes)
	} else {
		var sessionToken [8 + 16]byte
		binary.BigEndian.PutUint64(sessionToken[:8], uint64(time.Now().Unix()))
		_, err := rand.Read(sessionToken[8:])
		if err != nil {
			return fmt.Errorf("reading rand: %w", err)
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256([]byte(sessionToken[8:]))
		copy(sessionTokenHash[:8], sessionToken[:8])
		copy(sessionTokenHash[8:], checksum[:])
		_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format:  "INSERT INTO sessions (session_token_hash, payload) VALUES ({sessionTokenHash}, {payload})",
			Values: []any{
				sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
				sq.BytesParam("data", dataBytes),
			},
		})
		if err != nil {
			return fmt.Errorf("saving session: %w", err)
		}
		cookie.Value = strings.TrimLeft(hex.EncodeToString(sessionToken[:]), "0")
	}
	http.SetCookie(w, cookie)
	return nil
}

func (nbrew *Notebrew) getSession(w http.ResponseWriter, r *http.Request, name string, v any) (ok bool, err error) {
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return false, nil
	}
	var dataBytes []byte
	if nbrew.DB == nil {
		dataBytes, err = base64.URLEncoding.DecodeString(cookie.Value)
		if err != nil {
			return false, nil
		}
	} else {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
		if err != nil {
			return false, nil
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256([]byte(sessionToken[8:]))
		copy(sessionTokenHash[:8], sessionToken[:8])
		copy(sessionTokenHash[8:], checksum[:])
		createdAt := time.Unix(int64(binary.BigEndian.Uint64(sessionTokenHash[:8])), 0)
		if time.Now().Sub(createdAt) > 5*time.Minute {
			return false, nil
		}
		dataBytes, err = sq.FetchOneContext(r.Context(), nbrew.DB, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format:  "SELECT {*} FROM sessions WHERE session_token_hash = {sessionTokenHash}",
			Values: []any{
				sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
			},
		}, func(row *sq.Row) []byte {
			return row.Bytes("data")
		})
		if err != nil {
			return false, err
		}
	}
	if ptr, ok := v.(*[]byte); ok {
		*ptr = dataBytes
		return true, nil
	}
	err = json.Unmarshal(dataBytes, v)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (nbrew *Notebrew) clearSession(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		MaxAge: -1,
	})
	if nbrew.DB == nil {
		return
	}
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return
	}
	sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
	if err != nil {
		return
	}
	var sessionTokenHash [8 + blake2b.Size256]byte
	checksum := blake2b.Sum256([]byte(sessionToken[8:]))
	copy(sessionTokenHash[:8], sessionToken[:8])
	copy(sessionTokenHash[8:], checksum[:])
	_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
		Dialect: nbrew.Dialect,
		Format:  "DELETE FROM sessions WHERE session_token_hash = {sessionTokenHash}",
		Values: []any{
			sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
		},
	})
	if err != nil {
		logger, ok := r.Context().Value(loggerKey).(*slog.Logger)
		if !ok {
			logger = slog.Default()
		}
		logger.Error(err.Error())
	}
}
