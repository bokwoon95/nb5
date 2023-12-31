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
	"golang.org/x/exp/slices"
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

// ErrUnsupported indicates that a requested operation cannot be performed,
// because it is unsupported.
var ErrUnsupported = errors.New("unsupported operation")

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

type FS interface {
	// Open opens the named file.
	//
	// When Open returns an error, it should be of type *PathError
	// with the Op field set to "open", the Path field set to name,
	// and the Err field describing the problem.
	//
	// Open should reject attempts to open names that do not satisfy
	// ValidPath(name), returning a *PathError with Err set to
	// ErrInvalid or ErrNotExist.
	Open(name string) (fs.File, error)

	// OpenWriter opens an io.WriteCloser that represents an instance of a file
	// that can be written to. If the file doesn't exist, it should be created.
	// If the file exists, its should be truncated.
	OpenWriter(name string) (io.WriteCloser, error)

	// ReadDir reads the named directory and returns a list of directory
	// entries sorted by filename.
	ReadDir(name string) ([]fs.DirEntry, error) // ls

	// MkdirAll creates a directory named path, along with any necessary
	// parents, and returns nil, or else returns an error. The permission bits
	// perm (before umask) are used for all directories that MkdirAll creates.
	// If path is already a directory, MkdirAll does nothing and returns nil.
	MkdirAll(name string) error // mkdir -p

	// RemoveAll removes all files with prefix matching the path. If there are
	// no files matching the path, RemoveAll returns nil.
	RemoveAll(name string) error // rm -rf

	// TODO: Document this.
	Copy(oldname, newname string) error // cp

	// TODO: Document this.
	Move(oldname, newname string) error // mv
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
	MkdirAll(name string) error
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

	Move(oldname, newname string) error
}

// OpenWriter opens an io.WriteCloser from the file system that represents an
// instance of a file that can be written to. If the file doesn't exist, it
// should be created.
func OpenWriter(fsys fs.FS, name string) (io.WriteCloser, error) {
	if fsys, ok := fsys.(WriteFS); ok {
		return fsys.OpenWriter(name)
	}
	return nil, ErrUnsupported
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
func MkdirAll(fsys fs.FS, path string) error {
	if fsys, ok := fsys.(MkdirAllFS); ok {
		return fsys.MkdirAll(path)
	}
	return ErrUnsupported
}

// RemoveAll removes all files from the file system with prefix matching the
// path. If there are no files matching the path, RemoveAll returns nil.
func RemoveAll(fsys fs.FS, path string) error {
	if fsys, ok := fsys.(RemoveAllFS); ok {
		return fsys.RemoveAll(path)
	}
	return ErrUnsupported
}

// TODO: Document this.
func Move(fsys fs.FS, oldpath, newpath string) error {
	if fsys, ok := fsys.(MoveFS); ok {
		return fsys.Move(oldpath, newpath)
	}
	return ErrUnsupported
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

type DirFS string

// var _ FS = DirFS("")

func (dirFS DirFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	return os.Open(path.Join(string(dirFS), name))
}

func (dirFS DirFS) OpenWriter(name string) (io.WriteCloser, error) {
	var err error
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	tempDir := path.Join(os.TempDir(), "notebrewtempdir")
	err = os.MkdirAll(tempDir, 0755)
	if err != nil {
		return nil, err
	}
	f := &tempFileWrapper{
		destFilename: path.Join(string(dirFS), name),
	}
	f.tempFile, err = os.CreateTemp(tempDir, "*")
	if err != nil {
		return nil, err
	}
	fileInfo, err := f.tempFile.Stat()
	if err != nil {
		return nil, err
	}
	f.tempFilename = path.Join(tempDir, fileInfo.Name())
	return f, nil
}

func (dirFS DirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	return os.ReadDir(path.Join(string(dirFS), name))
}

func (dirFS DirFS) MkdirAll(name string) error {
	if !fs.ValidPath(name) {
		return &fs.PathError{Op: "mkdirall", Path: name, Err: fs.ErrInvalid}
	}
	return os.MkdirAll(path.Join(string(dirFS), name), 0755)
}

func (dirFS DirFS) RemoveAll(name string) error {
	if !fs.ValidPath(name) {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	return os.RemoveAll(path.Join(string(dirFS), name))
}

func (dirFS DirFS) Copy(oldname, newname string) error {
	if !fs.ValidPath(oldname) {
		return &fs.PathError{Op: "copy", Path: oldname, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newname) {
		return &fs.PathError{Op: "copy", Path: newname, Err: fs.ErrInvalid}
	}
	if oldname == newname {
		return &fs.PathError{Op: "copy", Path: newname, Err: fmt.Errorf("oldname and newname are the same")}
	}
	oldname = path.Join(string(dirFS), oldname)
	newname = path.Join(string(dirFS), newname)
	oldfileinfo, err := os.Stat(oldname)
	if err != nil {
		return err
	}
	newfileinfo, err := os.Stat(newname)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !oldfileinfo.IsDir() {
		oldfile, err := os.Open(oldname)
		if err != nil {
			return err
		}
		name := newname
		if newfileinfo != nil && newfileinfo.IsDir() {
			name = path.Join(newname, path.Base(oldname))
		}
		newfile, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, oldfileinfo.Mode())
		if err != nil {
			return err
		}
		_, err = io.Copy(newfile, oldfile)
		if err != nil {
			return err
		}
		return nil
	}
	if runtime.GOOS == "windows" {
		return exec.Command("xcopy", "/s", "/e", "/y", filepath.FromSlash(oldname), filepath.FromSlash(newname)).Run()
	}
	return exec.Command("cp", filepath.ToSlash(oldname), filepath.ToSlash(newname)).Run()
}

func (dirFS DirFS) Move(oldname, newname string) error {
	if !fs.ValidPath(oldname) {
		return &fs.PathError{Op: "move", Path: oldname, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newname) {
		return &fs.PathError{Op: "move", Path: newname, Err: fs.ErrInvalid}
	}
	if oldname == newname {
		return &fs.PathError{Op: "move", Path: newname, Err: fmt.Errorf("oldname and newname are the same")}
	}
	oldname = path.Join(string(dirFS), oldname)
	newname = path.Join(string(dirFS), newname)
	_, err := os.Stat(oldname)
	if err != nil {
		return err
	}
	newfileinfo, err := os.Stat(newname)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if newfileinfo == nil || !newfileinfo.IsDir() {
		return os.Rename(oldname, newname)
	}
	if runtime.GOOS == "windows" {
		return exec.Command("move", filepath.FromSlash(oldname), filepath.FromSlash(newname)).Run()
	}
	return exec.Command("mv", filepath.ToSlash(oldname), filepath.ToSlash(newname)).Run()
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

var uppercaseCharSet = map[rune]struct{}{
	'A': {}, 'B': {}, 'C': {}, 'D': {}, 'E': {}, 'F': {}, 'G': {}, 'H': {}, 'I': {},
	'J': {}, 'K': {}, 'L': {}, 'M': {}, 'N': {}, 'O': {}, 'P': {}, 'Q': {}, 'R': {},
	'S': {}, 'T': {}, 'U': {}, 'V': {}, 'W': {}, 'X': {}, 'Y': {}, 'Z': {},
}

var forbiddenCharSet = map[rune]struct{}{
	' ': {}, '!': {}, '"': {}, '#': {}, '$': {}, '%': {}, '&': {}, '\'': {},
	'(': {}, ')': {}, '*': {}, '+': {}, ',': {}, '/': {}, ':': {}, ';': {},
	'<': {}, '>': {}, '=': {}, '?': {}, '[': {}, ']': {}, '\\': {}, '^': {},
	'`': {}, '{': {}, '}': {}, '|': {}, '~': {},
}

var forbiddenNameSet = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {}, "com1": {}, "com2": {},
	"com3": {}, "com4": {}, "com5": {}, "com6": {}, "com7": {}, "com8": {},
	"com9": {}, "lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {}, "lpt5": {},
	"lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
}

func validateName(errmsgs []string, name string) []string {
	var forbiddenChars strings.Builder
	hasUppercaseChar := false
	writtenChar := make(map[rune]struct{})
	for _, char := range name {
		if _, ok := uppercaseCharSet[char]; ok {
			hasUppercaseChar = true
		}
		if _, ok := forbiddenCharSet[char]; ok {
			if _, ok := writtenChar[char]; !ok {
				writtenChar[char] = struct{}{}
				forbiddenChars.WriteRune(char)
			}
		}
	}
	if hasUppercaseChar {
		errmsgs = append(errmsgs, "no uppercase letters [A-Z] allowed")
	}
	if forbiddenChars.Len() > 0 {
		errmsgs = append(errmsgs, "forbidden characters: "+forbiddenChars.String())
	}
	if len(name) > 0 && name[len(name)-1] == '.' {
		errmsgs = append(errmsgs, "cannot end in dot")
	}
	if _, ok := forbiddenNameSet[strings.ToLower(name)]; ok {
		errmsgs = append(errmsgs, "forbidden name")
	}
	return errmsgs
}

type contextKey struct{}

var loggerKey = &contextKey{}

func (nbrew *Notebrew) createFile(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	type Request struct {
		ParentFolder string `json:"parent_folder,omitempty"`
		Name         string `json:"name,omitempty"`
	}
	type Response struct {
		ParentFolder       string   `json:"parent_folder,omitempty"`
		ParentFolderErrors []string `json:"parent_folder_errors,omitempty"`
		Name               string   `json:"name,omitempty"`
		NameErrors         []string `json:"name_errors,omitempty"`
		Error              string   `json:"error,omitempty"`
		AlreadyExists      string   `json:"already_exists,omitempty"`
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
		var response Response
		ok, err := nbrew.getSession(r, "flash_session", &response)
		if err != nil {
			logger.Error(err.Error())
		}
		if !ok {
			response.ParentFolder = r.Form.Get("parent_folder")
			response.Name = r.Form.Get("name")
		}
		if response.ParentFolder != "" {
			response.ParentFolder = strings.Trim(path.Clean(response.ParentFolder), "/")
		}
		nbrew.clearSession(w, r, "flash_session")
		tmpl, err := template.ParseFS(rootFS, "html/create_file.html")
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		err = tmpl.Execute(buf, &response)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf.WriteTo(w)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
			if accept == "application/json" {
				b, err := json.Marshal(&response)
				if err != nil {
					logger.Error(err.Error())
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
				w.Write(b)
				return
			}
			if len(response.ParentFolderErrors) == 0 && len(response.NameErrors) == 0 && response.Error == "" && response.AlreadyExists == "" {
				http.Redirect(w, r, "/"+path.Join("admin", sitePrefix, response.ParentFolder, response.Name), http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, &response, &http.Cookie{
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
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		}

		var request Request
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
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
		case "application/x-www-form-urlencoded":
			err := r.ParseForm()
			if err != nil {
				http.Error(w, fmt.Sprintf("400 Bad Request: %s", err), http.StatusBadRequest)
				return
			}
			request.ParentFolder = r.Form.Get("parent_folder")
			request.Name = r.Form.Get("name")
		default:
			http.Error(w, "415 Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}

		response := Response{
			ParentFolder: request.ParentFolder,
			Name:         request.Name,
		}
		if response.ParentFolder != "" {
			response.ParentFolder = strings.Trim(path.Clean(response.ParentFolder), "/")
		}
		head, tail, _ := strings.Cut(response.ParentFolder, "/")

		if head != "posts" && head != "notes" && head != "pages" && head != "templates" && head != "assets" {
			response.ParentFolderErrors = append(response.ParentFolderErrors, "parent folder has to start with posts, notes, pages, templates or assets")
		} else if (head == "posts" || head == "notes") && strings.Contains(tail, "/") {
			response.ParentFolderErrors = append(response.ParentFolderErrors, "not allowed to use this parent folder")
		}

		if (head == "posts" || head == "notes") && response.Name == "" {
			response.Name = strings.ToLower(ulid.Make().String()) + ".md"
		}

		if response.Name == "" {
			response.NameErrors = append(response.NameErrors, "cannot be empty")
		} else {
			response.NameErrors = validateName(response.NameErrors, response.Name)
			switch head {
			case "posts", "notes":
				if path.Ext(response.Name) != ".md" {
					response.NameErrors = append(response.NameErrors, "invalid extension (must end in .md)")
				}
			case "pages", "templates":
				if path.Ext(response.Name) != ".html" {
					response.NameErrors = append(response.NameErrors, "invalid extension (must end in .html)")
				}
			case "assets":
				ext := path.Ext(response.Name)
				if ext == ".gz" {
					ext = path.Ext(strings.TrimSuffix(response.Name, ext))
				}
				allowedExts := []string{
					".html", ".css", ".js", ".md", ".txt",
					".jpeg", ".jpg", ".png", ".gif", ".svg", ".ico",
					".eof", ".ttf", ".woff", ".woff2",
					".csv", ".tsv", ".json", ".xml", ".toml", ".yaml", ".yml",
				}
				if !slices.Contains(allowedExts, ext) {
					response.NameErrors = append(response.NameErrors, fmt.Sprintf("invalid extension (must be one of: %s)", strings.Join(allowedExts, ", ")))
				}
			}
		}

		if len(response.ParentFolderErrors) > 0 || len(response.NameErrors) > 0 {
			writeResponse(w, r, response)
			return
		}

		_, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.ParentFolder))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				logger.Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			response.ParentFolderErrors = append(response.ParentFolderErrors, "folder does not exist")
			writeResponse(w, r, response)
			return
		}

		_, err = fs.Stat(nbrew.FS, path.Join(sitePrefix, response.ParentFolder, response.Name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err == nil {
			response.AlreadyExists = "/" + path.Join("admin", sitePrefix, response.ParentFolder, response.Name)
			writeResponse(w, r, response)
			return
		}

		writer, err := OpenWriter(nbrew.FS, path.Join(sitePrefix, response.ParentFolder, response.Name))
		if err != nil {
			if errors.Is(err, ErrUnsupported) {
				response.Error = "unable to create file"
				writeResponse(w, r, response)
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
		writeResponse(w, r, response)
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (nbrew *Notebrew) createFolder(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	type Request struct {
		ParentFolder string `json:"parent_folder,omitempty"`
		Name         string `json:"name,omitempty"`
	}
	type Response struct {
		ParentFolder       string   `json:"parent_folder,omitempty"`
		ParentFolderErrors []string `json:"parent_folder_errors,omitempty"`
		Name               string   `json:"name,omitempty"`
		NameErrors         []string `json:"name_errors,omitempty"`
		Error              string   `json:"error,omitempty"`
		AlreadyExists      string   `json:"already_exists,omitempty"`
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
		var response Response
		ok, err := nbrew.getSession(r, "flash_session", &response)
		if err != nil {
			logger.Error(err.Error())
		}
		if !ok {
			response.ParentFolder = r.Form.Get("parent_folder")
			response.Name = r.Form.Get("name")
		}
		if response.ParentFolder != "" {
			response.ParentFolder = strings.Trim(path.Clean(response.ParentFolder), "/")
		}
		nbrew.clearSession(w, r, "flash_session")
		tmpl, err := template.ParseFS(rootFS, "html/create_folder.html")
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		err = tmpl.Execute(buf, &response)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf.WriteTo(w)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
			if accept == "application/json" {
				b, err := json.Marshal(&response)
				if err != nil {
					logger.Error(err.Error())
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
				w.Write(b)
				return
			}
			if len(response.ParentFolderErrors) == 0 && len(response.NameErrors) == 0 && response.Error == "" && response.AlreadyExists == "" {
				http.Redirect(w, r, "/"+path.Join("admin", sitePrefix, response.ParentFolder, response.Name)+"/", http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, &response, &http.Cookie{
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
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		}

		var request Request
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
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
		case "application/x-www-form-urlencoded":
			err := r.ParseForm()
			if err != nil {
				http.Error(w, fmt.Sprintf("400 Bad Request: %s", err), http.StatusBadRequest)
				return
			}
			request.ParentFolder = r.Form.Get("parent_folder")
			request.Name = r.Form.Get("name")
		default:
			http.Error(w, "415 Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}

		response := Response{
			ParentFolder: request.ParentFolder,
			Name:         request.Name,
		}
		if response.ParentFolder != "" {
			response.ParentFolder = strings.Trim(path.Clean(response.ParentFolder), "/")
		}
		head, tail, _ := strings.Cut(response.ParentFolder, "/")

		if head != "posts" && head != "notes" && head != "pages" && head != "templates" && head != "assets" {
			response.ParentFolderErrors = append(response.ParentFolderErrors, "parent folder has to start with posts, notes, pages, templates or assets")
		} else if (head == "posts" || head == "notes") && tail != "" {
			response.ParentFolderErrors = append(response.ParentFolderErrors, "not allowed to use this parent folder")
		}

		if response.Name == "" {
			response.NameErrors = append(response.NameErrors, "cannot be empty")
		} else {
			response.NameErrors = validateName(response.NameErrors, response.Name)
		}

		if len(response.ParentFolderErrors) > 0 || len(response.NameErrors) > 0 {
			writeResponse(w, r, response)
			return
		}

		_, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.ParentFolder))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				logger.Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			response.ParentFolderErrors = append(response.ParentFolderErrors, "folder does not exist")
			writeResponse(w, r, response)
			return
		}

		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.ParentFolder, response.Name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err == nil {
			if fileInfo.IsDir() {
				response.AlreadyExists = "/" + path.Join("admin", sitePrefix, response.ParentFolder, response.Name)
			} else {
				response.NameErrors = append(response.NameErrors, "file with the same name already exists")
			}
			writeResponse(w, r, response)
			return
		}

		err = MkdirAll(nbrew.FS, path.Join(sitePrefix, response.ParentFolder, response.Name))
		if err != nil {
			if errors.Is(err, ErrUnsupported) {
				response.Error = "unable to create folder"
				writeResponse(w, r, response)
				return
			}
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		writeResponse(w, r, response)
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (nbrew *Notebrew) rename(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	type Request struct {
		ParentFolder string `json:"parent_folder,omitempty"`
		OldName      string `json:"old_name,omitempty"`
		NewName      string `json:"new_name,omitempty"`
	}
	type Response struct {
		ParentFolder       string   `json:"parent_folder,omitempty"`
		ParentFolderErrors []string `json:"parent_folder_errors,omitempty"`
		OldName            string   `json:"old_name,omitempty"`
		OldNameErrors      []string `json:"old_name_errors,omitempty"`
		NewName            string   `json:"new_name,omitempty"`
		NewNameErrors      []string `json:"new_name_errors,omitempty"`
		Error              string   `json:"error,omitempty"`
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
		var response Response
		ok, err := nbrew.getSession(r, "flash_session", &response)
		if err != nil {
			logger.Error(err.Error())
		}
		if !ok {
			response.ParentFolder = r.Form.Get("parent_folder")
			response.OldName = r.Form.Get("old_name")
			response.NewName = r.Form.Get("new_name")
		}
		if response.ParentFolder != "" {
			response.ParentFolder = strings.Trim(path.Clean(response.ParentFolder), "/")
		}
		nbrew.clearSession(w, r, "flash_session")
		tmpl, err := template.ParseFS(rootFS, "html/rename.html")
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		err = tmpl.Execute(buf, &response)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf.WriteTo(w)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
			if accept == "application/json" {
				b, err := json.Marshal(&response)
				if err != nil {
					logger.Error(err.Error())
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
				w.Write(b)
				return
			}
			if len(response.ParentFolderErrors) == 0 && len(response.OldNameErrors) == 0 && len(response.NewNameErrors) == 0 && response.Error == "" {
				http.Redirect(w, r, "/"+path.Join("admin", sitePrefix, response.ParentFolder)+"/", http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, &response, &http.Cookie{
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
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		}

		var request Request
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
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
		case "application/x-www-form-urlencoded":
			err := r.ParseForm()
			if err != nil {
				http.Error(w, fmt.Sprintf("400 Bad Request: %s", err), http.StatusBadRequest)
				return
			}
			request.ParentFolder = r.Form.Get("parent_folder")
			request.OldName = r.Form.Get("old_name")
			request.NewName = r.Form.Get("new_name")
		default:
			http.Error(w, "415 Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}

		response := Response{
			ParentFolder: request.ParentFolder,
			OldName:      request.OldName,
			NewName:      request.NewName,
		}
		if response.ParentFolder == "" {
			response.ParentFolderErrors = append(response.ParentFolderErrors, "cannot be empty")
		} else {
			response.ParentFolder = strings.Trim(path.Clean(response.ParentFolder), "/")
		}
		if response.OldName == "" {
			response.OldNameErrors = append(response.OldNameErrors, "cannot be empty")
		}
		if response.NewName == "" {
			response.NewNameErrors = append(response.NewNameErrors, "cannot be empty")
		} else {
			response.NewNameErrors = validateName(response.NewNameErrors, response.NewName)
		}
		if len(response.ParentFolderErrors) > 0 || len(response.OldNameErrors) > 0 || len(response.NewNameErrors) > 0 {
			writeResponse(w, r, response)
			return
		}

		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.ParentFolder))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.ParentFolderErrors = append(response.ParentFolderErrors, "folder does not exist")
				writeResponse(w, r, response)
				return
			}
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !fileInfo.IsDir() {
			response.ParentFolderErrors = append(response.ParentFolderErrors, "not a folder")
			writeResponse(w, r, response)
			return
		}

		_, err = fs.Stat(nbrew.FS, path.Join(sitePrefix, response.ParentFolder, response.OldName))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.OldNameErrors = append(response.OldNameErrors, "old file/folder does not exist")
				writeResponse(w, r, response)
				return
			}
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		_, err = fs.Stat(nbrew.FS, path.Join(sitePrefix, response.ParentFolder, response.NewName))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err == nil {
			response.NewNameErrors = append(response.NewNameErrors, "new file/folder already exists")
			writeResponse(w, r, response)
			return
		}

		err = Move(nbrew.FS, path.Join(sitePrefix, response.ParentFolder, response.OldName), path.Join(sitePrefix, response.ParentFolder, response.NewName))
		if err != nil {
			if errors.Is(err, ErrUnsupported) {
				response.Error = "unable to rename file/folder"
				writeResponse(w, r, response)
				return
			}
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		writeResponse(w, r, response)
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (nbrew *Notebrew) move(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	type Request struct {
		Path              string `json:"path,omitempty"`
		DestinationFolder string `json:"destination_folder,omitempty"`
	}
	type Response struct {
		Path                    string   `json:"path,omitempty"`
		PathErrors              []string `json:"path_errors,omitempty"`
		DestinationFolder       string   `json:"destination_folder,omitempty"`
		DestinationFolderErrors []string `json:"destination_folder_errors,omitempty"`
		Error                   string   `json:"error,omitempty"`
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
		var response Response
		ok, err := nbrew.getSession(r, "flash_session", &response)
		if err != nil {
			logger.Error(err.Error())
		}
		if !ok {
			response.Path = r.Form.Get("path")
			response.DestinationFolder = r.Form.Get("destination_folder")
		}
		if response.Path != "" {
			response.Path = strings.Trim(path.Clean(response.Path), "/")
		}
		if response.DestinationFolder != "" {
			response.DestinationFolder = strings.Trim(path.Clean(response.DestinationFolder), "/")
		}
		nbrew.clearSession(w, r, "flash_session")
		tmpl, err := template.ParseFS(rootFS, "html/move.html")
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		err = tmpl.Execute(buf, &response)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf.WriteTo(w)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
			if accept == "application/json" {
				b, err := json.Marshal(&response)
				if err != nil {
					logger.Error(err.Error())
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
				w.Write(b)
				return
			}
			if len(response.PathErrors) == 0 && len(response.DestinationFolderErrors) == 0 && response.Error == "" {
				http.Redirect(w, r, "/"+path.Join("admin", sitePrefix, response.DestinationFolder)+"/", http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, &response, &http.Cookie{
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
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		}

		var request Request
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
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
		case "application/x-www-form-urlencoded":
			err := r.ParseForm()
			if err != nil {
				http.Error(w, fmt.Sprintf("400 Bad Request: %s", err), http.StatusBadRequest)
				return
			}
			request.Path = r.Form.Get("path")
			request.DestinationFolder = r.Form.Get("destination_folder")
		default:
			http.Error(w, "415 Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}

		response := Response{
			Path:              request.Path,
			DestinationFolder: request.DestinationFolder,
		}
		if response.Path == "" {
			response.PathErrors = append(response.PathErrors, "cannot be empty")
		} else {
			response.Path = strings.Trim(path.Clean(response.Path), "/")
		}
		if response.DestinationFolder == "" {
			response.DestinationFolderErrors = append(response.DestinationFolderErrors, "cannot be empty")
		} else {
			response.DestinationFolder = strings.Trim(path.Clean(response.DestinationFolder), "/")
		}
		if len(response.PathErrors) > 0 || len(response.DestinationFolderErrors) > 0 {
			writeResponse(w, r, response)
			return
		}

		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.DestinationFolder))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.DestinationFolderErrors = append(response.DestinationFolderErrors, "folder does not exist")
				writeResponse(w, r, response)
				return
			}
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !fileInfo.IsDir() {
			response.DestinationFolderErrors = append(response.DestinationFolderErrors, "not a folder")
			writeResponse(w, r, response)
			return
		}
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
			Format:  "INSERT INTO sessions (session_token_hash, data) VALUES ({sessionTokenHash}, {data})",
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

func (nbrew *Notebrew) getSession(r *http.Request, name string, v any) (ok bool, err error) {
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
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
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
