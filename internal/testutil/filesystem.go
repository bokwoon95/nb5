package testutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"sync"
	"testing/fstest"
	"time"
)

var ErrUnsupported = errors.New("unsupported operation")

type Filesystem struct {
	mu       sync.RWMutex
	mapFS    fstest.MapFS
	readonly bool
}

func NewFilesystem(mapFS fstest.MapFS) *Filesystem {
	if mapFS == nil {
		mapFS = make(fstest.MapFS)
	}
	return &Filesystem{mapFS: mapFS}
}

func NewReadonlyFilesystem(mapFS fstest.MapFS) *Filesystem {
	return &Filesystem{mapFS: mapFS, readonly: true}
}

/*
Open(name) (fs.File, error)
OpenWriter(name string) (io.WriteCloser, error)
ReadDir(name string) ([]fs.DirEntry, error) -> ls
MkdirAll(name string) error -> mkdir -p
RemoveAll(name string) error -> rm -rf
Copy(oldname, newname string) error -> cp
Move(oldname, newname string) error -> mv
*/

func (fsys *Filesystem) Open(name string) (fs.File, error) {
	fsys.mu.RLock()
	defer fsys.mu.RUnlock()
	return fsys.mapFS.Open(name)
}

func (fsys *Filesystem) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	if fsys.readonly {
		return nil, ErrUnsupported
	}
	testFile := &file{
		fsys: fsys,
		name: name,
		buf:  &bytes.Buffer{},
	}
	return testFile, nil
}

func (fsys *Filesystem) MkdirAll(path string, perm fs.FileMode) error {
	if !fs.ValidPath(path) {
		return &fs.PathError{Op: "mkdirall", Path: path, Err: fs.ErrInvalid}
	}
	if fsys.readonly {
		return ErrUnsupported
	}
	fileInfo, err := fs.Stat(fsys, path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if fileInfo != nil {
		if fileInfo.IsDir() {
			return nil
		}
		return fmt.Errorf("file named %q already exists", path)
	}
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	fsys.mapFS[path] = &fstest.MapFile{
		Mode:    fs.ModeDir,
		ModTime: time.Now(),
	}
	return nil
}

func (fsys *Filesystem) RemoveAll(path string) error {
	if !fs.ValidPath(path) {
		return &fs.PathError{Op: "removeall", Path: path, Err: fs.ErrInvalid}
	}
	if fsys.readonly {
		return ErrUnsupported
	}
	fileInfo, err := fs.Stat(fsys, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	delete(fsys.mapFS, path)
	if !fileInfo.IsDir() {
		return nil
	}
	prefix := path + "/"
	for name := range fsys.mapFS {
		if strings.HasPrefix(name, prefix) {
			delete(fsys.mapFS, name)
		}
	}
	return nil
}

func (fsys *Filesystem) Move(oldpath, newpath string) error {
	if !fs.ValidPath(oldpath) {
		return &fs.PathError{Op: "move", Path: oldpath, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newpath) {
		return &fs.PathError{Op: "move", Path: newpath, Err: fs.ErrInvalid}
	}
	if fsys.readonly {
		return ErrUnsupported
	}
	oldFileInfo, err := fs.Stat(fsys, oldpath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	newFileInfo, err := fs.Stat(fsys, newpath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if oldFileInfo == nil {
		return fmt.Errorf("%q does not exist", oldpath)
	}
	fsys.mu.Lock()
	defer fsys.mu.Lock()
	if newFileInfo == nil {
		if !oldFileInfo.IsDir() {
			// Rename a file.
			fsys.mapFS[newpath] = fsys.mapFS[oldpath]
			delete(fsys.mapFS, oldpath)
			return nil
		}
		// Rename a directory (and all its children).
		for name, file := range fsys.mapFS {
			if !strings.HasPrefix(name, oldpath) {
				continue
			}
			tail := strings.TrimPrefix(name, oldpath)
			if tail != "" && !strings.HasPrefix(tail, "/") {
				continue
			}
			fsys.mapFS[newpath+tail] = file
			delete(fsys.mapFS, name)
		}
		return nil
	}
	if !newFileInfo.IsDir() {
		if oldFileInfo.IsDir() {
			// Move a directory into a file (not allowed).
			return fmt.Errorf("cannot move directory %q into file %q", oldpath, newpath)
		}
		// Move a file into a file (overwrite).
		fsys.mapFS[newpath] = fsys.mapFS[oldpath]
		delete(fsys.mapFS, oldpath)
		return nil
	}
	if !oldFileInfo.IsDir() {
		// Move a file into a directory.
		filename := path.Base(oldpath)
		fsys.mapFS[newpath+"/"+filename] = fsys.mapFS[oldpath]
		delete(fsys.mapFS, oldpath)
		return nil
	}
	// Move a directory (and all its children) into a directory.
	dirname := path.Base(oldpath)
	for name, file := range fsys.mapFS {
		if !strings.HasPrefix(name, oldpath) {
			continue
		}
		tail := strings.TrimPrefix(name, oldpath)
		if tail != "" && !strings.HasPrefix(tail, "/") {
			continue
		}
		fsys.mapFS[newpath+"/"+dirname+"/"+tail] = file
		delete(fsys.mapFS, name)
	}
	return nil
}

func (fsys *Filesystem) Clone() *Filesystem {
	mapFS := make(fstest.MapFS)
	fsys.mu.RLock()
	defer fsys.mu.RUnlock()
	for name, file := range fsys.mapFS {
		mapFS[name] = &fstest.MapFile{
			Data:    file.Data,
			Mode:    file.Mode,
			ModTime: file.ModTime,
			Sys:     file.Sys,
		}
	}
	return &Filesystem{mapFS: mapFS}
}

type file struct {
	fsys *Filesystem
	name string
	buf  *bytes.Buffer
}

func (f *file) Write(p []byte) (n int, err error) {
	return f.buf.Write(p)
}

func (f *file) Close() error {
	if f.buf == nil {
		return fmt.Errorf("already closed")
	}
	defer func() {
		f.buf = nil
	}()
	if f.fsys.readonly {
		return ErrUnsupported
	}
	fileInfo, err := fs.Stat(f.fsys, f.name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if fileInfo != nil && !fileInfo.IsDir() {
		return fmt.Errorf("directory named %q already exists", f.name)
	}
	f.fsys.mu.Lock()
	defer f.fsys.mu.Unlock()
	f.fsys.mapFS[f.name] = &fstest.MapFile{
		Data:    f.buf.Bytes(),
		ModTime: time.Now(),
	}
	return nil
}
