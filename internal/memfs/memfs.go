package memfs

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

// memfs.New()

type Filesystem struct {
	mu    sync.RWMutex
	mapFS fstest.MapFS
}

func New(mapFS fstest.MapFS) *Filesystem {
	return &Filesystem{mapFS: mapFS}
}

func (fsys *Filesystem) Open(name string) (fs.File, error) {
	fsys.mu.RLock()
	defer fsys.mu.RUnlock()
	return fsys.mapFS.Open(name)
}

func (fsys *Filesystem) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	testFile := &TestFile{
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
	fileInfo, err := fs.Stat(fsys, path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if fileInfo != nil && !fileInfo.IsDir() {
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
	fsys.mu.Lock()
	delete(fsys.mapFS, path)
	fsys.mu.Unlock()
	fileInfo, err := fs.Stat(fsys, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if !fileInfo.IsDir() {
		return nil
	}
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
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
	fsys.mu.Lock()
	defer fsys.mu.Unlock()
	oldFileInfo, err := fs.Stat(fsys, oldpath)
	if err != nil {
		// If source file/directory does not exist, no point in moving
		// anything.
		return err
	}
	var data []byte
	if !oldFileInfo.IsDir() {
		data, err = fs.ReadFile(fsys, oldpath)
		if err != nil {
			return err
		}
	}
	newFileInfo, err := fs.Stat(fsys, newpath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// If destination does not exist, the file or directory can safely
			// take its place. Move the data and filemode over.
			// TODO: if oldFileInfo.IsDir(), we need to move all child files over to the new folder as well :/.
			delete(fsys.mapFS, oldpath)
			fsys.mapFS[newpath] = &fstest.MapFile{
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
		// TODO: if oldFileInfo.IsDir(), we need to move all child files over to the new folder as well :/.
		delete(fsys.mapFS, oldpath)
		fsys.mapFS[path.Join(newpath, oldFileInfo.Name())] = &fstest.MapFile{
			Data:    data,
			Mode:    oldFileInfo.Mode(),
			ModTime: time.Now(),
		}
		return nil
	}
	// Otherwise, move the old file over to the newpath, replacing the current
	// file.
	delete(fsys.mapFS, oldpath)
	fsys.mapFS[newpath] = &fstest.MapFile{
		Data:    data,
		Mode:    oldFileInfo.Mode(),
		ModTime: time.Now(),
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

type TestFile struct {
	fsys *Filesystem
	name string
	buf  *bytes.Buffer
}

func (testFile *TestFile) Write(p []byte) (n int, err error) {
	return testFile.buf.Write(p)
}

func (testFile *TestFile) Close() error {
	if testFile.buf == nil {
		return fmt.Errorf("already closed")
	}
	defer func() {
		testFile.buf = nil
	}()
	fileInfo, err := fs.Stat(testFile.fsys, testFile.name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if fileInfo != nil && !fileInfo.IsDir() {
		return fmt.Errorf("directory named %q already exists", testFile.name)
	}
	testFile.fsys.mu.Lock()
	defer testFile.fsys.mu.Unlock()
	testFile.fsys.mapFS[testFile.name] = &fstest.MapFile{
		Data:    testFile.buf.Bytes(),
		ModTime: time.Now(),
	}
	return nil
}
