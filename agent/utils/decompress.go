package utils

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	relativeParentDir = ".." + string(os.PathSeparator)
)

func DecompressTarGz(r io.Reader, dst string) error {
	madeDir := map[string]bool{}
	zr, err := gzip.NewReader(io.LimitReader(r, 512*1024*1024))
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for {
		var f *tar.Header
		f, err = tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if strings.Contains(f.Name, relativeParentDir) {
			return fmt.Errorf("invalid file name: %s", f.Name)
		}
		abs := filepath.Join(dst, f.Name)
		mode := f.FileInfo().Mode()
		switch {
		case mode.IsRegular():
			// Make the directory. This is redundant because it should
			// already be made by a directory entry in the tar
			// beforehand. Thus, don't check for errors; the next
			// write will fail with the same error.
			dir := filepath.Dir(abs)
			if !madeDir[dir] {
				if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
					return err
				}
				madeDir[dir] = true
			}
			wf, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode.Perm())
			if err != nil {
				return err
			}
			n, err := io.Copy(wf, tr)
			if closeErr := wf.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			if err != nil {
				return fmt.Errorf("error writing to %s: %v", abs, err)
			}
			if n != f.Size {
				return fmt.Errorf("only wrote %d bytes to %s; expected %d", n, abs, f.Size)
			}
		case mode.IsDir():
			if err := os.MkdirAll(abs, 0755); err != nil {
				return err
			}
			madeDir[abs] = true
		default:
			return fmt.Errorf("tar file entry %s contained unsupported file type %v", f.Name, mode)
		}
	}
	return nil
}
