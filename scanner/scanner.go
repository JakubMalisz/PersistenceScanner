package scanner

import (
	
	"io/fs"
	"os"
	"github.com/charlievieth/fastwalk"
	"PersistenceScanner/internal/core"
)

func DirScan(paths []string) <-chan core.FileData {
	data := make(chan core.FileData, 100)

	go func() {
		defer close(data)
		conf := &fastwalk.Config{Follow: false}

		for _, root := range paths {
			_ = fastwalk.Walk(conf, root, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}

				fileInfo, err := os.Stat(path)
				if err != nil {
					return nil
				}

				data <- core.FileData{
					Name:        fileInfo.Name(),
					Path:        path,
					Size:        uint(fileInfo.Size()),
					Permissions: fileInfo.Mode(),
					ModTime:     fileInfo.ModTime(),
				}
				return nil
			})
		}
	}()
	return data
}