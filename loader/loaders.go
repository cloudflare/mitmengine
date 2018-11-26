package loader

import "io"

type Loader interface {
	LoadFile(fileName string) (io.ReadCloser, error)
}

