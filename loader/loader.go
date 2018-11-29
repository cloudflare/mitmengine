package loader

import "io"

// Loader is the interface for loading files from any datasource you would like to specify;
// make sure that you implement this interface when developing support for reading fingerprint files from
// your own desired sources!
type Loader interface {
	LoadFile(fileName string) (io.ReadCloser, error)
}
