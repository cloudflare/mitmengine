package loader_test

import (
	"github.com/cloudflare/mitmengine"
	"github.com/cloudflare/mitmengine/loader"
	"os"
	"testing"
)

func TestProcessorConfigS3(t *testing.T) {
	configFileName := "s3cfg.toml"

	_, notInLocalDirErr := os.Stat("./" + configFileName)
	_, notInProjectRootDirErr := os.Stat("../" + configFileName)

	// This test will be a no-op if no s3cfg.toml file is provided in the loader directory or the project's
	// root directory.
	if os.IsNotExist(notInLocalDirErr) && os.IsNotExist(notInProjectRootDirErr) {
		t.Fatal(`No s3cfg.toml file found in project root directory 
($GOPATH/src/github.com/cloudflare/mitmengine) or loaders directory`)
	}

	s3Instance, err := loader.NewS3Instance(configFileName)
	if err != nil {
		t.Fatal("Could not load s3 instance:", err)
	}

	testConfigS3 := mitmengine.Config{
		BrowserFileName:   "browser.txt",
		MitmFileName:      "mitm.txt",
		BadHeaderFileName: "badheader.txt",
		Loader:            s3Instance,
	}

	t.Run("LoaderThrowsErrFileNNonexistent", func(t *testing.T) { _TestLoaderThrowsErrFileNNonexistent(t, &testConfigS3) })
	t.Run("TestLoaderLoadsExistingFile", func(t *testing.T) { _TestLoaderLoadsExistingFile(t, &testConfigS3) })
}

// Please edit this function to represent .txt files you DON'T expect to find in your data store
func _TestLoaderThrowsErrFileNNonexistent(t *testing.T, config *mitmengine.Config) {
	fakeFile := "not-real.txt"
	_, loadFileErr := config.Loader.LoadFile(fakeFile)
	if loadFileErr == nil {
		t.Fatal("s3 instance retrieves fake file not-real.txt:", loadFileErr)
	}
}

// Please edit this function to represent .txt files you DO expect to find in your data store
func _TestLoaderLoadsExistingFile(t *testing.T, config *mitmengine.Config) {
	realFile := "browser.txt"
	_, loadFileErr := config.Loader.LoadFile(realFile)
	if loadFileErr != nil {
		t.Fatal("s3 instance cannot retrieve real file browser.txt:", loadFileErr)
	}
}
