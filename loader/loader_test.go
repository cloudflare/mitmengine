package loader_test

import (
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/mitmengine"
	"github.com/cloudflare/mitmengine/loader"
)

func TestProcessorConfigS3(t *testing.T) {

	variables := []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_ACCESS_KEY_ID",
		"AWS_ENDPOINT",
		"AWS_BUCKET_NAME",
	}
	skip := false
	for _, v := range variables {
		if _, ok := os.LookupEnv(v); !ok {
			skip = true
		}
	}
	if skip {
		t.Skipf("To run this test, set the following environment variables: %v", strings.Join(variables, ", "))
	}

	s3Instance, err := loader.NewS3Instance()
	if err != nil {
		t.Fatalf("loader.NewS3Instance(): '%v'", err)
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
