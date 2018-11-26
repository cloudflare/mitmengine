package loader

import (
	"fmt"
	"os"
	"testing"
)

func setup() (S3, error) {
	var s3Instance S3
	configFileName := "s3cfg.toml"

	_, notInLocalDirErr := os.Stat("./" + configFileName)
	_, notInProjectRootDirErr := os.Stat("../" + configFileName)

	// This test will be a no-op if no s3cfg.toml file is provided in the loader directory or the project's
	// root directory.
	if os.IsNotExist(notInLocalDirErr) && os.IsNotExist(notInProjectRootDirErr) {
		return s3Instance, fmt.Errorf(`No s3cfg.toml file found in project root directory 
($GOPATH/src/github.com/cloudflare/mitmengine) or loaders directory`)
	}

	return NewS3Instance(configFileName)
}

func TestNewS3InstanceCorrectlyLoadsValues(t *testing.T) {
	_, getS3Err := setup()
	if getS3Err != nil {
		t.Fatal("Could not connect to s3 instance and retrieve bucket using given credentials:", getS3Err)
	}
}

func TestNewS3InstanceThrowsErrFileNotFound(t *testing.T) {
	s3Instance, getS3Err := setup()
	if getS3Err != nil {
		t.Fatal("Could not connect to s3 instance and retrieve bucket using given credentials:", getS3Err)
	}

	fakeFile := "not-real.txt"
	_, loadFileErr := s3Instance.LoadFile(fakeFile)
	if loadFileErr == nil {
		t.Fatal("s3 instance retrieves fake file not-real.txt:", loadFileErr)
	}
}

func TestNewS3InstanceLoadsFile(t *testing.T) {
	s3Instance, getS3Err := setup()
	if getS3Err != nil {
		t.Fatal("Could not connect to s3 instance and retrieve bucket using given credentials:", getS3Err)
	}

	realFile := "browser.txt"
	_, loadFileErr := s3Instance.LoadFile(realFile)
	if loadFileErr != nil {
		t.Fatal("s3 instance cannot retrieve real file browser.txt:", loadFileErr)
	}
}