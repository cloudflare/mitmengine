package loader

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/goamz/goamz/aws"
	"github.com/goamz/goamz/s3"
	"github.com/spf13/viper"
)

// S3 implements interface Loader, so it can be used in an mitmengine.Config struct when getting a
// mitmengine.Processor.
type S3 struct {
	configFileName string
	bucket         *s3.Bucket
}

// NewS3Instance creates S3 struct from toml-styled configuration file (an implementation of a Loader)
func NewS3Instance(configFileName string) (S3, error) {
	var s3Instance S3

	// Find and read the config file
	viper.SetConfigType("toml")
	// Viper is weird and only expects filenames with no extensions...
	viper.SetConfigName(strings.Replace(configFileName, ".toml", "", -1))
	viper.AddConfigPath("$GOPATH/src/github.com/cloudflare/mitmengine/loader")
	viper.AddConfigPath("$GOPATH/src/github.com/cloudflare/mitmengine/")
	err := viper.ReadInConfig()
	if err != nil {
		return s3Instance, fmt.Errorf("fatal error config file: %s", err)
	}

	accessKey := viper.GetString("AccessKey")
	secretKey := viper.GetString("SecretKey")

	// If keys not in config file, read from environment variables
	if len(accessKey) == 0 {
		accessKey = os.Getenv("AWS_ACCESS_KEY_ID")
	}
	if len(secretKey) == 0 {
		secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}

	auth, err := aws.GetAuth(strings.TrimSpace(string(accessKey)), strings.TrimSpace(string(secretKey)), "", time.Time{})
	if err != nil {
		log.Fatal("could not be authorized by S3 server:", err)
	}

	s3Endpoint := viper.GetString("S3Endpoint")
	s3BucketEndpoint := viper.GetString("S3BucketEndpoint")
	region := aws.Region{
		S3Endpoint:       s3Endpoint,
		S3BucketEndpoint: s3BucketEndpoint,
	}

	// use the bucket to pull fingerprint files
	bucketName := viper.GetString("BucketName")
	mitmBucket := s3.New(auth, region).Bucket(bucketName)
	if mitmBucket == nil {
		return s3Instance, fmt.Errorf("no bucket \"%s\" found at bucket endpoint %s", bucketName, s3BucketEndpoint)
	}
	return S3{
		configFileName: configFileName,
		bucket:         mitmBucket,
	}, nil
}

// LoadFile implements the LoadFile function specified in Loader interface, as defined in loader.go
func (s3 S3) LoadFile(fileName string) (io.ReadCloser, error) {
	reader, err := s3.bucket.GetReader(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %s", fileName, err)
	}
	return reader, nil
}
