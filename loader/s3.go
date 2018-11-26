package loader

import (
	"fmt"
	"github.com/goamz/goamz/aws"
	"github.com/goamz/goamz/s3"
	"github.com/spf13/viper"
	"io"
	"log"
	"strings"
	"time"
)

type S3 struct {
	configFileName string
	bucket         *s3.Bucket
}

func NewS3Instance(configFileName string) (S3, error) {
	var s3Instance S3

	// Find and read the config file
	viper.SetConfigType("toml")
	// Viper is weird and only expects filenames with no extensions...
	viper.SetConfigName(strings.Replace(configFileName, ".toml", "", -1))
	viper.AddConfigPath("./")
	viper.AddConfigPath("$GOPATH/src/github.com/cloudflare/mitmengine/")
	err := viper.ReadInConfig()
	if err != nil {
		return s3Instance, fmt.Errorf("fatal error config file: %s \n", err)
	}

	accessKey := viper.GetString("AccessKey")
	secretKey := viper.GetString("SecretKey")

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

func (s3 S3) LoadFile(fileName string) (io.ReadCloser, error) {
	reader, err := s3.bucket.GetReader(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %s", fileName, err)
	}
	return reader, nil
}
