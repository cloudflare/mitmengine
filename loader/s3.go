package loader

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/goamz/goamz/aws"
	"github.com/goamz/goamz/s3"
)

// S3 implements interface Loader, so it can be used in an mitmengine.Config struct when getting a
// mitmengine.Processor.
type S3 struct {
	bucket *s3.Bucket
}

// NewS3Instance creates S3 struct using configs loaded from environment variables
func NewS3Instance() (*S3, error) {
	accessKey, ok := os.LookupEnv("AWS_ACCESS_KEY_ID")
	if !ok {
		return nil, fmt.Errorf("environment variable '%s' not set", "AWS_ACCESS_KEY_ID")
	}
	secretKey, ok := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	if !ok {
		return nil, fmt.Errorf("environment variable '%s' not set", "AWS_SECRET_ACCESS_KEY")
	}
	endpoint, ok := os.LookupEnv("AWS_ENDPOINT")
	if !ok {
		return nil, fmt.Errorf("environment variable '%s' not set", "AWS_ENDPOINT")
	}
	bucketName, ok := os.LookupEnv("AWS_BUCKET_NAME")
	if !ok {
		return nil, fmt.Errorf("environment variable '%s' not set", "AWS_BUCKET_NAME")
	}

	auth, err := aws.GetAuth(strings.TrimSpace(string(accessKey)), strings.TrimSpace(string(secretKey)), "", time.Time{})
	if err != nil {
		return nil, fmt.Errorf("aws.GetAuth(): '%v'", err)
	}

	region := aws.Region{
		S3BucketEndpoint: fmt.Sprintf("https://%s.%s", bucketName, endpoint),
	}

	// use the bucket to pull fingerprint files
	mitmBucket := s3.New(auth, region).Bucket(bucketName)
	if mitmBucket == nil {
		return nil, fmt.Errorf("no bucket '%s' found at bucket endpoint '%s'", bucketName, endpoint)
	}
	return &S3{
		bucket: mitmBucket,
	}, nil
}

// LoadFile implements the LoadFile function specified in Loader interface, as defined in loader.go
func (s3Instance *S3) LoadFile(fileName string) (io.ReadCloser, error) {
	reader, err := s3Instance.bucket.GetReader(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %s", fileName, err)
	}
	return reader, nil
}
