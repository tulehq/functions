// Command s3put is a test function that writes an object with the AWS SDK's
// default configuration: the credentials, region and S3 endpoint
// (AWS_ENDPOINT_URL_S3) its environment gives it, as a function's SDK takes
// its execution role's credentials. It answers the error the put met, if
// any, so a test can tell a denied put from a successful one.
package main

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

type request struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
	Body   string `json:"body"`
}

type response struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func handler(ctx context.Context, req request) (response, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return response{}, err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.RetryMaxAttempts = 1
	})
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(req.Bucket),
		Key:    aws.String(req.Key),
		Body:   strings.NewReader(req.Body),
	})
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return response{Code: apiErr.ErrorCode(), Message: apiErr.ErrorMessage()}, nil
	}
	return response{}, err
}

func main() {
	lambda.Start(handler)
}
