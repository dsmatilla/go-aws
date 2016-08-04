package iam

import (
	"github.com/dsmatilla/go-aws"
)

func GetAccountSummary(accessKey, secretKey string) string {
	request := aws.AwsRequest{accessKey, secretKey, "GetAccountSummary", "2010-05-08", "GET", "iam", "us-east-1", "iam.amazonaws.com", "https://iam.amazonaws.com"}
	result := aws.SendRequest(request)
	return result
}