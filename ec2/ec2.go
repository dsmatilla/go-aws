package ec2

import (
	"github.com/dsmatilla/aws"
)

func DescribeRegions(accessKey, secretKey string) string {
	request := aws.AwsRequest{accessKey, secretKey, "DescribeRegions","2013-10-15","GET","ec2", "us-east-1", "ec2.amazonaws.com","https://ec2.amazonaws.com"}
	result := aws.SendRequest(request)
	return result
}
