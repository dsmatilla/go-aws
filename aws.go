package aws

import (
	"fmt"
	"net/http"
	"time"
	"crypto/sha256"
	"crypto/hmac"
	"net/url"
	"encoding/hex"
	"io/ioutil"
)

type AwsRequest struct {
	AccessKey, SecretKey, Action, Version, Method, Service, Region, Host, Endpoint string
}

func sign(key []byte, data string) []byte {
	sign := hmac.New(sha256.New, []byte(key))
	sign.Write([]byte(data))
	return sign.Sum(nil)
}

func getSignatureKey(string_to_sign, key, datestamp, region, service string) string {
	seed := "AWS4" + key
	kdate := sign([]byte(seed), datestamp)
	kregion := sign(kdate, region)
	kservice := sign(kregion, service)
	ksigning := sign(kservice, "aws4_request")
	signature := sign(ksigning, string_to_sign);
	return hex.EncodeToString(signature)
}

func SendRequest(data AwsRequest) string {
	// Timestamps
	t := time.Now()
	amzdate := fmt.Sprintf("%04d%02d%02dT%02d%02d%02dZ",t.Year(),t.Month(),t.Day(),t.Hour() - 2,t.Minute(),t.Second())
	datestamp := fmt.Sprintf("%04d%02d%02d",t.Year(),t.Month(),t.Day())

	// Create canonical request
	ep, _ := url.Parse(data.Endpoint)
	canonical_uri := "/" + ep.Path

	canonical_querystring := "Action=" + data.Action + "&Version=" + data.Version
	canonical_headers := "host:" + data.Host + "\n" + "x-amz-date:" + amzdate + "\n"
	signed_headers := "host;x-amz-date"

	// Set Payload sha256 hash
	byte_hash := sha256.Sum256([]byte(canonical_querystring))
	if data.Method == "GET" {
		byte_hash = sha256.Sum256(nil)
	}
	payload_hash := fmt.Sprintf("%x", byte_hash)

	// Build canonical request
	canonical_request := data.Method + "\n"
	canonical_request = canonical_request + canonical_uri + "\n"
	if data.Method == "GET" {
		canonical_request = canonical_request + canonical_querystring
	}
	canonical_request = canonical_request + "\n"
	canonical_request = canonical_request + canonical_headers + "\n"
	canonical_request = canonical_request + signed_headers + "\n"
	canonical_request = canonical_request + payload_hash

	//Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credential_scope := datestamp + "/" + data.Region + "/" + data.Service + "/aws4_request"
	request_hash_byte := sha256.Sum256([]byte(canonical_request))
	request_hash := fmt.Sprintf("%x", request_hash_byte)
	string_to_sign := algorithm + "\n" + amzdate + "\n" + credential_scope + "\n" + request_hash

	// Calculate the signature
	signature := getSignatureKey(string_to_sign, data.SecretKey, datestamp, data.Region, data.Service)

	// ADD SIGNING INFORMATION TO THE REQUEST
	authorization_header := algorithm + " " + "Credential=" + data.AccessKey + "/" + credential_scope + ", ";
	authorization_header += "SignedHeaders=" + signed_headers + ", ";
	authorization_header += "Signature=" + signature;

	// Start HTTP client
	client := &http.Client{}

	// Build request
	request, _ := http.NewRequest(data.Method, data.Endpoint + "?" + canonical_querystring, nil)

	// Add headers
	request.Header.Add("x-amz-date", amzdate)
	request.Header.Add("Authorization", authorization_header)

	// Execute request
	response, _ := client.Do(request)
	defer response.Body.Close()

	body, _ := ioutil.ReadAll(response.Body)
	xml := fmt.Sprintf("%s", body)
	return xml
}