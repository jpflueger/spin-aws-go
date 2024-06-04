package signers

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS4SignerForAuthorizationHeader represents a sample AWS4 signer for signing requests to Amazon S3
type AWS4SignerForAuthorizationHeader struct {
	*AWS4SignerBase
}

// NewAWS4SignerForAuthorizationHeader initializes and returns a new AWS4SignerForAuthorizationHeader instance
func NewAWS4SignerForAuthorizationHeader(endpointUri url.URL, httpMethod string, service string, region string) *AWS4SignerForAuthorizationHeader {
	return &AWS4SignerForAuthorizationHeader{NewAWS4SignerBase(endpointUri, httpMethod, service, region)}
}

// ComputeSignature computes an AWS4 signature for a request, ready for inclusion as an 'Authorization' header
func (s *AWS4SignerForAuthorizationHeader) ComputeSignature(headers map[string]string, queryParameters, bodyHash, awsAccessKey, awsSecretKey string) string {
	// first get the date and time for the subsequent request, and convert to ISO 8601 format
	// for use in signature generation
	requestDateTime := time.Now().UTC()
	dateTimeStamp := requestDateTime.Format(ISO8601BasicFormat)

	// update the headers with required 'x-amz-date' and 'host' values
	headers[X_Amz_Date] = dateTimeStamp

	hostHeader := s.EndpointUri.Host

	if s.EndpointUri.Port() != "" {
		hostHeader += ":" + s.EndpointUri.Port()
	}
	headers["Host"] = hostHeader

	// canonicalize the headers; we need the set of header names as well as the
	// names and values to go into the signature process
	canonicalizedHeaderNames := s.CanonicalizeHeaderNames(headers)
	canonicalizedHeaders := s.CanonicalizeHeaders(headers)

	// if any query string parameters have been supplied, canonicalize them
	// (note this sample assumes any required url encoding has been done already)
	canonicalizedQueryParameters := ""
	if queryParameters != "" {
		paramDictionary := make(map[string]string)
		for _, param := range strings.Split(queryParameters, "&") {
			nameVal := strings.Split(param, "=")
			paramDictionary[nameVal[0]] = ""
			if len(nameVal) > 1 {
				paramDictionary[nameVal[0]] = nameVal[1]
			}
		}

		var paramKeys []string
		for k := range paramDictionary {
			paramKeys = append(paramKeys, k)
		}
		sort.Strings(paramKeys)

		var sb strings.Builder
		for i, p := range paramKeys {
			if i > 0 {
				sb.WriteString("&")
			}
			sb.WriteString(fmt.Sprintf("%s=%s", p, paramDictionary[p]))
		}

		canonicalizedQueryParameters = sb.String()
	}

	// canonicalize the various components of the request
	canonicalRequest := s.CanonicalizeRequest(canonicalizedQueryParameters, canonicalizedHeaderNames, canonicalizedHeaders, bodyHash)
	fmt.Printf("\nCanonicalRequest:\n%s\n", canonicalRequest)

	// generate a hash of the canonical request, to go into signature computation
	canonicalRequestHashBytes := CanonicalRequestHashAlgorithm.New()
	canonicalRequestHashBytes.Write([]byte(canonicalRequest))

	// construct the string to be signed
	var stringToSign strings.Builder

	dateStamp := requestDateTime.Format(DateStringFormat)
	scope := fmt.Sprintf("%s/%s/%s/%s", dateStamp, s.Region, s.Service, TERMINATOR)

	stringToSign.WriteString(fmt.Sprintf("%s-%s\n%s\n%s\n", SCHEME, ALGORITHM, dateTimeStamp, scope))
	stringToSign.WriteString(hex.EncodeToString(canonicalRequestHashBytes.Sum(nil)))

	fmt.Printf("\nStringToSign:\n%s\n", stringToSign.String())

	// compute the signing key
	signingKey := s.DeriveSigningKey(HMACSHA256, awsSecretKey, s.Region, dateStamp, s.Service)

	// compute the AWS4 signature and return it
	h := hmac.New(CanonicalRequestHashAlgorithm.New, signingKey)
	h.Write([]byte(stringToSign.String()))
	signature := h.Sum(nil)
	signatureString := hex.EncodeToString(signature)
	fmt.Printf("\nSignature:\n%s\n", signatureString)

	authString := fmt.Sprintf("%s-%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		SCHEME, ALGORITHM, awsAccessKey, scope, canonicalizedHeaderNames, signatureString)

	authorization := authString
	fmt.Printf("\nAuthorization:\n%s\n", authorization)

	return authorization
}
