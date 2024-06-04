package signers

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	EMPTY_BODY_SHA256             = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	SCHEME                        = "AWS4"
	ALGORITHM                     = "HMAC-SHA256"
	TERMINATOR                    = "aws4_request"
	ISO8601BasicFormat            = "yyyyMMddTHHmmssZ"
	DateStringFormat              = "yyyyMMdd"
	X_Amz_Algorithm               = "X-Amz-Algorithm"
	X_Amz_Credential              = "X-Amz-Credential"
	X_Amz_SignedHeaders           = "X-Amz-SignedHeaders"
	X_Amz_Date                    = "X-Amz-Date"
	X_Amz_Signature               = "X-Amz-Signature"
	X_Amz_Expires                 = "X-Amz-Expires"
	X_Amz_Content_SHA256          = "X-Amz-Content-SHA256"
	X_Amz_Decoded_Content_Length  = "X-Amz-Decoded-Content-Length"
	X_Amz_Meta_UUID               = "X-Amz-Meta-UUID"
	HMACSHA256                    = "HMACSHA256"
	CanonicalRequestHashAlgorithm = crypto.SHA256
)

// AWS4SignerBase defines common methods and properties for all AWS4 signer variants
type AWS4SignerBase struct {
	EndpointUri             url.URL
	HttpMethod              string
	Service                 string
	Region                  string
	compressWhitespaceRegex *regexp.Regexp
}

// NewAWS4SignerBase initializes and returns a new AWS4SignerBase instance
func NewAWS4SignerBase(endpointUri url.URL, httpMethod string, service string, region string) *AWS4SignerBase {
	return &AWS4SignerBase{
		EndpointUri:             endpointUri,
		HttpMethod:              httpMethod,
		Service:                 service,
		Region:                  region,
		compressWhitespaceRegex: regexp.MustCompile(`\\s+`),
	}
}

// CanonicalizeHeaderNames returns the canonical collection of header names that will be included in the signature
func (s *AWS4SignerBase) CanonicalizeHeaderNames(headers map[string]string) string {
	headerNames := make([]string, 0, len(headers))
	for header := range headers {
		headerNames = append(headerNames, header)
	}
	sort.Strings(headerNames)

	var sb strings.Builder
	for i, header := range headerNames {
		if i > 0 {
			sb.WriteString(";")
		}
		sb.WriteString(strings.ToLower(header))
	}
	return sb.String()
}

// CanonicalizeHeaders computes the canonical headers with values for the request
func (s *AWS4SignerBase) CanonicalizeHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}

	// step1: sort the headers into lower-case format; we create a new
	// map to ensure we can do a subsequent key lookup using a lower-case
	// key regardless of how 'headers' was created.
	sortedHeaderMap := make(map[string]string)
	for header, value := range headers {
		sortedHeaderMap[strings.ToLower(header)] = value
	}

	// step2: form the canonical header:value entries in sorted order.
	// Multiple white spaces in the values should be compressed to a single
	// space.
	var sb strings.Builder
	for header, value := range sortedHeaderMap {
		headerValue := s.compressWhitespaceRegex.ReplaceAllString(value, " ")
		sb.WriteString(header)
		sb.WriteString(":")
		sb.WriteString(headerValue)
		sb.WriteString("\n")
	}

	return sb.String()
}

// CanonicalizeRequest returns the canonical request string to go into the signer process
func (s *AWS4SignerBase) CanonicalizeRequest(queryParameters, canonicalizedHeaderNames, canonicalizedHeaders, bodyHash string) string {
	var canonicalRequest bytes.Buffer

	canonicalRequest.WriteString(s.HttpMethod)
	canonicalRequest.WriteString("\n")
	canonicalRequest.WriteString(s.CanonicalResourcePath(&s.EndpointUri))
	canonicalRequest.WriteString("\n")
	canonicalRequest.WriteString(queryParameters)
	canonicalRequest.WriteString("\n")
	canonicalRequest.WriteString(canonicalizedHeaders)
	canonicalRequest.WriteString("\n")
	canonicalRequest.WriteString(canonicalizedHeaderNames)
	canonicalRequest.WriteString("\n")
	canonicalRequest.WriteString(bodyHash)

	return canonicalRequest.String()
}

// CanonicalResourcePath returns the canonicalized resource path for the service endpoint
func (s *AWS4SignerBase) CanonicalResourcePath(endpointURL *url.URL) string {
	if endpointURL.Path == "" {
		return "/"
	}
	return endpointURL.Path
}

// DeriveSigningKey computes and returns the multi-stage signing key for the request
func (s *AWS4SignerBase) DeriveSigningKey(algorithm, awsSecretAccessKey, region, date, service string) []byte {
	ksecretPrefix := SCHEME
	ksecret := []byte(ksecretPrefix + awsSecretAccessKey)

	hashDate := s.ComputeKeyedHash(algorithm, ksecret, []byte(date))
	hashRegion := s.ComputeKeyedHash(algorithm, hashDate, []byte(region))
	hashService := s.ComputeKeyedHash(algorithm, hashRegion, []byte(service))
	return s.ComputeKeyedHash(algorithm, hashService, []byte(TERMINATOR))
}

// ComputeKeyedHash computes and returns the hash of a data blob using the specified algorithm and key
func (s *AWS4SignerBase) ComputeKeyedHash(algorithm string, key, data []byte) []byte {
	hash := hmac.New(CanonicalRequestHashAlgorithm.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// ToHexString formats a byte array into string
func (s *AWS4SignerBase) ToHexString(data []byte, lowercase bool) string {
	return hex.EncodeToString(data)
}

// HashSHA256 computes SHA256 hash of the input string
func (s *AWS4SignerBase) HashSHA256(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// URLSigner is a struct to represent an URL signer
type URLSigner struct {
	*AWS4SignerBase
}

// NewURLSigner initializes and returns a new URLSigner instance
func NewURLSigner(endpointUri url.URL, httpMethod string, service string, region string) *URLSigner {
	return &URLSigner{NewAWS4SignerBase(endpointUri, httpMethod, service, region)}
}

// SignURL returns a signed URL
func (s *URLSigner) SignURL(accessKey, secretKey, region, service string, expires time.Time) string {
	// You can set other query parameters here as needed.
	queryParams := s.EndpointUri.Query()
	queryParams.Set(X_Amz_Date, expires.UTC().Format(ISO8601BasicFormat))
	s.EndpointUri.RawQuery = queryParams.Encode()

	canonicalRequest := s.CanonicalizeRequest(
		// "GET", why is this hard-coded?
		s.EndpointUri.RawQuery,
		"", // No headers
		"", // No headers
		"", // No body hash
	)

	credentialScope := s.CredentialScope(expires, region, service)
	stringToSign := s.StringToSign(canonicalRequest, credentialScope, expires)

	signingKey := s.DeriveSigningKey(HMACSHA256, secretKey, region, expires.Format(DateStringFormat), service)
	signature := s.Sign(stringToSign, signingKey)

	queryParams.Set(X_Amz_Algorithm, SCHEME+"-"+ALGORITHM)
	queryParams.Set(X_Amz_Credential, accessKey+"/"+credentialScope)
	queryParams.Set(X_Amz_Expires, strconv.FormatInt(expires.UTC().Unix()-time.Now().UTC().Unix(), 10))
	queryParams.Set(X_Amz_Signature, signature)

	s.EndpointUri.RawQuery = queryParams.Encode()
	return s.EndpointUri.String()
}

// CredentialScope returns the credential scope
func (s *AWS4SignerBase) CredentialScope(date time.Time, region, service string) string {
	return date.UTC().Format(DateStringFormat) + "/" + region + "/" + service + "/" + TERMINATOR
}

// StringToSign returns the string to sign
func (s *AWS4SignerBase) StringToSign(canonicalRequest, credentialScope string, date time.Time) string {
	return ALGORITHM + "\n" + date.UTC().Format(ISO8601BasicFormat) + "\n" + credentialScope + "\n" + s.HashSHA256(canonicalRequest)
}

// Sign returns the signature
func (s *AWS4SignerBase) Sign(stringToSign string, signingKey []byte) string {
	signature := s.ComputeKeyedHash(HMACSHA256, signingKey, []byte(stringToSign))
	return s.ToHexString(signature, true)
}
