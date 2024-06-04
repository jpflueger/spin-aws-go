package main

import (
	"fmt"
	"net/http"
	"net/url"

	spinhttp "github.com/fermyon/spin/sdk/go/v2/http"
	"github.com/jpflueger/spin-aws-go/signers"
)

const objectContent = `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc tortor metus, sagittis eget augue ut,\n 
feugiat vehicula risus. Integer tortor mauris, vehicula nec mollis et, consectetur eget tortor. In ut\n
elit sagittis, ultrices est ut, iaculis turpis. In hac habitasse platea dictumst. Donec laoreet tellus\n 
at auctor tempus. Praesent nec diam sed urna sollicitudin vehicula eget id est. Vivamus sed laoreet\n
lectus. Aliquam convallis condimentum risus, vitae porta justo venenatis vitae. Phasellus vitae nunc\n 
varius, volutpat quam nec, mollis urna. Donec tempus, nisi vitae gravida facilisis, sapien sem malesuada\n
purus, id semper libero ipsum condimentum nulla. Suspendisse vel mi leo. Morbi pellentesque placerat congue.\n
Nunc sollicitudin nunc diam, nec hendrerit dui commodo sed. Duis dapibus commodo elit, id commodo erat\n
congue id. Aliquam erat volutpat.\n`

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {

		bucketName := ""
		objectKey := ""
		region := ""
		service := "s3"
		awsAccessKey := ""
		awsSecretKey := ""

		var regionUrlPart string
		if region != "" {
			if region != "us-east-1" {
				regionUrlPart = "-" + region
			}
		}

		endpointUriStr := fmt.Sprintf("https://%s.s3%s.amazonaws.com/%s", bucketName, regionUrlPart, objectKey)
		endpointUri, err := url.Parse(endpointUriStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to parse generated s3 url: %s", endpointUriStr), http.StatusInternalServerError)
		}

		signer := signers.NewAWS4SignerForAuthorizationHeader(
			*endpointUri,
			http.MethodPut,
			service,
			region,
		)

		contentHash := signer.HashSHA256(objectContent)
		headers := map[string]string{
			signers.X_Amz_Content_SHA256: contentHash,
			"content-length":             string(len(objectContent)),
			"content-type":               "text/plain",
		}
		authorization := signer.ComputeSignature(
			headers,
			"", // no headers
			contentHash,
			awsAccessKey,
			awsSecretKey,
		)

		headers["Authorization"] = authorization

		//TODO: actually make an http request

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Hello Fermyon!")
	})
}

func main() {}
