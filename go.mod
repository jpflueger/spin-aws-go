module github.com/jpflueger/spin-aws-go

go 1.22.2

require (
	github.com/fermyon/spin/sdk/go/v2 v2.2.0
	github.com/jpflueger/spin-aws-go/signers v0.0.0-00010101000000-000000000000
)

require github.com/julienschmidt/httprouter v1.3.0 // indirect

replace github.com/jpflueger/spin-aws-go/signers => ./signers
