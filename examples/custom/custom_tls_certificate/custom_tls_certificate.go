package main

import (
	"crypto/x509"
	"fmt"
	"log"

	"github.com/enetx/surf"
)

func main() {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	cert := []byte(`-----BEGIN CERTIFICATE-----
MIIDqDCCApCgAwIBAgIFAIFlYTIwDQYJKoZIhvcNAQELBQAwgYoxFDASBgNVBAYT
C1BvcnRTd2lnZ2VyMRQwEgYDVQQIEwtQb3J0U3dpZ2dlcjEUMBIGA1UEBxMLUG9y
dFN3aWdnZXIxFDASBgNVBAoTC1BvcnRTd2lnZ2VyMRcwFQYDVQQLEw5Qb3J0U3dp
Z2dlciBDQTEXMBUGA1UEAxMOUG9ydFN3aWdnZXIgQ0EwHhcNMTQwNTE2MTcxNDAw
WhcNMzAwNTE2MTgxNDAwWjCBijEUMBIGA1UEBhMLUG9ydFN3aWdnZXIxFDASBgNV
BAgTC1BvcnRTd2lnZ2VyMRQwEgYDVQQHEwtQb3J0U3dpZ2dlcjEUMBIGA1UEChML
UG9ydFN3aWdnZXIxFzAVBgNVBAsTDlBvcnRTd2lnZ2VyIENBMRcwFQYDVQQDEw5Q
b3J0U3dpZ2dlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8t
0IyyENgCuW0ce/G5iI/zy0/pBaK6Db8NNGREyyZsAlFUWZk4oqAhtUfUADL+HmHU
II9RKUoNNiX8pFPkRrO79QhwFlfZshUIComyUxocebuao8JLzlKiCk7SuE04UsGh
404MkhXzXX5qUDmWJSvKs+yrg8k0sQOfY2lCzb8Fz8hW75CYaMVwOtA/5B4njqdi
sSYQ8uPu0jqEOE+a2ypeiPRLcuX7quHH+oCzpxFVuKG2+1coNDKXxzOKX/GI8y8P
EYbL7EQZzr0rO5aGqaebGfoPPe7CELFo3sZPgMTRlPj+hRI2rxKBYB4X5u+Kosau
HNpTQHQTZNnJWkOKDqMCAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOCAQEAdlYIkmgWGXm7aOYZU1XNoS3JBwIJmTEcYiS/z81uYFJLaE3n
rsKGxOo3d5jCFt7kl/aQGSmh5rcyW/lhLjPtoYbURvSMtv/CxN0XE6w3f4ATPcDS
QZPR0iQy5dnHkVokgcmk66vRJAydYxiCke9FM2xU7UIqL0y5xjDoXQ1el9uJ+4Mm
IO/7xqy0faXRRvcYFPBA3uF4IUPRdofJYg+ghe45vpPt0hzn9kVf5dc3+wzn1vgs
PB0KuEzBx1LQzkE8M0MToiGLsR2iK7x1KsWqbf7+5Y2Zqm5qmOfDm+71WnmIprnU
+6w+hqeKM4+ZUyrQWqK4unh2SEI8CJMZ2lNamQ==
-----END CERTIFICATE-----`)

	rootCAs.AppendCertsFromPEM(cert)

	cli := surf.NewClient()

	tc := cli.GetTLSConfig()
	tc.InsecureSkipVerify = false
	tc.RootCAs = rootCAs

	r := cli.Get("https://www.google.com").Do()
	if r.IsErr() {
		log.Fatal(r.Err())
	}

	fmt.Println(r.Ok().Body.String().Unwrap())
}
