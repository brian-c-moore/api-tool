package auth

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"regexp"
	"strings"

	"api-tool/internal/logging"
)

// ErrDigestFIPSCompliance indicates a failure due to FIPS mode disallowing offered algorithms.
var ErrDigestFIPSCompliance = fmt.Errorf("server offered only non-FIPS compliant Digest algorithms (MD5) while FIPS mode is enabled")

// ErrDigestUnsupported indicates the server offered no algorithms supported by the client.
var ErrDigestUnsupported = fmt.Errorf("server offered no Digest algorithms supported by the client")

// ErrDigestQopUnsupported indicates the server requires an unsupported QOP.
var ErrDigestQopUnsupported = fmt.Errorf("server requires an unsupported QOP value")


// digestChallenge holds parsed values from the WWW-Authenticate header.
type digestChallenge struct {
	Realm      string
	Nonce      string
	Opaque     string
	Algorithm  string
	QopOptions []string
	Stale      bool
}

// DigestAuthRoundTripper implements http.RoundTripper for Digest authentication.
type DigestAuthRoundTripper struct {
	Username string
	Password string
	FipsMode bool
	Next     http.RoundTripper
}

// RoundTrip handles the Digest challenge-response flow.
func (rt *DigestAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	logging.Logf(logging.Debug, "Digest RT: Making initial request to %s", req.URL)
	resp, err := rt.Next.RoundTrip(req)
	if err != nil { return nil, err }

	if resp.StatusCode != http.StatusUnauthorized {
		logging.Logf(logging.Debug, "Digest RT: Initial request status %d, not 401. Passing through.", resp.StatusCode)
		return resp, nil
	}

	authHeader := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(strings.ToLower(authHeader), "digest ") {
		logging.Logf(logging.Debug, "Digest RT: Received 401, but WWW-Authenticate header is missing or not Digest ('%s'). Passing through 401.", authHeader)
		return resp, nil
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	logging.Logf(logging.Debug, "Digest RT: Received 401 Digest challenge: %s", authHeader)

	challenge, err := parseDigestChallenge(authHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Digest challenge header '%s': %w", authHeader, err)
	}

	selectedAlgo, selectedQop, err := rt.selectAlgorithmAndQop(challenge)
	if err != nil { return nil, err }
	logging.Logf(logging.Info, "Digest RT: Selected Algorithm: %s, QOP: %s (FIPS Mode: %v)", selectedAlgo, selectedQop, rt.FipsMode)

	nc := uint32(1)
	cnonce, err := generateCNonce()
	if err != nil { return nil, fmt.Errorf("failed to generate cnonce: %w", err) }

	authResp, err := calculateDigestResponse(rt.Username, rt.Password, req.Method, req.URL.RequestURI(), req.Body, req.GetBody,
		challenge.Realm, challenge.Nonce, selectedAlgo, selectedQop, nc, cnonce)
	if err != nil { return nil, fmt.Errorf("failed to calculate Digest response: %w", err) }

	authzHeader := formatDigestAuthorization(rt.Username, challenge.Realm, challenge.Nonce, challenge.Opaque,
		req.URL.RequestURI(), selectedAlgo, selectedQop, nc, cnonce, authResp)

	authedReq := req.Clone(req.Context())
	authedReq.Header.Set("Authorization", authzHeader)

	// Handle Body for the second request
	if req.Body != nil && req.GetBody == nil {
		logging.Logf(logging.Warning, "Digest RT: Original request body exists but GetBody is nil. Body might not be sent correctly on authenticated request.")
		if seeker, ok := req.Body.(io.Seeker); ok {
			_, seekErr := seeker.Seek(0, io.SeekStart)
			if seekErr == nil { authedReq.Body = req.Body } else { authedReq.Body = nil; authedReq.ContentLength = 0 }
		} else { authedReq.Body = nil; authedReq.ContentLength = 0 }
	} else if req.GetBody != nil {
		newBody, gbErr := req.GetBody()
		// <<< FIX: Lowercase error message start >>>
		if gbErr != nil { return nil, fmt.Errorf("digest RT: failed GetBody for authenticated request: %w", gbErr) }
		authedReq.Body = newBody
		authedReq.ContentLength = req.ContentLength
	} else {
		authedReq.Body = nil
		authedReq.ContentLength = 0
	}

	logging.Logf(logging.Debug, "Digest RT: Making authenticated request to %s with header: %s", authedReq.URL, authzHeader)
	finalResp, finalErr := rt.Next.RoundTrip(authedReq)
	if finalErr != nil { return nil, finalErr }

	logging.Logf(logging.Debug, "Digest RT: Authenticated request returned status %d", finalResp.StatusCode)
	return finalResp, nil
}

func (rt *DigestAuthRoundTripper) selectAlgorithmAndQop(challenge *digestChallenge) (string, string, error) {
	// Algorithm Selection
	offeredAlgoUpper := strings.ToUpper(challenge.Algorithm)
	selectedAlgo := ""
	if offeredAlgoUpper == "SHA-256-SESS" { selectedAlgo = "SHA-256-sess" } else
	if offeredAlgoUpper == "SHA-256" { selectedAlgo = "SHA-256" } else
	if !rt.FipsMode {
		if offeredAlgoUpper == "MD5-SESS" { selectedAlgo = "MD5-sess" } else
		if offeredAlgoUpper == "MD5" || offeredAlgoUpper == "" { selectedAlgo = "MD5" }
	}

	isMD5Selected := selectedAlgo == "MD5" || selectedAlgo == "MD5-sess"
	if rt.FipsMode && isMD5Selected { return "", "", ErrDigestFIPSCompliance }
	if selectedAlgo == "" {
		if rt.FipsMode && (offeredAlgoUpper == "MD5" || offeredAlgoUpper == "MD5-SESS" || offeredAlgoUpper == "") {
			return "", "", ErrDigestFIPSCompliance
		}
		return "", "", fmt.Errorf("%w: server offered '%s'", ErrDigestUnsupported, challenge.Algorithm)
	}

	// QOP Selection
	selectedQop := ""
	hasAuthInt := false
	hasAuth := false
	for _, qop := range challenge.QopOptions {
		if qop == "auth-int" { hasAuthInt = true }
		if qop == "auth" { hasAuth = true }
	}

	if hasAuthInt { selectedQop = "auth-int" } else
	if hasAuth { selectedQop = "auth" }

	if len(challenge.QopOptions) > 0 && selectedQop == "" {
		 return "", "", fmt.Errorf("%w: server offered QOP(s) '%s'", ErrDigestQopUnsupported, strings.Join(challenge.QopOptions, ","))
	}
	return selectedAlgo, selectedQop, nil
}

var digestParamRegex = regexp.MustCompile(`([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^",\s]+))`)

func parseDigestChallenge(header string) (*digestChallenge, error) {
	prefix := "digest "
	if !strings.HasPrefix(strings.ToLower(header), prefix) {
		return nil, fmt.Errorf("invalid Digest header prefix: %s", header)
	}
	headerValue := strings.TrimSpace(header[len(prefix):])
	if headerValue == "" { return nil, fmt.Errorf("empty Digest challenge parameters") }

	params := make(map[string]string)
	matches := digestParamRegex.FindAllStringSubmatch(headerValue, -1)
	if matches == nil {
		return nil, fmt.Errorf("could not parse any parameters from Digest challenge")
	}

	for _, match := range matches {
		key := strings.ToLower(match[1])
		value := match[2]; if value == "" { value = match[3] }
		params[key] = value
	}

	var qopOptions []string
	if qopVal, ok := params["qop"]; ok {
		 for _, qop := range strings.Split(qopVal, ",") {
			 trimmedQop := strings.ToLower(strings.TrimSpace(qop))
			 if trimmedQop == "auth" || trimmedQop == "auth-int" {
				 qopOptions = append(qopOptions, trimmedQop)
			 }
		 }
	}

	challenge := &digestChallenge{
		Realm:       params["realm"], Nonce:       params["nonce"], Opaque:      params["opaque"],
		Algorithm:   params["algorithm"], Stale:       strings.ToLower(params["stale"]) == "true", QopOptions:  qopOptions,
	}

	if challenge.Realm == "" || challenge.Nonce == "" {
		return nil, fmt.Errorf("missing required Digest parameters (realm or nonce)")
	}
	return challenge, nil
}

func generateCNonce() (string, error) {
	b := make([]byte, 8); _, err := rand.Read(b); if err != nil { return "", err }; return hex.EncodeToString(b), nil
}
func h(hasher hash.Hash, data string) string {
	hasher.Reset(); _, _ = hasher.Write([]byte(data)); return hex.EncodeToString(hasher.Sum(nil))
}
func kd(hasher hash.Hash, ha1, nonce, nc, cnonce, qop, ha2 string) string {
	return h(hasher, fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, qop, ha2))
}

func calculateDigestResponse(
	username, password, method, uri string,
	body io.ReadCloser, getBody func() (io.ReadCloser, error),
	realm, nonce, selectedAlgorithm, selectedQop string,
	nc uint32, cnonce string,
) (string, error) {
	var hasher hash.Hash
	algoUpper := strings.ToUpper(selectedAlgorithm)
	switch algoUpper {
	case "MD5", "MD5-SESS": hasher = md5.New()
	case "SHA-256", "SHA-256-SESS": hasher = sha256.New()
	default: return "", fmt.Errorf("internal error: unsupported Digest algorithm selected: %s", selectedAlgorithm)
	}

	ha1 := h(hasher, fmt.Sprintf("%s:%s:%s", username, realm, password))
	if strings.HasSuffix(algoUpper, "-SESS") { ha1 = h(hasher, fmt.Sprintf("%s:%s:%s", ha1, nonce, cnonce)) }

	var ha2 string
	if selectedQop == "auth-int" {
		var bodyBytes []byte; var readErr error
		if getBody != nil {
			bodyReader, gbErr := getBody(); if gbErr != nil { return "", fmt.Errorf("failed get body for auth-int: %w", gbErr) }
			bodyBytes, readErr = io.ReadAll(bodyReader); bodyReader.Close()
		} else if body != nil {
			logging.Logf(logging.Warning, "Calculating Digest auth-int without GetBody, body will be consumed.")
			bodyBytes, readErr = io.ReadAll(body); body.Close()
		}
		if readErr != nil { return "", fmt.Errorf("failed read body for auth-int: %w", readErr) }
		hasher.Reset(); _, _ = hasher.Write(bodyBytes); bodyHash := hex.EncodeToString(hasher.Sum(nil))
		ha2 = h(hasher, fmt.Sprintf("%s:%s:%s", method, uri, bodyHash))
	} else { ha2 = h(hasher, fmt.Sprintf("%s:%s", method, uri)) }

	var response string
	ncString := fmt.Sprintf("%08x", nc)
	if selectedQop == "auth" || selectedQop == "auth-int" {
		response = kd(hasher, ha1, nonce, ncString, cnonce, selectedQop, ha2)
	} else { response = h(hasher, fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2)) }
	return response, nil
}

func formatDigestAuthorization(
	username, realm, nonce, opaque, uri string,
	selectedAlgorithm, selectedQop string,
	nc uint32, cnonce string,
	response string,
) string {
	parts := []string{
		fmt.Sprintf(`username="%s"`, username), fmt.Sprintf(`realm="%s"`, realm), fmt.Sprintf(`nonce="%s"`, nonce),
		fmt.Sprintf(`uri="%s"`, uri), fmt.Sprintf(`response="%s"`, response),
	}
	if selectedAlgorithm != "" && (selectedAlgorithm != "MD5" || selectedQop != "") {
		 parts = append(parts, fmt.Sprintf(`algorithm=%s`, selectedAlgorithm))
	}
	if opaque != "" { parts = append(parts, fmt.Sprintf(`opaque="%s"`, opaque)) }
	if selectedQop != "" {
		parts = append(parts, fmt.Sprintf(`qop=%s`, selectedQop))
		parts = append(parts, fmt.Sprintf(`nc=%08x`, nc))
		parts = append(parts, fmt.Sprintf(`cnonce="%s"`, cnonce))
	}
	return "Digest " + strings.Join(parts, ", ")
}