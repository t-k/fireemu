package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// The emulator host variables the Go SDKs used by this smoke read, as of the versions pinned in
// go.mod. Every one must be set: an unset variable sends that SDK to production.
//
//   - FIRESTORE_EMULATOR_HOST: cloud.google.com/go/firestore client.go (newClient) dials it over
//     plaintext gRPC after normalizeEmulatorAddress strips an http:// or https:// prefix.
//   - FIREBASE_AUTH_EMULATOR_HOST: firebase.google.com/go/v4 auth/auth.go (emulatorHostEnvVar)
//     builds "http://<value>/identitytoolkit.googleapis.com", so it must be a bare host:port.
//   - STORAGE_EMULATOR_HOST: cloud.google.com/go/storage storage.go and http_client.go (NewClient)
//     parse it as a URL when it contains "://" and otherwise prefix "http://".
//   - FIREBASE_STORAGE_EMULATOR_HOST: firebase.google.com/go/v4 storage/storage.go (NewClient)
//     copies it into STORAGE_EMULATOR_HOST when that one is empty.
var requiredHostVars = []hostVar{
	{name: "FIRESTORE_EMULATOR_HOST", allowHTTPURL: false},
	{name: "FIREBASE_AUTH_EMULATOR_HOST", allowHTTPURL: false},
	{name: "STORAGE_EMULATOR_HOST", allowHTTPURL: true},
	{name: "FIREBASE_STORAGE_EMULATOR_HOST", allowHTTPURL: false},
}

// Variables the same modules read on code paths this smoke does not take. They are not required,
// but a value that is set must still name a loopback emulator.
//
//   - STORAGE_EMULATOR_HOST_GRPC: cloud.google.com/go/storage grpc_client.go (NewGRPCClient).
//   - FIREBASE_DATABASE_EMULATOR_HOST: firebase.google.com/go/v4 db/db.go (emulatorDatabaseEnvVar).
var optionalHostVars = []hostVar{
	{name: "STORAGE_EMULATOR_HOST_GRPC", allowHTTPURL: false},
	{name: "FIREBASE_DATABASE_EMULATOR_HOST", allowHTTPURL: false},
}

type hostVar struct {
	name string
	// allowHTTPURL accepts "http://host:port" as well as a bare "host:port".
	allowHTTPURL bool
}

// checkEmulatorEnv refuses unless every emulator host variable the SDKs read is set to a
// loopback host with a numeric port and no userinfo. getenv is os.Getenv in production and a
// map lookup in the offline tests.
func checkEmulatorEnv(getenv func(string) string) error {
	var problems []string
	for _, v := range requiredHostVars {
		value := getenv(v.name)
		if value == "" {
			problems = append(problems, v.name+" is not set")
			continue
		}
		if err := checkHostValue(value, v.allowHTTPURL); err != nil {
			problems = append(problems, fmt.Sprintf("%s=%q: %v", v.name, value, err))
		}
	}
	for _, v := range optionalHostVars {
		value := getenv(v.name)
		if value == "" {
			continue
		}
		if err := checkHostValue(value, v.allowHTTPURL); err != nil {
			problems = append(problems, fmt.Sprintf("%s=%q: %v", v.name, value, err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("refusing to run outside a loopback emulator: %s", strings.Join(problems, "; "))
	}
	return nil
}

func checkHostValue(value string, allowHTTPURL bool) error {
	hostport := value
	if strings.Contains(value, "://") {
		if !allowHTTPURL {
			return fmt.Errorf("must be a bare host:port without a scheme")
		}
		u, err := url.Parse(value)
		if err != nil {
			return fmt.Errorf("not a URL: %v", err)
		}
		if u.Scheme != "http" {
			return fmt.Errorf("scheme must be http, not %q", u.Scheme)
		}
		if u.User != nil {
			return fmt.Errorf("must not carry userinfo")
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
			return fmt.Errorf("must not carry a path, query or fragment")
		}
		hostport = u.Host
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return fmt.Errorf("not host:port: %v", err)
	}
	// Base 10 with no sign, so "+80", "0x50" and "http" are refused along with 0 and 65536.
	// A userinfo, path, query or fragment in a bare value ends up in the host or the port and
	// is refused by these two checks.
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return fmt.Errorf("port %q is not a number in 1..65535", port)
	}
	if !isLoopback(host) {
		return fmt.Errorf("host %q is not loopback", host)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
