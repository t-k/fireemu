package main

import (
	"strings"
	"testing"
)

func validEnv() map[string]string {
	return map[string]string{
		"FIRESTORE_EMULATOR_HOST":        "127.0.0.1:8080",
		"FIREBASE_AUTH_EMULATOR_HOST":    "127.0.0.1:9099",
		"STORAGE_EMULATOR_HOST":          "http://127.0.0.1:9199",
		"FIREBASE_STORAGE_EMULATOR_HOST": "127.0.0.1:9199",
	}
}

func check(env map[string]string) error {
	return checkEmulatorEnv(func(name string) string { return env[name] })
}

func TestGuardAcceptsTheExecEnvironment(t *testing.T) {
	if err := check(validEnv()); err != nil {
		t.Fatalf("valid environment refused: %v", err)
	}
}

func TestGuardAcceptsOtherLoopbackSpellings(t *testing.T) {
	for _, value := range []string{"localhost:8080", "[::1]:8080", "127.0.0.2:8080", "127.255.255.254:65535"} {
		env := validEnv()
		env["FIRESTORE_EMULATOR_HOST"] = value
		env["FIREBASE_AUTH_EMULATOR_HOST"] = value
		env["FIREBASE_STORAGE_EMULATOR_HOST"] = value
		env["STORAGE_EMULATOR_HOST"] = value
		if err := check(env); err != nil {
			t.Errorf("%q refused: %v", value, err)
		}
		env["STORAGE_EMULATOR_HOST"] = "http://" + value + "/"
		if err := check(env); err != nil {
			t.Errorf("http://%s/ refused: %v", value, err)
		}
	}
}

func TestGuardRequiresEveryVariable(t *testing.T) {
	for name := range validEnv() {
		env := validEnv()
		delete(env, name)
		err := check(env)
		if err == nil || !strings.Contains(err.Error(), name+" is not set") {
			t.Errorf("missing %s: got %v", name, err)
		}
	}
}

func TestGuardRefusesBadValues(t *testing.T) {
	bad := map[string][]string{
		"FIRESTORE_EMULATOR_HOST": {
			"firestore.googleapis.com:443", "10.0.0.1:8080", "0.0.0.0:8080", "[::]:8080",
			"127.0.0.1", "127.0.0.1:", "127.0.0.1:http", "127.0.0.1:+80", "127.0.0.1:0",
			"127.0.0.1:65536", "127.0.0.1:0x50", "user@127.0.0.1:8080", "http://127.0.0.1:8080",
			"127.0.0.1:8080/x", "localhost.example.com:8080", "127.0.0.1.nip.io:8080",
			"[::1%lo]:8080", " 127.0.0.1:8080",
		},
		"FIREBASE_AUTH_EMULATOR_HOST": {
			"identitytoolkit.googleapis.com:443", "http://127.0.0.1:9099", "u:p@127.0.0.1:9099",
		},
		"FIREBASE_STORAGE_EMULATOR_HOST": {"storage.googleapis.com:443", "http://127.0.0.1:9199"},
		"STORAGE_EMULATOR_HOST": {
			"https://storage.googleapis.com", "http://storage.googleapis.com:80",
			"https://127.0.0.1:9199", "http://fireemu:secret@127.0.0.1:9199",
			"http://fireemu@127.0.0.1:9199", "http://127.0.0.1", "http://127.0.0.1:9199/storage/v1/",
			"http://127.0.0.1:9199?x=1", "http://127.0.0.1:9199#x", "http://127.0.0.1:9199?",
			"grpc://127.0.0.1:9199", "http:127.0.0.1:9199", "http:x://127.0.0.1:9199",
		},
	}
	for name, values := range bad {
		for _, value := range values {
			env := validEnv()
			env[name] = value
			err := check(env)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s=%q accepted (err=%v)", name, value, err)
			}
		}
	}
}

func TestGuardChecksOptionalVariablesOnlyWhenSet(t *testing.T) {
	for _, name := range []string{"STORAGE_EMULATOR_HOST_GRPC", "FIREBASE_DATABASE_EMULATOR_HOST"} {
		env := validEnv()
		env[name] = "127.0.0.1:9000"
		if err := check(env); err != nil {
			t.Errorf("%s loopback refused: %v", name, err)
		}
		env[name] = "example.com:443"
		if err := check(env); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s non-loopback accepted (err=%v)", name, err)
		}
	}
}
