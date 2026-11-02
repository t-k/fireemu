// Command sdk-smoke-go exercises a running fireemu with the Go Admin SDK
// (firebase.google.com/go/v4): Firestore through cloud.google.com/go/firestore, Auth, and
// Storage through cloud.google.com/go/storage. Run it under `fireemu exec`; it refuses to start
// unless every emulator host variable those SDKs read names a loopback emulator (guard.go).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"time"

	"cloud.google.com/go/firestore"
	gcs "cloud.google.com/go/storage"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type step struct {
	name string
	run  func(ctx context.Context, s *smoke) error
}

type smoke struct {
	app      *firebase.App
	fs       *firestore.Client
	auth     *auth.Client
	authHost string
	bucket   *gcs.BucketHandle
}

func main() {
	if err := checkEmulatorEnv(os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		project = "demo-app"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// No credentials: the SDKs switch to their emulator modes from the variables checked above
	// (Auth: a static "owner" token; Firestore: "Bearer owner"; Storage: no authentication),
	// and WithoutAuthentication keeps every other path from looking up ADC.
	app, err := firebase.NewApp(ctx, &firebase.Config{
		ProjectID:     project,
		StorageBucket: project + ".appspot.com",
	}, option.WithoutAuthentication())
	if err != nil {
		fatal("firebase.NewApp", err)
	}
	s := &smoke{app: app, authHost: os.Getenv("FIREBASE_AUTH_EMULATOR_HOST")}
	if s.fs, err = app.Firestore(ctx); err != nil {
		fatal("app.Firestore", err)
	}
	defer s.fs.Close()
	if s.auth, err = app.Auth(ctx); err != nil {
		fatal("app.Auth", err)
	}
	st, err := app.Storage(ctx)
	if err != nil {
		fatal("app.Storage", err)
	}
	if s.bucket, err = st.DefaultBucket(); err != nil {
		fatal("DefaultBucket", err)
	}

	steps := []step{
		{"firestore set/get/update/delete", firestoreCRUD},
		{"firestore where+orderBy+limit", firestoreQuery},
		{"firestore transaction", firestoreTransaction},
		{"firestore batch", firestoreBatch},
		{"firestore snapshot listener", firestoreListener},
		{"auth user lifecycle and custom token", authFlow},
		{"storage upload/download/metadata/delete", storageFlow},
	}
	failed := 0
	for _, st := range steps {
		stepCtx, stepCancel := context.WithTimeout(ctx, 30*time.Second)
		err := st.run(stepCtx, s)
		stepCancel()
		if err != nil {
			failed++
			fmt.Printf("FAIL %s: %v\n", st.name, err)
		} else {
			fmt.Printf("ok   %s\n", st.name)
		}
	}
	if failed > 0 {
		fmt.Printf("%d of %d steps failed\n", failed, len(steps))
		os.Exit(1)
	}
	fmt.Printf("go admin sdk smoke: all %d steps passed\n", len(steps))
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

func firestoreCRUD(ctx context.Context, s *smoke) error {
	doc := s.fs.Collection("go-smoke").Doc("crud")
	if _, err := doc.Set(ctx, map[string]any{"name": "alpha", "n": 1}); err != nil {
		return fmt.Errorf("set: %w", err)
	}
	snap, err := doc.Get(ctx)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	if got := snap.Data(); got["name"] != "alpha" || got["n"] != int64(1) {
		return fmt.Errorf("get after set: %v", got)
	}
	if _, err := doc.Update(ctx, []firestore.Update{{Path: "n", Value: firestore.Increment(1)}, {Path: "tag", Value: "updated"}}); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	snap, err = doc.Get(ctx)
	if err != nil {
		return fmt.Errorf("get after update: %w", err)
	}
	if got := snap.Data(); got["name"] != "alpha" || got["n"] != int64(2) || got["tag"] != "updated" {
		return fmt.Errorf("get after update: %v", got)
	}
	if _, err := doc.Delete(ctx); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	snap, err = doc.Get(ctx)
	if status.Code(err) != codes.NotFound || snap == nil || snap.Exists() {
		return fmt.Errorf("get after delete: want NotFound and a missing snapshot, got err=%v", err)
	}
	// Update of a missing document fails as production does.
	if _, err := doc.Update(ctx, []firestore.Update{{Path: "n", Value: 3}}); status.Code(err) != codes.NotFound {
		return fmt.Errorf("update of a missing document: want NotFound, got %v", err)
	}
	return nil
}

func firestoreQuery(ctx context.Context, s *smoke) error {
	col := s.fs.Collection("go-cities")
	for id, pop := range map[string]int{"sf": 870, "la": 3900, "sd": 1400, "oak": 430, "fre": 540} {
		if _, err := col.Doc(id).Set(ctx, map[string]any{"population": pop}); err != nil {
			return fmt.Errorf("seed %s: %w", id, err)
		}
	}
	// Inequality and order on the same field: served by the automatic single-field index,
	// so the strict profile needs no composite index declaration.
	docs, err := col.Where("population", ">", 500).OrderBy("population", firestore.Desc).Limit(3).Documents(ctx).GetAll()
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	var ids []string
	for _, d := range docs {
		ids = append(ids, d.Ref.ID)
	}
	if want := []string{"la", "sd", "sf"}; !reflect.DeepEqual(ids, want) {
		return fmt.Errorf("query: got %v, want %v", ids, want)
	}
	return nil
}

func firestoreTransaction(ctx context.Context, s *smoke) error {
	doc := s.fs.Collection("go-smoke").Doc("counter")
	if _, err := doc.Set(ctx, map[string]any{"count": 10}); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	err := s.fs.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		snap, err := tx.Get(doc)
		if err != nil {
			return err
		}
		n, err := snap.DataAt("count")
		if err != nil {
			return err
		}
		return tx.Update(doc, []firestore.Update{{Path: "count", Value: n.(int64) + 5}})
	})
	if err != nil {
		return fmt.Errorf("transaction: %w", err)
	}
	snap, err := doc.Get(ctx)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	if n, _ := snap.DataAt("count"); n != int64(15) {
		return fmt.Errorf("count after transaction: %v, want 15", n)
	}
	return nil
}

func firestoreBatch(ctx context.Context, s *smoke) error {
	col := s.fs.Collection("go-batch")
	if _, err := col.Doc("c").Set(ctx, map[string]any{"v": "c"}); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	// WriteBatch is deprecated in favour of BulkWriter, but BulkWriter is not atomic; the
	// atomic batch commit is what this step covers.
	batch := s.fs.Batch()
	batch.Set(col.Doc("a"), map[string]any{"v": "a"})
	batch.Set(col.Doc("b"), map[string]any{"v": "b"})
	batch.Delete(col.Doc("c"))
	results, err := batch.Commit(ctx)
	if err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	if len(results) != 3 {
		return fmt.Errorf("commit: %d write results, want 3", len(results))
	}
	docs, err := col.Documents(ctx).GetAll()
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	var ids []string
	for _, d := range docs {
		ids = append(ids, d.Ref.ID)
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(ids, want) {
		return fmt.Errorf("after batch: %v, want %v", ids, want)
	}
	return nil
}

func firestoreListener(ctx context.Context, s *smoke) error {
	col := s.fs.Collection("go-listen")
	it := col.Snapshots(ctx)
	defer it.Stop()
	first, err := it.Next()
	if err != nil {
		return fmt.Errorf("initial snapshot: %w", err)
	}
	if first.Size != 0 || len(first.Changes) != 0 {
		return fmt.Errorf("initial snapshot: size %d, %d changes, want an empty collection", first.Size, len(first.Changes))
	}
	if _, err := col.Doc("one").Set(ctx, map[string]any{"hello": "world"}); err != nil {
		return fmt.Errorf("set: %w", err)
	}
	next, err := it.Next()
	if err != nil {
		return fmt.Errorf("snapshot after set: %w", err)
	}
	if len(next.Changes) != 1 {
		return fmt.Errorf("snapshot after set: %d changes, want 1", len(next.Changes))
	}
	ch := next.Changes[0]
	if ch.Kind != firestore.DocumentAdded || ch.Doc.Ref.ID != "one" || ch.Doc.Data()["hello"] != "world" {
		return fmt.Errorf("snapshot after set: change kind %v doc %s data %v", ch.Kind, ch.Doc.Ref.ID, ch.Doc.Data())
	}
	return nil
}

func authFlow(ctx context.Context, s *smoke) error {
	const email = "go-smoke@example.com"
	created, err := s.auth.CreateUser(ctx, (&auth.UserToCreate{}).Email(email).Password("go-smoke-password").DisplayName("Go Smoke"))
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	uid := created.UID
	byEmail, err := s.auth.GetUserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("get by email: %w", err)
	}
	if byEmail.UID != uid || byEmail.DisplayName != "Go Smoke" {
		return fmt.Errorf("get by email: uid %q name %q, want %q", byEmail.UID, byEmail.DisplayName, uid)
	}
	if err := s.auth.SetCustomUserClaims(ctx, uid, map[string]any{"role": "admin"}); err != nil {
		return fmt.Errorf("set custom claims: %w", err)
	}
	withClaims, err := s.auth.GetUser(ctx, uid)
	if err != nil {
		return fmt.Errorf("get after claims: %w", err)
	}
	if withClaims.CustomClaims["role"] != "admin" {
		return fmt.Errorf("custom claims: %v", withClaims.CustomClaims)
	}
	custom, err := s.auth.CustomTokenWithClaims(ctx, uid, map[string]any{"tier": "gold"})
	if err != nil {
		return fmt.Errorf("custom token: %w", err)
	}
	idToken, err := signInWithCustomToken(ctx, s.authHost, custom)
	if err != nil {
		return err
	}
	tok, err := s.auth.VerifyIDToken(ctx, idToken)
	if err != nil {
		return fmt.Errorf("verify id token: %w", err)
	}
	if tok.UID != uid || tok.Claims["role"] != "admin" || tok.Claims["tier"] != "gold" {
		return fmt.Errorf("verified token: uid %q claims %v", tok.UID, tok.Claims)
	}
	if err := s.auth.DeleteUser(ctx, uid); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if _, err := s.auth.GetUser(ctx, uid); !auth.IsUserNotFound(err) {
		return fmt.Errorf("get after delete: want user-not-found, got %v", err)
	}
	return nil
}

// signInWithCustomToken is the Identity Toolkit call a client SDK makes; the Go Admin SDK has
// no client sign-in, so the smoke posts it to the Auth emulator itself.
func signInWithCustomToken(ctx context.Context, authHost, customToken string) (string, error) {
	body, _ := json.Marshal(map[string]any{"token": customToken, "returnSecureToken": true})
	url := "http://" + authHost + "/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=demo-api-key"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("signInWithCustomToken: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("signInWithCustomToken: HTTP %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		IDToken string `json:"idToken"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.IDToken == "" {
		return "", fmt.Errorf("signInWithCustomToken: no idToken in %s", raw)
	}
	return out.IDToken, nil
}

func storageFlow(ctx context.Context, s *smoke) error {
	obj := s.bucket.Object("go-smoke/hello.txt")
	payload := []byte("hello from the Go Admin SDK\n")
	w := obj.NewWriter(ctx)
	w.ContentType = "text/plain; charset=utf-8"
	w.Metadata = map[string]string{"origin": "sdk-smoke-go"}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("upload write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("upload close: %w", err)
	}
	r, err := obj.NewReader(ctx)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		return fmt.Errorf("download read: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("download: %q, want %q", got, payload)
	}
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		return fmt.Errorf("metadata: %w", err)
	}
	if attrs.Size != int64(len(payload)) || attrs.ContentType != w.ContentType || attrs.Metadata["origin"] != "sdk-smoke-go" || attrs.Name != "go-smoke/hello.txt" {
		return fmt.Errorf("metadata: size %d type %q metadata %v name %q", attrs.Size, attrs.ContentType, attrs.Metadata, attrs.Name)
	}
	if err := obj.Delete(ctx); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	if _, err := obj.Attrs(ctx); !errors.Is(err, gcs.ErrObjectNotExist) {
		return fmt.Errorf("metadata after delete: want ErrObjectNotExist, got %v", err)
	}
	return nil
}
