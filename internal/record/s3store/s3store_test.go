package s3store_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarlock/oarlock/internal/record"
	"github.com/oarlock/oarlock/internal/record/s3store"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// The tests below drive the real minio-go client against a fake S3 rather than a
// mocked-out interface, because the thing worth pinning is not "did we call a
// method" but "did the object-lock headers leave the process". A store that wrote
// recordings to S3 and reported compliance without sending those headers would be
// worse than no store at all: the operator would believe the evidence is locked.
//
// Nothing here carries a credential that means anything. The fake accepts whatever
// signature arrives; real credentials come from the config file or the environment
// and never from a fixture.
const (
	testBucket    = "oarlock-recordings"
	testPrefix    = "recordings"
	testAccessKey = "fake-access-key"
	testSecretKey = "fake-secret-key"
	testSessionID = "sess_01J8Z9QX2N4T7V"
	partSize      = 5 << 20 // minio-go's floor; see the multipart test
)

// clockStart makes the retain-until date exact rather than approximate. A test that
// allowed a window would pass with the retention period computed from the wrong base.
var clockStart = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

// ── the rule this whole feature turns on ────────────────────────────────────────

// TestAnUnlockedBucketIsMutableWhateverTheConfigAsked is the feature.
//
// The store reports what the bucket says, never what the config says. A backend that
// answered ModeCompliance because its YAML asked for compliance would hand the
// operator a green light and no lock, and every manifest written afterwards would
// carry a signed claim nobody checked.
func TestAnUnlockedBucketIsMutableWhateverTheConfigAsked(t *testing.T) {
	f := newFakeS3(t)
	f.lock = nil // the bucket has no object-lock configuration at all

	st := open(t, f, func(c *s3store.Config) {
		c.LockMode = record.ModeCompliance
		c.RetainFor = 2160 * time.Hour
	})

	im, err := st.Immutability(context.Background())
	if err != nil {
		t.Fatalf("Immutability: %v", err)
	}
	if im.Mode != record.ModeMutable {
		t.Fatalf("mode = %q, want %q — the config asked for compliance and the "+
			"bucket has no lock, so the honest answer is mutable", im.Mode, record.ModeMutable)
	}
	if im.Mode.Protected() {
		t.Fatal("an unlocked bucket reported itself as protected")
	}
	if im.Kind != "s3" {
		t.Errorf("kind = %q, want s3", im.Kind)
	}
	if im.Detail == "" {
		t.Error("no detail: somebody reading a manifest years later needs to know why")
	}
}

// TestImmutabilityReportsWhatTheBucketSays covers the answers a locked bucket gives.
func TestImmutabilityReportsWhatTheBucketSays(t *testing.T) {
	cases := []struct {
		name      string
		lock      *lockConfig
		requested record.Mode
		want      record.Mode
		wantFor   time.Duration
		// wantDetail are substrings the detail must contain. The mode is one number
		// and some of these cases carry two facts; Detail is where the second one
		// has to survive, so where it matters it is asserted rather than assumed.
		wantDetail []string
	}{
		{
			// wantFor is the *configured* retention, which is what each PUT's own
			// retain-until date carries. That it also equals this bucket's 90-day
			// default is a coincidence, and one worth naming: it let this case pass
			// under the old weaker-of rule too, so it was never evidence either way.
			name:      "a compliance default retention",
			lock:      &lockConfig{Enabled: true, Mode: "COMPLIANCE", Days: 90},
			requested: record.ModeCompliance,
			want:      record.ModeCompliance,
			wantFor:   2160 * time.Hour,
		},
		{
			// The same bucket-agrees-with-us case where the two durations differ,
			// so it actually discriminates: the object's retain-until comes from
			// RetainFor, not from the bucket's 30-day default.
			name:      "a governance default retention",
			lock:      &lockConfig{Enabled: true, Mode: "GOVERNANCE", Days: 30},
			requested: record.ModeGovernance,
			want:      record.ModeGovernance,
			wantFor:   2160 * time.Hour,
		},
		{
			// A per-PUT mode overrides the bucket default, so a recording this
			// gateway wrote really is compliance-locked and that is what gets
			// reported — reporting the bucket's weaker default would understate the
			// lock on the very object whose manifest carries this.
			//
			// It is the same reasoning as "lock enabled with no default rule"
			// below, and the two used to disagree: this case reported the weaker
			// mode while that one trusted the same header. What the bucket default
			// does or does not cover is a separate fact, and it lives in Detail.
			name:      "the config asks for more than the bucket's default",
			lock:      &lockConfig{Enabled: true, Mode: "GOVERNANCE", Days: 30},
			requested: record.ModeCompliance,
			want:      record.ModeCompliance,
			wantFor:   2160 * time.Hour,
			// Both facts must be legible to whoever reads the manifest: what this
			// object got, and what an object written by anything else would get.
			wantDetail: []string{"compliance", "governance", "other than this gateway"},
		},
		{
			// The reverse, which is an operator mistake worth reporting accurately
			// rather than flattering: asking for governance against a compliance
			// bucket writes governance objects, and governance is liftable.
			name:      "the config asks for less than the bucket's default",
			lock:      &lockConfig{Enabled: true, Mode: "COMPLIANCE", Days: 90},
			requested: record.ModeGovernance,
			want:      record.ModeGovernance,
			wantFor:   2160 * time.Hour,
		},
		{
			// Object Lock enabled with no default rule still locks the objects we
			// write, because every PUT of ours carries the mode explicitly. What it
			// does not do is constrain anybody else's writes.
			name:      "lock enabled with no default rule",
			lock:      &lockConfig{Enabled: true},
			requested: record.ModeCompliance,
			want:      record.ModeCompliance,
			wantFor:   2160 * time.Hour,
		},
		{
			// Nothing was asked for and the bucket sets no default, so nothing is
			// enforced on our objects.
			name:      "lock enabled, nothing requested, no default rule",
			lock:      &lockConfig{Enabled: true},
			requested: "",
			want:      record.ModeMutable,
		},
		{
			// Nothing asked for, but the bucket locks by default — so our PUTs send
			// no mode and inherit it. The retention is the bucket's, not the
			// RetainFor nobody asked to apply.
			name:      "nothing requested, the bucket locks by default",
			lock:      &lockConfig{Enabled: true, Mode: "COMPLIANCE", Days: 7},
			requested: "",
			want:      record.ModeCompliance,
			wantFor:   7 * 24 * time.Hour,
		},
		{
			// A bucket that reports the lock switch as off is mutable, same as one
			// with no configuration.
			name:      "object lock explicitly disabled",
			lock:      &lockConfig{Enabled: false},
			requested: record.ModeCompliance,
			want:      record.ModeMutable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeS3(t)
			f.lock = tc.lock
			st := open(t, f, func(c *s3store.Config) {
				c.LockMode = tc.requested
				c.RetainFor = 2160 * time.Hour
			})

			im, err := st.Immutability(context.Background())
			if err != nil {
				t.Fatalf("Immutability: %v", err)
			}
			if im.Mode != tc.want {
				t.Errorf("mode = %q, want %q", im.Mode, tc.want)
			}
			if im.RetainFor != tc.wantFor {
				t.Errorf("retain_for = %v, want %v", im.RetainFor, tc.wantFor)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(im.Detail, want) {
					t.Errorf("detail does not mention %q:\n  %s", want, im.Detail)
				}
			}
		})
	}
}

// TestAnUnreadableBucketIsAnError pins the other half of honest reporting. A store
// that cannot reach its bucket must say so, so record.immutabilityOf turns it into
// ModeUnknown — which Mode.Protected() excludes. Answering "mutable" here would be a
// guess dressed as a fact, and answering the requested mode would be the lie the
// whole feature exists to prevent.
func TestAnUnreadableBucketIsAnError(t *testing.T) {
	f := newFakeS3(t)
	f.lockStatus = http.StatusInternalServerError

	st := open(t, f, func(c *s3store.Config) {
		c.LockMode = record.ModeCompliance
		c.RetainFor = time.Hour
	})

	im, err := st.Immutability(context.Background())
	if err == nil {
		t.Fatalf("Immutability returned %+v and no error for a bucket it could not read", im)
	}
}

// ── the lock headers actually leave the process ─────────────────────────────────

// TestARecordingAndItsManifestBothCarryTheLock is the assertion that stops this
// shipping as an ordinary S3 writer.
//
// Both halves matter. A locked recording beside an editable manifest is not
// evidence: the manifest holds the signature and the chain head, so anyone who can
// rewrite it can re-sign a doctored chain and the lock on the .cast buys nothing.
func TestARecordingAndItsManifestBothCarryTheLock(t *testing.T) {
	f := newFakeS3(t)
	f.lock = &lockConfig{Enabled: true, Mode: "COMPLIANCE", Days: 90}

	retention := 2160 * time.Hour
	st := open(t, f, func(c *s3store.Config) {
		c.LockMode = record.ModeCompliance
		c.RetainFor = retention
	})
	wantUntil := clockStart.Add(retention).Format(time.RFC3339)

	w, err := st.Create(context.Background(), meta())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte("{\"version\":3}\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := st.PutManifest(context.Background(), testSessionID, []byte(`{"session_id":"x"}`)); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	castKey := testPrefix + "/" + testSessionID + ".cast"
	manifestKey := testPrefix + "/" + testSessionID + ".manifest.json"

	// The recording is a stream of unknown length, so it goes up as a multipart
	// upload — and S3 takes the lock from the request that *initiates* it, not from
	// the parts or from the completion.
	initiate := f.only(t, func(r recorded) bool {
		return r.Method == http.MethodPost && r.Key == castKey && r.Query.Has("uploads")
	})
	assertLocked(t, "the recording's CreateMultipartUpload", initiate, "COMPLIANCE", wantUntil)

	manifest := f.only(t, func(r recorded) bool {
		return r.Method == http.MethodPut && r.Key == manifestKey
	})
	assertLocked(t, "the manifest PUT", manifest, "COMPLIANCE", wantUntil)

	// Both objects have to be findable by session id by somebody holding bucket
	// credentials and no gateway.
	if _, ok := f.object(castKey); !ok {
		t.Errorf("no object at %s; keys present: %v", castKey, f.keys())
	}
	if b, ok := f.object(manifestKey); !ok {
		t.Errorf("no object at %s; keys present: %v", manifestKey, f.keys())
	} else if string(b) != `{"session_id":"x"}` {
		t.Errorf("manifest body = %q", b)
	}
}

// TestGovernanceIsSentAsGovernance guards against a store that hardcodes the strongest
// mode. An operator who asked for governance must not silently get a lock nobody can
// lift, including them.
func TestGovernanceIsSentAsGovernance(t *testing.T) {
	f := newFakeS3(t)
	f.lock = &lockConfig{Enabled: true, Mode: "GOVERNANCE", Days: 30}

	retention := 720 * time.Hour
	st := open(t, f, func(c *s3store.Config) {
		c.LockMode = record.ModeGovernance
		c.RetainFor = retention
	})
	wantUntil := clockStart.Add(retention).Format(time.RFC3339)

	write(t, st, []byte("hello"))

	initiate := f.only(t, func(r recorded) bool {
		return r.Method == http.MethodPost && r.Query.Has("uploads")
	})
	assertLocked(t, "the recording's CreateMultipartUpload", initiate, "GOVERNANCE", wantUntil)
}

// TestNoLockRequestedSendsNoLockHeaders keeps the store usable against a bucket with
// no Object Lock, which is what a lab has. S3 refuses a lock header on such a bucket
// outright, so sending one anyway would make the store unusable there rather than
// merely unprotected.
func TestNoLockRequestedSendsNoLockHeaders(t *testing.T) {
	f := newFakeS3(t)
	f.lock = nil

	st := open(t, f, func(c *s3store.Config) { c.LockMode = "" })
	write(t, st, []byte("hello"))
	if err := st.PutManifest(context.Background(), testSessionID, []byte("{}")); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	for _, r := range f.recorded() {
		if got := r.Header.Get("X-Amz-Object-Lock-Mode"); got != "" {
			t.Errorf("%s %s carried x-amz-object-lock-mode: %q", r.Method, r.Key, got)
		}
		if got := r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"); got != "" {
			t.Errorf("%s %s carried a retain-until date: %q", r.Method, r.Key, got)
		}
	}
}

// ── multipart, and cleaning up after itself ─────────────────────────────────────

// TestAStreamLongerThanOnePartBecomesMultipart is why this backend takes a
// dependency at all: Create hands back an io.WriteCloser and the spool writes to it
// incrementally, so the final length is unknown and the upload has to be multipart.
//
// The part size here is 5 MiB because that is minio-go's floor — OptimalPartInfo
// refuses anything smaller with "Input part size is smaller than allowed minimum of
// 5MiB" — so the stream has to clear it. It is generated rather than read from a
// fixture: a 5 MiB blob in the repository would be a strange thing to explain.
func TestAStreamLongerThanOnePartBecomesMultipart(t *testing.T) {
	f := newFakeS3(t)
	f.lock = &lockConfig{Enabled: true, Mode: "COMPLIANCE", Days: 90}

	st := open(t, f, func(c *s3store.Config) {
		c.LockMode = record.ModeCompliance
		c.RetainFor = 2160 * time.Hour
	})

	body := stream(partSize + 1024)
	w, err := st.Create(context.Background(), meta())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Written in small pieces on purpose: this is how the spool drains, and a
	// backend that only works when handed the whole recording at once would pass a
	// single-Write test and fail in production.
	for off := 0; off < len(body); off += 4096 {
		end := min(off+4096, len(body))
		if _, err := w.Write(body[off:end]); err != nil {
			t.Fatalf("Write at %d: %v", off, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	castKey := testPrefix + "/" + testSessionID + ".cast"
	var parts []int
	for _, r := range f.recorded() {
		if r.Method == http.MethodPut && r.Key == castKey && r.Query.Get("uploadId") != "" {
			n, _ := strconv.Atoi(r.Query.Get("partNumber"))
			parts = append(parts, n)
		}
	}
	sort.Ints(parts)
	if len(parts) < 2 {
		t.Fatalf("part numbers uploaded = %v, want at least two: a %d-byte stream "+
			"with a %d-byte part size must not arrive as one part", parts, len(body), partSize)
	}
	if parts[0] != 1 || parts[1] != 2 {
		t.Errorf("part numbers = %v, want them to start 1, 2", parts)
	}
	if n := f.count(func(r recorded) bool {
		return r.Method == http.MethodPost && r.Key == castKey && r.Query.Get("uploadId") != ""
	}); n != 1 {
		t.Errorf("CompleteMultipartUpload requests = %d, want 1", n)
	}

	// And the object that lands is the stream that went in, in order. A multipart
	// upload whose parts arrive out of order produces a recording that verifies as
	// nothing.
	got, ok := f.object(castKey)
	if !ok {
		t.Fatalf("no object at %s", castKey)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("stored object is %d bytes and differs from the %d bytes written",
			len(got), len(body))
	}
}

// TestAFailedPartAbortsTheUpload pins the cleanup. A dangling multipart upload holds
// storage that no listing shows and no lifecycle rule removes unless somebody
// configured one, so it costs money silently — which is the specific failure that
// made a library preferable to hand-rolling this.
//
// It also pins that the writer stops accepting bytes. Once the upload has failed
// nothing is reading the other end of the stream, and a Write that blocked there
// would wedge the session's drain goroutine rather than fail the session.
func TestAFailedPartAbortsTheUpload(t *testing.T) {
	f := newFakeS3(t)
	f.lock = &lockConfig{Enabled: true, Mode: "COMPLIANCE", Days: 90}
	f.failPart = 1

	st := open(t, f, func(c *s3store.Config) {
		c.LockMode = record.ModeCompliance
		c.RetainFor = 2160 * time.Hour
	})

	w, err := st.Create(context.Background(), meta())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	body := stream(2*partSize + 1024)
	writeErr := make(chan error, 1)
	go func() {
		for off := 0; off < len(body); off += 4096 {
			end := min(off+4096, len(body))
			if _, err := w.Write(body[off:end]); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	select {
	case err := <-writeErr:
		if err == nil {
			t.Error("every write succeeded even though the store rejected part 1")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Write blocked after the upload failed: the writer is holding the " +
			"session open on a stream nobody is reading")
	}

	if err := w.Close(); err == nil {
		t.Error("Close reported success for an upload the store rejected")
	}

	castKey := testPrefix + "/" + testSessionID + ".cast"
	if n := f.count(func(r recorded) bool {
		return r.Method == http.MethodDelete && r.Key == castKey && r.Query.Get("uploadId") != ""
	}); n != 1 {
		t.Errorf("AbortMultipartUpload requests = %d, want 1; requests seen: %s",
			n, f.summary())
	}
	if _, ok := f.object(castKey); ok {
		t.Error("a failed upload left an object behind")
	}
	if n := f.uploadsOpen(); n != 0 {
		t.Errorf("%d multipart upload(s) still open at the fake", n)
	}
}

// ── reading it back ─────────────────────────────────────────────────────────────

// TestGetOnAMissingRecordingIsErrNotFound matters because callers switch on it. A
// transport error here turns "no such recording" into "the store is broken", which
// is a different page in the console and a different pager at three in the morning.
func TestGetOnAMissingRecordingIsErrNotFound(t *testing.T) {
	f := newFakeS3(t)
	st := open(t, f, nil)

	if rc, err := st.Get(context.Background(), "sess_missing"); !errors.Is(err, record.ErrNotFound) {
		if rc != nil {
			rc.Close()
		}
		t.Errorf("Get error = %v, want record.ErrNotFound", err)
	}
	if _, err := st.GetManifest(context.Background(), "sess_missing"); !errors.Is(err, record.ErrNotFound) {
		t.Errorf("GetManifest error = %v, want record.ErrNotFound", err)
	}
}

// TestGetReturnsTheRecording is the round trip, so the not-found test above cannot
// pass by returning ErrNotFound for everything.
func TestGetReturnsTheRecording(t *testing.T) {
	f := newFakeS3(t)
	st := open(t, f, nil)

	want := []byte("{\"version\":3}\n[0.1,\"o\",\"hi\"]\n")
	write(t, st, want)
	if err := st.PutManifest(context.Background(), testSessionID, []byte(`{"session_id":"s"}`)); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	rc, err := st.Get(context.Background(), testSessionID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading the recording: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("recording = %q, want %q", got, want)
	}

	man, err := st.GetManifest(context.Background(), testSessionID)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if string(man) != `{"session_id":"s"}` {
		t.Errorf("manifest = %q", man)
	}
}

// TestURLIsPresignedForTheRequestedTTL. This is the method that keeps replay from
// streaming through the gateway, so unlike FileStore's it must not answer
// ErrUnsupported — a local directory has no shareable link, and a bucket does.
func TestURLIsPresignedForTheRequestedTTL(t *testing.T) {
	f := newFakeS3(t)
	st := open(t, f, nil)

	const ttl = 7 * time.Minute
	raw, err := st.URL(context.Background(), testSessionID, ttl)
	if err != nil {
		t.Fatalf("URL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	if want := "/" + testBucket + "/" + testPrefix + "/" + testSessionID + ".cast"; u.Path != want {
		t.Errorf("path = %q, want %q", u.Path, want)
	}
	q := u.Query()
	if got, want := q.Get("X-Amz-Expires"), strconv.Itoa(int(ttl.Seconds())); got != want {
		t.Errorf("X-Amz-Expires = %q, want %q", got, want)
	}
	if q.Get("X-Amz-Signature") == "" {
		t.Error("no X-Amz-Signature: the link is not presigned, it is just a URL")
	}
	if q.Get("X-Amz-Credential") == "" {
		t.Error("no X-Amz-Credential")
	}
	// A presigned GET is a link somebody pastes. It must not be a request that
	// needs an Authorization header the browser will never send.
	if strings.Contains(raw, testSecretKey) {
		t.Error("the secret key is in the presigned URL")
	}

	if _, err := st.URL(context.Background(), testSessionID, 0); err == nil {
		t.Error("a zero TTL produced a link; an unbounded link is not time-limited")
	}
}

// TestOpenRefusesAnIncompleteConfig. A store built without a bucket, or asking for a
// lock with no retention period, would fail at the first recording — which is a
// session that closes rather than a gateway that refuses to start.
func TestOpenRefusesAnIncompleteConfig(t *testing.T) {
	cases := map[string]s3store.Config{
		"no bucket": {Region: "us-east-1"},
		"compliance, no retention": {
			Bucket: testBucket, Region: "us-east-1", LockMode: record.ModeCompliance,
		},
		"a lock mode no lock can express": {
			Bucket: testBucket, Region: "us-east-1",
			LockMode: record.ModeDeclared, RetainFor: time.Hour,
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if st, err := s3store.Open(cfg); err == nil {
				t.Errorf("Open accepted %+v and returned %v", cfg, st)
			}
		})
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────────

func meta() *plugin.SessionMeta {
	return &plugin.SessionMeta{
		SessionID: testSessionID, DeviceID: "treadmill-4821", Profile: "shell",
		Mode: "gateway", Principal: "admin@mail.com",
		Term: "xterm-256color", Cols: 132, Rows: 38,
		StartedAt: clockStart,
	}
}

func open(t *testing.T, f *fakeS3, tweak func(*s3store.Config)) *s3store.Store {
	t.Helper()
	cfg := s3store.Config{
		Bucket:    testBucket,
		Region:    "us-east-1",
		Endpoint:  f.host(),
		Prefix:    testPrefix,
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		UseSSL:    false,
		PartSize:  partSize,
		Now:       func() time.Time { return clockStart },
	}
	if tweak != nil {
		tweak(&cfg)
	}
	st, err := s3store.Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st
}

func write(t *testing.T, st *s3store.Store, b []byte) {
	t.Helper()
	w, err := st.Create(context.Background(), meta())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// stream builds n bytes that are not all the same, so a store that reassembled parts
// in the wrong order would be caught.
func stream(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

func assertLocked(t *testing.T, what string, r recorded, mode, until string) {
	t.Helper()
	if got := r.Header.Get("X-Amz-Object-Lock-Mode"); got != mode {
		t.Errorf("%s: x-amz-object-lock-mode = %q, want %q", what, got, mode)
	}
	if got := r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"); got != until {
		t.Errorf("%s: x-amz-object-lock-retain-until-date = %q, want %q", what, got, until)
	}
}

// ── the fake S3 ─────────────────────────────────────────────────────────────────

type recorded struct {
	Method string
	Bucket string
	Key    string
	Query  url.Values
	Header http.Header
	Body   []byte
}

// lockConfig is what GetObjectLockConfiguration answers. A nil *lockConfig means the
// bucket has no configuration at all, which on real S3 is a 404 rather than an empty
// document — and is the case this whole feature turns on.
type lockConfig struct {
	Enabled bool
	Mode    string // COMPLIANCE, GOVERNANCE, or empty for no default retention rule
	Days    uint
}

// fakeS3 answers enough of S3 to drive minio-go: PutObject, the three multipart
// calls, AbortMultipartUpload, HEAD and GET including a 404, and the bucket's
// object-lock configuration. It records every request it is given so the tests can
// assert on what was actually sent rather than on what was intended.
type fakeS3 struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []recorded
	objects  map[string][]byte
	uploads  map[string]map[int][]byte

	// lock is read under mu but set before the server sees traffic.
	lock       *lockConfig
	lockStatus int // non-zero to fail GetObjectLockConfiguration outright
	failPart   int // reject UploadPart of this number
	nextUpload int
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{
		objects: map[string][]byte{},
		uploads: map[string]map[int][]byte{},
	}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeS3) host() string { return strings.TrimPrefix(f.srv.URL, "http://") }

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		s3Error(w, http.StatusBadRequest, "IncompleteBody", err.Error())
		return
	}
	bucket, key := splitPath(r.URL.Path)
	q := r.URL.Query()

	f.mu.Lock()
	f.requests = append(f.requests, recorded{
		Method: r.Method, Bucket: bucket, Key: key,
		Query: q, Header: r.Header.Clone(), Body: body,
	})
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && key == "" && q.Has("object-lock"):
		f.serveObjectLock(w)
	case r.Method == http.MethodPost && key != "" && q.Has("uploads"):
		f.initiate(w, bucket, key)
	case r.Method == http.MethodPut && q.Get("uploadId") != "":
		f.uploadPart(w, q, body)
	case r.Method == http.MethodPost && q.Get("uploadId") != "":
		f.complete(w, bucket, key, q)
	case r.Method == http.MethodDelete && q.Get("uploadId") != "":
		f.abort(w, q)
	case r.Method == http.MethodPut && key != "":
		f.put(w, key, body)
	case r.Method == http.MethodHead && key != "":
		f.head(w, key)
	case r.Method == http.MethodGet && key != "":
		f.get(w, key)
	default:
		s3Error(w, http.StatusNotImplemented, "NotImplemented",
			r.Method+" "+r.URL.String()+" is not part of the fake")
	}
}

func (f *fakeS3) serveObjectLock(w http.ResponseWriter) {
	f.mu.Lock()
	cfg, status := f.lock, f.lockStatus
	f.mu.Unlock()

	if status != 0 {
		s3Error(w, status, "InternalError", "the fake was told to fail this call")
		return
	}
	if cfg == nil {
		// What real S3 says about a bucket that was never created with Object Lock.
		s3Error(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError",
			"Object Lock configuration does not exist for this bucket")
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	if cfg.Enabled {
		b.WriteString(`<ObjectLockEnabled>Enabled</ObjectLockEnabled>`)
	}
	if cfg.Mode != "" {
		fmt.Fprintf(&b, `<Rule><DefaultRetention><Mode>%s</Mode><Days>%d</Days>`+
			`</DefaultRetention></Rule>`, cfg.Mode, cfg.Days)
	}
	b.WriteString(`</ObjectLockConfiguration>`)
	xmlOK(w, b.String())
}

func (f *fakeS3) initiate(w http.ResponseWriter, bucket, key string) {
	f.mu.Lock()
	f.nextUpload++
	id := fmt.Sprintf("upload-%d", f.nextUpload)
	f.uploads[id] = map[int][]byte{}
	f.mu.Unlock()

	xmlOK(w, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<InitiateMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key>`+
		`<UploadId>%s</UploadId></InitiateMultipartUploadResult>`, bucket, key, id))
}

func (f *fakeS3) uploadPart(w http.ResponseWriter, q url.Values, body []byte) {
	n, err := strconv.Atoi(q.Get("partNumber"))
	if err != nil {
		s3Error(w, http.StatusBadRequest, "InvalidPart", "unparseable partNumber")
		return
	}
	f.mu.Lock()
	fail := f.failPart == n
	parts, ok := f.uploads[q.Get("uploadId")]
	if ok && !fail {
		parts[n] = body
	}
	f.mu.Unlock()

	switch {
	case !ok:
		s3Error(w, http.StatusNotFound, "NoSuchUpload", "no such upload")
	case fail:
		// 403 on purpose: minio-go retries 5xx and throttling codes, and a test
		// that waited out ten backoffs would be a test nobody runs.
		s3Error(w, http.StatusForbidden, "AccessDenied", "the fake rejected this part")
	default:
		w.Header().Set("ETag", fmt.Sprintf("%q", fmt.Sprintf("part-%d", n)))
		w.WriteHeader(http.StatusOK)
	}
}

func (f *fakeS3) complete(w http.ResponseWriter, bucket, key string, q url.Values) {
	id := q.Get("uploadId")
	f.mu.Lock()
	parts, ok := f.uploads[id]
	if ok {
		nums := make([]int, 0, len(parts))
		for n := range parts {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		var whole []byte
		for _, n := range nums {
			whole = append(whole, parts[n]...)
		}
		f.objects[key] = whole
		delete(f.uploads, id)
	}
	f.mu.Unlock()

	if !ok {
		s3Error(w, http.StatusNotFound, "NoSuchUpload", "no such upload")
		return
	}
	xmlOK(w, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<CompleteMultipartUploadResult><Location>/%s/%s</Location><Bucket>%s</Bucket>`+
		`<Key>%s</Key><ETag>%q</ETag></CompleteMultipartUploadResult>`,
		bucket, key, bucket, key, "complete-"+id))
}

func (f *fakeS3) abort(w http.ResponseWriter, q url.Values) {
	f.mu.Lock()
	delete(f.uploads, q.Get("uploadId"))
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeS3) put(w http.ResponseWriter, key string, body []byte) {
	f.mu.Lock()
	f.objects[key] = body
	f.mu.Unlock()
	w.Header().Set("ETag", fmt.Sprintf("%q", "put-"+key))
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3) head(w http.ResponseWriter, key string) {
	b, ok := f.object(key)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	objectHeaders(w, key, len(b))
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3) get(w http.ResponseWriter, key string) {
	b, ok := f.object(key)
	if !ok {
		s3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}
	objectHeaders(w, key, len(b))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// objectHeaders sets what minio-go's ToObjectInfo insists on. Leaving Last-Modified
// off turns every read into an opaque InternalError, which is a confusing hour.
func objectHeaders(w http.ResponseWriter, key string, size int) {
	w.Header().Set("Content-Length", strconv.Itoa(size))
	w.Header().Set("ETag", fmt.Sprintf("%q", "etag-"+key))
	w.Header().Set("Last-Modified", clockStart.Format(http.TimeFormat))
	w.Header().Set("Content-Type", "application/octet-stream")
}

func xmlOK(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
}

func s3Error(w http.ResponseWriter, status int, code, message string) {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code>`+
		`<Message>%s</Message></Error>`, code, message)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func splitPath(p string) (bucket, key string) {
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

// readBody strips the streaming-signature framing minio-go uses for a body sent over
// plain HTTP. Each chunk arrives as "<hex length>;chunk-signature=<sig>\r\n<data>\r\n"
// and a zero-length chunk ends it. Real S3 decodes this; a fake that did not would
// store framing bytes and fail every round-trip assertion for reasons that look like
// a bug in the store.
func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	if !strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
		return io.ReadAll(r.Body)
	}
	br := bufio.NewReader(r.Body)
	var out []byte
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading a chunk header: %w", err)
		}
		head := strings.TrimRight(line, "\r\n")
		if i := strings.IndexByte(head, ';'); i >= 0 {
			head = head[:i]
		}
		n, err := strconv.ParseInt(head, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("chunk header %q: %w", head, err)
		}
		if n == 0 {
			return out, nil
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, fmt.Errorf("reading %d chunk bytes: %w", n, err)
		}
		out = append(out, buf...)
		if _, err := br.Discard(2); err != nil { // the CRLF after the data
			return nil, err
		}
	}
}

// ── reading the fake back ───────────────────────────────────────────────────────

func (f *fakeS3) recorded() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.requests...)
}

func (f *fakeS3) count(match func(recorded) bool) int {
	n := 0
	for _, r := range f.recorded() {
		if match(r) {
			n++
		}
	}
	return n
}

// only returns the single matching request, failing the test when there is not
// exactly one. "The header was on one of the four PUTs" is not an assertion.
func (f *fakeS3) only(t *testing.T, match func(recorded) bool) recorded {
	t.Helper()
	var found []recorded
	for _, r := range f.recorded() {
		if match(r) {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("matched %d requests, want exactly 1; requests seen: %s", len(found), f.summary())
	}
	return found[0]
}

func (f *fakeS3) object(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	return b, ok
}

func (f *fakeS3) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.objects))
	for k := range f.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (f *fakeS3) uploadsOpen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uploads)
}

func (f *fakeS3) summary() string {
	var b strings.Builder
	for _, r := range f.recorded() {
		fmt.Fprintf(&b, "\n  %s /%s/%s?%s", r.Method, r.Bucket, r.Key, r.Query.Encode())
	}
	return b.String()
}
