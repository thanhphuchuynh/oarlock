// Package s3store writes recordings to an S3-compatible bucket under an object
// lock, and reports what that lock actually is.
//
// # Why this exists
//
// record.FileStore reports ModeMutable, and it is telling the truth: anything with
// write access to a directory can alter or delete a recording. The hash chain and
// the signed manifest make that *detectable*, which is not the same as impossible —
// detection tells you afterwards, and afterwards is when somebody is already asking
// why the recording disagrees with the incident report. Object Lock is where the
// difference lives, so this is the backend that can answer "can your administrator
// delete the evidence?" with no.
//
// # Why a dependency
//
// record.Store.Create returns an io.WriteCloser and the spool writes to it
// incrementally, so the backend receives a stream whose final length is unknown.
// On S3 that means a multipart upload — CreateMultipartUpload, UploadPart × N,
// CompleteMultipartUpload, and AbortMultipartUpload on any failure — on top of SigV4
// and presigned URLs. That is a large security-adjacent surface where a mistake is
// silent, and a leaked multipart upload costs storage nobody is looking at. So this
// package is a thin layer over minio-go rather than a hand-rolled S3 client, and the
// same code reaches AWS S3, MinIO, Ceph or Backblaze.
//
// # What it will not do
//
// It will not report a guarantee it has not checked. Immutability asks the bucket
// and reports the answer; a bucket with no object lock is ModeMutable even when this
// package's own Config asked for compliance. A guarantee an operator types into a
// config file is a guarantee nobody checked, and every manifest written afterwards
// records the storage claim in its own signed JSON.
//
// # What "locked" means on S3, exactly
//
// S3 requires versioning for Object Lock, so a lock does not make a key unwritable —
// it makes each *version* undeletable until its retain-until date. Somebody with
// bucket write access can still PUT a doctored recording over the key, and Get will
// serve it, because Get reads the latest version. What they cannot do is remove the
// locked original, and they cannot produce a manifest that verifies: the signing key
// is deliberately somewhere the recording store cannot reach. So the lock's job is to
// keep the real recording recoverable while the signature keeps the fake one
// detectable, and neither substitutes for the other.
package s3store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/oarlock/oarlock/internal/record"
	"github.com/oarlock/oarlock/pkg/plugin"
)

// kind is what a manifest records as the store that wrote it.
const kind = "s3"

const (
	castExt     = ".cast"
	manifestExt = ".manifest.json"
)

// minPartSize is minio-go's floor (OptimalPartInfo refuses anything smaller), and
// also the default here.
//
// The default is the floor rather than minio-go's own 16 MiB because a part buffer
// is held per live recording: the streaming upload fills one part in memory before
// sending it. 5 MiB per concurrent recorded session is a cost worth paying; 16 MiB
// across a fleet is a surprise. It still allows a 50 GiB recording, which is far
// more terminal output than anybody will watch.
const minPartSize = 5 << 20

// The error codes S3 and its cousins use for "this bucket has no object lock". AWS
// and MinIO disagree on the spelling, and a store that only knew one of them would
// report ModeUnknown for a perfectly ordinary unlocked bucket — which reads as "the
// store is broken" rather than "there is no lock here".
const (
	lockNotConfiguredAWS   = "ObjectLockConfigurationNotFoundError"
	lockNotConfiguredMinIO = "ObjectLockConfigurationNotFound"
)

// Config describes the bucket and the lock to ask for.
type Config struct {
	// Bucket is required.
	Bucket string
	// Region is the signing region. Empty means minio-go looks the bucket's region
	// up, which works on AWS and costs a request at startup.
	Region string
	// Endpoint is empty for AWS, or host[:port] for MinIO, Ceph, Backblaze. A
	// scheme is tolerated and decides UseSSL.
	Endpoint string
	// Prefix is the key prefix, e.g. "recordings". Empty puts objects at the root.
	Prefix string

	// AccessKey and SecretKey are empty to take credentials from the environment —
	// AWS_ACCESS_KEY_ID and friends, ~/.aws/credentials, or the instance's IAM
	// role. Nothing here is ever logged.
	AccessKey string
	SecretKey string

	// UseSSL is ignored when Endpoint is empty: there is no plaintext AWS S3.
	UseSSL bool

	// LockMode is the lock to *ask* for: record.ModeCompliance,
	// record.ModeGovernance, or empty (also record.ModeMutable) for none. What gets
	// reported is what the bucket says, which is not the same thing.
	LockMode record.Mode
	// RetainFor is how long each object is locked. Required when LockMode asks for
	// a lock: S3 needs a retain-until date, not just a mode.
	RetainFor time.Duration

	// PartSize is the multipart part size. Zero means minPartSize; anything below
	// it is refused here rather than at the first recording.
	PartSize uint64

	// Now exists so a test can pin the retain-until date exactly.
	Now func() time.Time
}

// Store is a record.Store backed by a bucket.
type Store struct {
	cfg Config
	c   *minio.Client
	// requested is LockMode normalised: empty means no lock was asked for.
	requested record.Mode
}

var (
	_ record.Store                = (*Store)(nil)
	_ record.ImmutabilityReporter = (*Store)(nil)
)

// Open validates the configuration and builds the client.
//
// It deliberately talks to nobody. A gateway that could not start because a bucket
// was briefly unreachable would be a worse failure than one that starts and reports
// ModeUnknown, which the boot gate can then refuse on its own terms.
func Open(cfg Config) (*Store, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3store: Bucket is required")
	}

	requested, err := requestedMode(cfg.LockMode)
	if err != nil {
		return nil, err
	}
	if requested != "" && cfg.RetainFor <= 0 {
		return nil, fmt.Errorf("s3store: RetainFor is required for lock mode %q — "+
			"S3 locks an object until a date, so a mode without a period is not a lock",
			cfg.LockMode)
	}
	switch {
	case cfg.PartSize == 0:
		cfg.PartSize = minPartSize
	case cfg.PartSize < minPartSize:
		return nil, fmt.Errorf("s3store: PartSize %d is below S3's minimum of %d",
			cfg.PartSize, minPartSize)
	}

	endpoint, secure := endpointFor(cfg)
	c, err := minio.New(endpoint, &minio.Options{
		Creds:  credsFor(cfg),
		Secure: secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("s3store: %w", err)
	}
	return &Store{cfg: cfg, c: c, requested: requested}, nil
}

// requestedMode narrows a record.Mode to the two an object lock can express.
//
// ModeDeclared and ModeUnknown are refused rather than silently downgraded: they are
// answers a store *gives*, not locks anybody can ask for, and a config that named one
// is a config whose author expected something this cannot do.
func requestedMode(m record.Mode) (record.Mode, error) {
	switch m {
	case "", record.ModeMutable:
		return "", nil
	case record.ModeCompliance, record.ModeGovernance:
		return m, nil
	}
	return "", fmt.Errorf("s3store: lock mode %q is not something an object lock can "+
		"express; use %q, %q, or none", m, record.ModeCompliance, record.ModeGovernance)
}

// endpointFor resolves the host to talk to and whether to use TLS.
func endpointFor(cfg Config) (string, bool) {
	if cfg.Endpoint == "" {
		// Regional rather than the global s3.amazonaws.com, so a request is not
		// answered with a redirect that has to be followed for every object.
		if cfg.Region != "" {
			return "s3." + cfg.Region + ".amazonaws.com", true
		}
		return "s3.amazonaws.com", true
	}
	// An operator will paste what their console shows them, which has a scheme on
	// it. Taking the scheme's word for TLS is less surprising than ignoring it and
	// connecting in plaintext because a separate boolean was left at its zero value.
	switch {
	case strings.HasPrefix(cfg.Endpoint, "https://"):
		return strings.TrimPrefix(cfg.Endpoint, "https://"), true
	case strings.HasPrefix(cfg.Endpoint, "http://"):
		return strings.TrimPrefix(cfg.Endpoint, "http://"), false
	}
	return cfg.Endpoint, cfg.UseSSL
}

// credsFor returns static credentials when they were configured, and otherwise the
// usual chain: the AWS and MinIO environment variables, ~/.aws/credentials, then the
// instance's IAM role. An empty AccessKey means "not in the config file", which is
// where a deployment that would rather not write a secret to disk wants to be.
func credsFor(cfg Config) *credentials.Credentials {
	if cfg.AccessKey != "" {
		return credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	}
	return credentials.NewChainCredentials([]credentials.Provider{
		&credentials.EnvAWS{},
		&credentials.EnvMinio{},
		&credentials.FileAWSCredentials{},
		&credentials.IAM{},
	})
}

func (s *Store) now() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

// key is the object key for a session, and the reason it is this shape rather than
// something sharded by date: somebody holding bucket credentials and no gateway has
// to be able to find a recording by session id. `aws s3 cp s3://bucket/recordings/
// <id>.cast .` should be the whole procedure.
func (s *Store) key(sessionID, ext string) string {
	return path.Join(strings.Trim(s.cfg.Prefix, "/"), sessionID+ext)
}

// putOptions carries the lock. Every object this store writes goes through it,
// because a locked recording beside an editable manifest is not evidence: the
// manifest holds the signature and the chain head, so whoever can rewrite it can
// re-sign a doctored chain.
func (s *Store) putOptions(contentType string) minio.PutObjectOptions {
	opts := minio.PutObjectOptions{
		ContentType: contentType,
		PartSize:    s.cfg.PartSize,
	}
	switch s.requested {
	case record.ModeCompliance:
		opts.Mode = minio.Compliance
	case record.ModeGovernance:
		opts.Mode = minio.Governance
	default:
		// No lock asked for, so no lock headers. S3 rejects them outright on a
		// bucket without Object Lock, and a lab with an ordinary bucket has to
		// still be able to record.
		return opts
	}
	opts.RetainUntilDate = s.now().UTC().Add(s.cfg.RetainFor)
	return opts
}

// ── writing ─────────────────────────────────────────────────────────────────────

// Create opens the recording stream as a multipart upload.
func (s *Store) Create(ctx context.Context, m *plugin.SessionMeta) (io.WriteCloser, error) {
	if m == nil || m.SessionID == "" {
		return nil, errors.New("s3store: SessionID is required")
	}
	if err := safeID(m.SessionID); err != nil {
		return nil, err
	}

	// The upload deliberately outlives the context Create was given. A session ends
	// because its transport went away, and the last bytes of a recording are written
	// after that — sessionrun finalises under context.WithoutCancel for the same
	// reason. Cancelling here would abort the multipart upload and throw the
	// evidence away at the exact moment it became interesting.
	upCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	pr, pw := io.Pipe()
	w := &castWriter{pw: pw, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(w.done)
		// Size -1: the length is unknown, so minio-go streams parts until EOF and
		// aborts the upload itself on any failure.
		_, err := s.c.PutObject(upCtx, s.cfg.Bucket, s.key(m.SessionID, castExt),
			pr, -1, s.putOptions("application/x-asciicast"))
		if err != nil {
			err = fmt.Errorf("s3store: uploading the recording: %w", err)
		}
		w.err = err
		// Once PutObject has returned, nothing is reading the other end. Closing it
		// makes any further Write fail rather than block, which matters because the
		// blocked writer would be the spool's drain goroutine: a failing store has
		// to fail the session, not hold it open forever.
		if err == nil {
			err = errUploadOver
		}
		pr.CloseWithError(err)
	}()
	return w, nil
}

// errUploadOver is what a Write sees after a clean upload has already completed.
var errUploadOver = errors.New("s3store: the recording upload is already closed")

// castWriter is the io.WriteCloser the spool drives. It is a pipe into a streaming
// multipart upload running in its own goroutine.
type castWriter struct {
	pw     *io.PipeWriter
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	// err is written by the upload goroutine before done is closed, and read only
	// after it, so the channel carries the happens-before.
	err error
}

func (w *castWriter) Write(p []byte) (int, error) { return w.pw.Write(p) }

// Close finishes the upload and reports whether it landed.
//
// It waits for the upload rather than returning immediately, because the caller uses
// this answer to decide whether the session was recorded — and "probably" is not an
// answer to give about evidence.
func (w *castWriter) Close() error {
	w.once.Do(func() {
		_ = w.pw.Close() // EOF: minio-go completes the upload with the parts it has
		<-w.done
		w.cancel()
	})
	return w.err
}

// PutManifest stores the sidecar under the same lock as the recording.
func (s *Store) PutManifest(ctx context.Context, sessionID string, b []byte) error {
	if err := safeID(sessionID); err != nil {
		return err
	}
	_, err := s.c.PutObject(ctx, s.cfg.Bucket, s.key(sessionID, manifestExt),
		bytes.NewReader(b), int64(len(b)), s.putOptions("application/json"))
	if err != nil {
		return fmt.Errorf("s3store: writing the manifest: %w", err)
	}
	return nil
}

// ── reading ─────────────────────────────────────────────────────────────────────

// Get streams a recording back.
func (s *Store) Get(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	if err := safeID(sessionID); err != nil {
		return nil, err
	}
	key := s.key(sessionID, castExt)
	obj, err := s.c.GetObject(ctx, s.cfg.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, s.readErr(err, sessionID, key)
	}
	// minio-go defers the request until the first Read, which would surface a
	// missing recording as a read error somewhere downstream. Stat forces it now so
	// the caller gets record.ErrNotFound from Get, which is what it switches on.
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		return nil, s.readErr(err, sessionID, key)
	}
	return obj, nil
}

// GetManifest reads the sidecar whole.
func (s *Store) GetManifest(ctx context.Context, sessionID string) ([]byte, error) {
	if err := safeID(sessionID); err != nil {
		return nil, err
	}
	key := s.key(sessionID, manifestExt)
	obj, err := s.c.GetObject(ctx, s.cfg.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, s.readErr(err, sessionID, key)
	}
	defer obj.Close()
	b, err := io.ReadAll(obj)
	if err != nil {
		return nil, s.readErr(err, sessionID, key)
	}
	return b, nil
}

// readErr turns a missing object into record.ErrNotFound and leaves everything else
// alone. Callers switch on the difference: "no such recording" is a 404 in the
// console, and "the store is unreachable" is a page.
func (s *Store) readErr(err error, sessionID, key string) error {
	if minio.ToErrorResponse(err).Code == minio.NoSuchKey {
		return fmt.Errorf("%w: %s (%s)", record.ErrNotFound, sessionID, key)
	}
	return fmt.Errorf("s3store: reading %s: %w", key, err)
}

// URL returns a presigned GET.
//
// Unlike FileStore's, this must not answer plugin.ErrUnsupported: it is the method
// that keeps replay from streaming a recording through the gateway, and a bucket
// genuinely does have a shareable link to hand out.
func (s *Store) URL(ctx context.Context, sessionID string, ttl time.Duration) (string, error) {
	if err := safeID(sessionID); err != nil {
		return "", err
	}
	if ttl <= 0 {
		return "", errors.New("s3store: a presigned URL needs a TTL; a link that " +
			"never expires is not time-limited")
	}
	u, err := s.c.PresignedGetObject(ctx, s.cfg.Bucket, s.key(sessionID, castExt),
		ttl, url.Values{})
	if err != nil {
		return "", fmt.Errorf("s3store: presigning %s: %w", sessionID, err)
	}
	return u.String(), nil
}

// ── immutability ────────────────────────────────────────────────────────────────

// Immutability asks the bucket and reports the answer.
//
// This is the method the whole backend is for, and the rule it holds to is that the
// store reports what the bucket says and never what the config says. A bucket with no
// object lock is ModeMutable even when Config asked for compliance, because otherwise
// an operator gets a green light and no lock — and safety.Settings takes this value
// as the *reported* guarantee, on which the boot gate then refuses to start.
//
// An error is a real answer too. record.immutabilityOf turns it into ModeUnknown,
// which Mode.Protected() excludes: a store nobody could reach has not promised
// anything.
func (s *Store) Immutability(ctx context.Context) (record.Immutability, error) {
	enabled, mode, validity, unit, err := s.c.GetObjectLockConfig(ctx, s.cfg.Bucket)
	if err != nil {
		switch minio.ToErrorResponse(err).Code {
		case lockNotConfiguredAWS, lockNotConfiguredMinIO:
			return s.mutable("the bucket has no object lock configuration"), nil
		case minio.NotImplemented, minio.APINotSupported:
			return s.mutable("this S3 implementation does not support object lock"), nil
		}
		// Kind even on the error path: record.immutabilityOf keeps it, so the
		// operator's warning and any manifest written afterwards still name which
		// store failed to answer rather than reporting an anonymous "unknown".
		return record.Immutability{Kind: kind}, fmt.Errorf(
			"s3store: reading the object lock configuration of %s: %w", s.cfg.Bucket, err)
	}
	if !strings.EqualFold(enabled, "Enabled") {
		return s.mutable("object lock is not enabled on the bucket"), nil
	}

	// What the bucket's own default retention rule says, if it has one. Without a
	// rule the bucket locks nothing by itself; it only honours the mode each PUT
	// carries, which is what putOptions sends.
	bucketMode := modeOf(mode)
	bucketFor := validityAsDuration(validity, unit)

	switch {
	case bucketMode == "" && s.requested == "":
		return s.mutable("object lock is enabled but neither the bucket nor this " +
			"gateway asks for a retention mode, so nothing is locked"), nil

	case s.requested == "":
		// Nothing configured here, so putOptions sends no mode and the bucket's own
		// default is what every object gets, ours included.
		return record.Immutability{
			Mode: bucketMode, Kind: kind, RetainFor: bucketFor,
			Detail: fmt.Sprintf("%s has object lock enabled with a default "+
				"retention of %s for %s, and this gateway asks for no mode of its "+
				"own", s.cfg.Bucket, bucketMode, bucketFor.Round(time.Hour)),
		}, nil

	default:
		// Every PUT carries its own mode and retain-until date, and S3 honours a
		// per-object mode over the bucket default. So this is what a recording and
		// its manifest actually get — and it is the honest answer even when the
		// bucket's default rule is weaker, because reporting the default would
		// understate the lock on the very object whose manifest records this.
		//
		// An earlier version reported the weaker of the two and called it caution.
		// It was not: it wrote "governance" into the manifest of an object S3 had
		// locked in compliance mode, and this package's standard is accuracy, not
		// pessimism. ModeUnknown is treated as mutable because nobody *knows*,
		// which is a different thing from understating what was measured.
		//
		// The bucket default still matters and it answers a different question —
		// what covers a write that did not come from this gateway. A gap in what
		// *else* is covered is not a weaker lock on the object in hand, so it goes
		// in the detail, where the person reading a manifest years later can see
		// both facts instead of one number that blurs them.
		return record.Immutability{
			Mode: s.requested, Kind: kind, RetainFor: s.cfg.RetainFor,
			Detail: fmt.Sprintf("each recording and manifest is written with %s "+
				"retention for %s; %s", s.requested,
				s.cfg.RetainFor.Round(time.Hour),
				elsewhere(s.cfg.Bucket, bucketMode, bucketFor)),
		}, nil
	}
}

// elsewhere describes what the bucket's own default rule covers, which is not the
// same question as what this gateway's PUTs get: it is what happens to a recording
// written by something that is not this gateway — a migration script, an older
// build, a second deployment pointed at the same bucket.
func elsewhere(bucket string, bucketMode record.Mode, bucketFor time.Duration) string {
	if bucketMode == "" {
		return fmt.Sprintf("%s has no default retention rule, so an object written "+
			"by anything other than this gateway is not locked at all", bucket)
	}
	return fmt.Sprintf("%s defaults to %s retention for %s, which is what an object "+
		"written by anything other than this gateway gets", bucket, bucketMode,
		bucketFor.Round(time.Hour))
}

// mutable is the honest answer for a bucket that cannot lock anything, and it says
// out loud when that contradicts what was configured — because that contradiction is
// what the boot gate exists to refuse.
func (s *Store) mutable(why string) record.Immutability {
	const consequence = ": anything with write access can alter or delete a recording, " +
		"and the signature is the only thing that makes it detectable"
	detail := why + consequence
	if s.requested != "" {
		// `why` once, not twice. It used to be prefixed here and then again inside
		// the string this wrapped, and the doubled clause landed in the middle of
		// the boot gate's refusal — which is the one line an operator has to be
		// able to read to learn the fix.
		detail = fmt.Sprintf("%s, but this gateway is configured to ask for %s "+
			"retention%s", why, s.requested, consequence)
	}
	return record.Immutability{Mode: record.ModeMutable, Kind: kind, Detail: detail}
}

// modeOf maps S3's retention mode onto record.Mode. A nil or unrecognised mode means
// the bucket has no default retention rule to report.
func modeOf(m *minio.RetentionMode) record.Mode {
	if m == nil {
		return ""
	}
	switch *m {
	case minio.Compliance:
		return record.ModeCompliance
	case minio.Governance:
		return record.ModeGovernance
	}
	return ""
}

// validityAsDuration converts a bucket's default retention into a duration. S3
// expresses it in whole days or years; a year here is 365 days, which is close
// enough for a number a human reads out of a manifest.
func validityAsDuration(validity *uint, unit *minio.ValidityUnit) time.Duration {
	if validity == nil || unit == nil {
		return 0
	}
	d := 24 * time.Hour * time.Duration(*validity)
	if *unit == minio.Years {
		d *= 365
	}
	return d
}

// safeID checks an id before it becomes part of a key. The format is constrained
// upstream; this is the second line, at the boundary where a "../" would turn one
// session's recording into another's.
func safeID(id string) error {
	if id == "" || strings.ContainsAny(id, "/\\") || id == "." || id == ".." ||
		strings.Contains(id, "..") {
		return fmt.Errorf("s3store: unsafe session id %q", id)
	}
	return nil
}
