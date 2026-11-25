package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ErrNoCredential reports a public id no row answers to. A Store returns it for
// a miss; anything else it returns is treated as the store being unreachable.
var ErrNoCredential = errors.New("auth: no such credential")

// ErrExpiryPassed reports an api credential asked for with an expiry that is
// not after the moment it is minted. It is a sentinel because a caller can act
// on it.
var ErrExpiryPassed = errors.New("auth: the requested expiry has already passed")

// ErrInvalidSubject reports a subject that names nobody: an empty one, or a
// type prefix with no id after it. Ending such a subject would reach rows it
// was never meant to, such as every session, whose minter is empty.
var ErrInvalidSubject = errors.New("auth: the subject names nobody")

// ValidSubject refuses a subject that names nobody.
func ValidSubject(subject string) error {
	trimmed := strings.TrimSpace(subject)
	if trimmed == "" || strings.HasSuffix(trimmed, ":") {
		return fmt.Errorf("%w: %q", ErrInvalidSubject, subject)
	}

	return nil
}

// ErrExpiryTooFar reports an api credential asked for with an expiry past
// APIMaxLifetime. It is a sentinel because a caller can act on it.
var ErrExpiryTooFar = errors.New("auth: the requested expiry is past the upper limit")

// The lifetimes of each credential kind. A broker client depends on the mqtt
// one, so shortening it would break that client.
const (
	// SessionIdle is the sliding window a browser session is kept alive by.
	SessionIdle = 12 * time.Hour
	// SessionLifetime bounds a session however active it stays.
	SessionLifetime = 7 * 24 * time.Hour
	// APILifetime is the default life of a Bearer credential.
	APILifetime = 90 * 24 * time.Hour
	// PageSessionLifetime is the longest a page session lives. It never
	// outlives the app pairing credential it stands in for
	// (ADR-20261112-nay).
	PageSessionLifetime = time.Hour
	// APIMaxLifetimeDays is the longest life a Bearer credential can ask for,
	// in days. A leaked token that nobody revokes stops working within a year.
	APIMaxLifetimeDays = 365
	// APIMaxLifetime is APIMaxLifetimeDays as a duration.
	APIMaxLifetime = APIMaxLifetimeDays * 24 * time.Hour
	// APIExpirySkew is how far past APIMaxLifetime a requested expiry may
	// reach and still be taken, lowered to APIMaxLifetime. A browser computes
	// the expiry from its own clock, and one even slightly ahead of this
	// server's pushed a 365-day request past the limit. Five minutes is the
	// usual clock-skew allowance, as in Kerberos. Lowering the expiry keeps
	// the 365-day cap.
	APIExpirySkew = 5 * time.Minute
	// MQTTLifetime is the life of a broker credential.
	MQTTLifetime = 12 * time.Hour
)

// Credential is a minted token's row. It holds no secret. Digest is the
// SHA-256 of the token's secret half, and a verify compares against that.
type Credential struct {
	PublicID string
	Subject  string
	Kind     Kind
	// Name is the label an api credential was minted under, so a listing can
	// tell one script's token from another's. A session and an mqtt credential
	// carry none.
	Name      string
	Digest    Digest
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Idle is the sliding window, zero when only ExpiresAt applies. A session
	// credential slides. An api or mqtt one does not.
	Idle time.Duration
	// LastSeen is when the credential was last verified. For a session it is
	// the anchor of the sliding window. For an api credential a listing renders
	// it as last used, and zero means never presented.
	LastSeen time.Time
	// MintedBy is the graph subject of the person who minted an api
	// credential. It is empty for a session and for a row an older build
	// wrote. A password change ends the rows its person minted.
	MintedBy string
	// Generation is the subject's generation when the credential was checked
	// for, before it was saved. A password change raises the subject's
	// generation, and a row carrying an older one is refused.
	Generation int64
	// MinterGeneration is the minter's generation when the credential was
	// checked for. It is zero when MintedBy is empty.
	MinterGeneration int64
	// CurrentGeneration and MinterCurrentGeneration are the generations the
	// store holds now, read beside the row. A lookup fills them and a save
	// ignores them.
	CurrentGeneration       int64
	MinterCurrentGeneration int64
	// RootCreator is the person at the top of the chain that minted the
	// credential. A session or a password login is its own root. A token
	// minted with a paired token names the root of that pairing, so the
	// root's password change ends the whole chain. It is empty for a session
	// and for a row an older build wrote.
	RootCreator string
	// RootGeneration is the root's generation when the credential was checked
	// for, and RootCurrentGeneration the one now, read beside the row.
	RootGeneration        int64
	RootCurrentGeneration int64
	// Scopes limit an api credential to a part of what its subject holds, as
	// the authorization graph names them. Every api credential has at least
	// one, and a row with none is refused. A session and an mqtt credential
	// carry none.
	Scopes []string
	// Origin says how an api credential was made: OriginMint for one a
	// person minted, OriginAppPairing for one an app received through a
	// pairing a person approved. It is empty for every other kind.
	Origin string
	// Parent is the app pairing credential a page session stands in for, by
	// its public id (ADR-20261112-nay). The verifier refuses the row once the
	// parent is gone or expired. It is empty for every other row.
	Parent string
}

// How an api credential was made. A listing shows the two apart, so a person
// can tell the apps they paired from the tokens they minted.
const (
	// OriginMint is a credential a person minted and copied by hand.
	OriginMint = "mint"
	// OriginAppPairing is a credential an app received through a pairing.
	OriginAppPairing = "app_pairing"
)

// ErrNoScope reports an api credential with no scope. A credential with no
// scope would read as one with no limit, so it is never minted and a row
// without one is refused.
var ErrNoScope = errors.New("auth: an api credential names at least one scope")

// Fence is the generations a caller read before it checked the credential that
// allows a mint. A password change between the check and the save then
// leaves the minted row refused.
type Fence struct {
	// Subject is the generation of the subject the credential speaks for.
	Subject int64
	// Minter is the generation of the person minting it.
	Minter int64
	// Root is the generation of the person at the top of the minting chain.
	Root int64
}

// APISpec is what an api credential is minted from.
type APISpec struct {
	// Subject is who the credential speaks for, as the graph keys them.
	Subject string
	// Name is the label the holder gave it.
	Name string
	// MintedBy is the graph subject of the person minting it.
	MintedBy string
	// RootCreator is the person at the top of the chain the mint came through.
	RootCreator string
	// ExpiresAt bounds the credential. Zero takes APILifetime from the mint.
	ExpiresAt time.Time
	// Fence is what the caller read before its check. Nil reads the current
	// generations at the mint, which is right only where no check came first.
	Fence *Fence
	// Scopes are the scopes the credential is limited to. At least one.
	Scopes []string
	// Origin is OriginMint or OriginAppPairing. Empty takes OriginMint.
	Origin string
}

// Store holds credential rows. It is a port: the in-memory implementation here
// serves the tests and a single-process install, and a persistent one plugs in
// without this package changing.
//
// Lookup reports a miss as ErrNoCredential. Every other error means the store
// could not answer, and a verify treats that as a refusal.
type Store interface {
	Lookup(ctx context.Context, publicID string) (Credential, error)
	Save(ctx context.Context, cred Credential) error
	Touch(ctx context.Context, publicID string, seen time.Time) error
	Revoke(ctx context.Context, publicID string) error
	// RevokeSubject deletes every credential held for one subject and reports
	// how many it removed. A password change calls it, so the sessions opened
	// under the old password end on every transport at once.
	RevokeSubject(ctx context.Context, subject string) (int, error)
	// Children returns the page sessions an app pairing credential opened,
	// oldest first (ADR-20261112-nay). Revoke deletes them with their parent.
	Children(ctx context.Context, parent string) ([]Credential, error)
	// ListSubject returns every credential held for one subject, oldest first.
	// A subject holding none is an empty listing and not an error.
	ListSubject(ctx context.Context, subject string) ([]Credential, error)
	// Generation returns a subject's current generation, zero for a subject
	// whose credentials never ended.
	Generation(ctx context.Context, subject string) (int64, error)
	// EndSubjects refuses a subject that names nobody with ErrInvalidSubject,
	// before it changes anything.
	//
	// EndSubjects deletes every credential of each subject whose generation is
	// below the subject's current one, and every credential a subject minted
	// for somebody else below its current one. A row of the current
	// generation, such as a session opened with the new password, stays. It
	// runs in one transaction.
	EndSubjects(ctx context.Context, subjects []string) (Ended, error)
}

// Ended counts what EndSubjects removed.
type Ended struct {
	// Held is the number of rows held by each subject, in the order given.
	Held []int
	// MintedForOthers is the number of rows the subjects minted for somebody
	// else, such as a service account.
	MintedForOthers int
}

// Issue mints a credential of the given kind for a subject and saves it, at the
// subject's current generation. The token is returned once and cannot be
// recovered from the store afterwards.
//
// A caller that checked something before the mint, such as a password, uses
// IssueAtGeneration with the generation it read before the check.
func Issue(ctx context.Context, store Store, subject string, kind Kind, now time.Time) (Token, Credential, error) {
	generation, err := store.Generation(ctx, subject)
	if err != nil {
		return "", Credential{}, fmt.Errorf("read the generation of %q: %w", subject, err)
	}

	return IssueAtGeneration(ctx, store, subject, kind, now, generation)
}

// IssueAtGeneration is Issue with the generation the caller read before its
// check. A password change that lands between the check and the save leaves
// the row refused.
func IssueAtGeneration(
	ctx context.Context, store Store, subject string, kind Kind, now time.Time, generation int64,
) (Token, Credential, error) {
	if subject == "" {
		return "", Credential{}, fmt.Errorf("%w: empty subject", ErrMalformedToken)
	}

	// An api credential carries a name and its scopes, which only IssueAPI
	// takes. One minted here would have neither.
	if kind == KindAPI {
		return "", Credential{}, fmt.Errorf("%w: mint an api credential with IssueAPI", ErrNoScope)
	}

	lifetime, idle, err := lifetimeOf(kind)
	if err != nil {
		return "", Credential{}, err
	}

	return mint(ctx, store, Credential{
		Subject:    subject,
		Kind:       kind,
		IssuedAt:   now,
		ExpiresAt:  now.Add(lifetime),
		Idle:       idle,
		LastSeen:   now,
		Generation: generation,
	})
}

// IssueAPI mints a named api credential and saves it. The token is returned
// once, like Issue's. An expiry that is not after now is refused with
// ErrExpiryPassed, and no expiry takes APILifetime. An expiry past
// APIMaxLifetime by at most APIExpirySkew is lowered to now plus
// APIMaxLifetime, and one further past is refused with ErrExpiryTooFar.
//
// LastSeen starts at zero and not at the mint. For this kind a listing renders
// it as last used, and a credential nobody has presented has not been used.
func IssueAPI(ctx context.Context, store Store, spec APISpec, now time.Time) (Token, Credential, error) {
	if spec.Subject == "" {
		return "", Credential{}, fmt.Errorf("%w: empty subject", ErrMalformedToken)
	}

	if spec.Name == "" {
		return "", Credential{}, fmt.Errorf("%w: empty name", ErrMalformedToken)
	}

	if len(spec.Scopes) == 0 {
		return "", Credential{}, ErrNoScope
	}

	origin := spec.Origin
	if origin == "" {
		origin = OriginMint
	}

	expiresAt := spec.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(APILifetime)
	}

	if !expiresAt.After(now) {
		return "", Credential{}, fmt.Errorf("%w: %s is not after %s", ErrExpiryPassed, expiresAt, now)
	}

	if expiresAt.After(now.Add(APIMaxLifetime + APIExpirySkew)) {
		return "", Credential{}, fmt.Errorf("%w: %s is more than %s after %s",
			ErrExpiryTooFar, expiresAt, APIMaxLifetime, now)
	}

	if expiresAt.After(now.Add(APIMaxLifetime)) {
		expiresAt = now.Add(APIMaxLifetime)
	}

	fence := spec.Fence
	if fence == nil {
		current, err := currentFence(ctx, store, spec)
		if err != nil {
			return "", Credential{}, err
		}

		fence = &current
	}

	minterGeneration := fence.Minter
	if spec.MintedBy == "" {
		minterGeneration = 0
	}

	rootGeneration := fence.Root
	if spec.RootCreator == "" {
		rootGeneration = 0
	}

	return mint(ctx, store, Credential{
		Subject:          spec.Subject,
		Kind:             KindAPI,
		Name:             spec.Name,
		MintedBy:         spec.MintedBy,
		Generation:       fence.Subject,
		MinterGeneration: minterGeneration,
		RootCreator:      spec.RootCreator,
		RootGeneration:   rootGeneration,
		IssuedAt:         now,
		ExpiresAt:        expiresAt,
		Scopes:           slices.Clone(spec.Scopes),
		Origin:           origin,
	})
}

// currentFence reads the generations a mint with no fence of its own is saved
// at.
func currentFence(ctx context.Context, store Store, spec APISpec) (Fence, error) {
	subject, err := store.Generation(ctx, spec.Subject)
	if err != nil {
		return Fence{}, fmt.Errorf("read the generation of %q: %w", spec.Subject, err)
	}

	fence := Fence{Subject: subject}

	if spec.MintedBy != "" {
		fence.Minter, err = store.Generation(ctx, spec.MintedBy)
		if err != nil {
			return Fence{}, fmt.Errorf("read the generation of %q: %w", spec.MintedBy, err)
		}
	}

	if spec.RootCreator != "" {
		fence.Root, err = store.Generation(ctx, spec.RootCreator)
		if err != nil {
			return Fence{}, fmt.Errorf("read the generation of %q: %w", spec.RootCreator, err)
		}
	}

	return fence, nil
}

// mint draws the token, fills the row's public half and digest, and saves it.
func mint(ctx context.Context, store Store, cred Credential) (Token, Credential, error) {
	token, publicID, digest, err := Mint()
	if err != nil {
		return "", Credential{}, err
	}

	cred.PublicID = publicID
	cred.Digest = digest

	if saveErr := store.Save(ctx, cred); saveErr != nil {
		return "", Credential{}, fmt.Errorf("save credential: %w", saveErr)
	}

	return token, cred, nil
}

// Live reports whether the credential is still valid at now, against both its
// absolute expiry and its idle window.
func (c Credential) Live(now time.Time) bool {
	if !now.Before(c.ExpiresAt) {
		return false
	}

	return c.Idle == 0 || now.Before(c.LastSeen.Add(c.Idle))
}

// upperLimitOf is the longest a credential of a kind may live from its issue,
// whatever expiry its row names. A kind this server never mints has none.
func upperLimitOf(kind Kind) (time.Duration, bool) {
	switch kind {
	case KindSession:
		return SessionLifetime, true
	case KindAPI:
		return APIMaxLifetime, true
	case KindMQTT:
		return MQTTLifetime, true
	case KindPrusaAccount, KindUnknown:
		return 0, false
	default:
		return 0, false
	}
}

func lifetimeOf(kind Kind) (lifetime time.Duration, idle time.Duration, err error) {
	switch kind {
	case KindSession:
		return SessionLifetime, SessionIdle, nil
	case KindAPI:
		return APILifetime, 0, nil
	case KindMQTT:
		return MQTTLifetime, 0, nil
	case KindPrusaAccount:
		// Another issuer minted it and set its life. There is no row to
		// write, so there is nothing to issue.
		return 0, 0, fmt.Errorf("%w: a %s credential is verified, never minted", ErrMalformedToken, kind)
	case KindUnknown:
		return 0, 0, fmt.Errorf("%w: no kind", ErrMalformedToken)
	default:
		return 0, 0, fmt.Errorf("%w: kind %d", ErrMalformedToken, kind)
	}
}
