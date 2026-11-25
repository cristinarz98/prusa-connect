package auth

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var mintedAt = time.Date(2026, time.September, 9, 10, 0, 0, 0, time.UTC)

// The row holds the SHA-256 of the secret half and nothing a caller could
// present. The token text exists only in the value the mint returned.
func TestAnAPICredentialIsStoredAsAHashAndReturnedOnce(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	token, cred, err := IssueAPI(
		t.Context(),
		store,
		APISpec{Scopes: []string{"administer"}, Subject: "user:ada", Name: "nightly export"},
		mintedAt,
	)
	require.NoError(t, err)

	publicID, secret, err := Split(token)
	require.NoError(t, err)
	require.Equal(t, publicID, cred.PublicID)

	rows := store.Rows()
	require.Len(t, rows, 1)

	stored := rows[publicID]
	require.Equal(t, KindAPI, stored.Kind)
	require.Equal(t, "nightly export", stored.Name)
	require.Equal(t, "user:ada", stored.Subject)
	require.Equal(t, Digest(sha256.Sum256([]byte(secret))), stored.Digest,
		"the row holds the digest of the secret half")
	require.NotContains(t, string(stored.Digest[:]), secret, "the row must not hold the secret")
	require.Zero(t, stored.Idle, "an api credential does not slide")
	require.True(t, stored.LastSeen.IsZero(), "a credential nobody has presented has no last-used time")
}

// The expiries a mint can produce, the ones it lowers to the upper limit, and
// the ones it refuses.
func TestAnAPICredentialTakesTheDefaultLifetimeOrTheOneAskedFor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		expiresAt time.Time
		want      time.Time
		refused   error
	}{
		{name: "no expiry takes ninety days", want: mintedAt.Add(APILifetime)},
		{name: "an expiry in the future is kept", expiresAt: mintedAt.Add(time.Hour), want: mintedAt.Add(time.Hour)},
		{name: "an expiry equal to now is refused", expiresAt: mintedAt, refused: ErrExpiryPassed},
		{name: "an expiry in the past is refused", expiresAt: mintedAt.Add(-time.Minute), refused: ErrExpiryPassed},
		{
			name: "an expiry at the upper limit is kept", expiresAt: mintedAt.Add(APIMaxLifetime),
			want: mintedAt.Add(APIMaxLifetime),
		},
		{
			name:      "an expiry a millisecond past the upper limit is lowered to it",
			expiresAt: mintedAt.Add(APIMaxLifetime + time.Millisecond), want: mintedAt.Add(APIMaxLifetime),
		},
		{
			name:      "an expiry a second past the upper limit is lowered to it",
			expiresAt: mintedAt.Add(APIMaxLifetime + time.Second), want: mintedAt.Add(APIMaxLifetime),
		},
		{
			name:      "an expiry five minutes past the upper limit is lowered to it",
			expiresAt: mintedAt.Add(APIMaxLifetime + 5*time.Minute), want: mintedAt.Add(APIMaxLifetime),
		},
		{
			name:      "an expiry just past the clock-skew margin is refused",
			expiresAt: mintedAt.Add(APIMaxLifetime + 5*time.Minute + time.Millisecond), refused: ErrExpiryTooFar,
		},
		{
			name:      "an expiry a day past the upper limit is refused",
			expiresAt: mintedAt.Add(APIMaxLifetime + 24*time.Hour), refused: ErrExpiryTooFar,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMemoryStore()

			_, cred, err := IssueAPI(t.Context(), store, APISpec{
				Scopes: []string{"administer"}, Subject: "user:ada", Name: "n", ExpiresAt: tc.expiresAt,
			}, mintedAt)

			if tc.refused != nil {
				require.ErrorIs(t, err, tc.refused)
				require.Empty(t, store.Rows(), "a refused mint must save nothing")

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, cred.ExpiresAt)
		})
	}
}

// A token cannot be minted for nobody, or with nothing to find it by later.
func TestAnAPICredentialNeedsASubjectAndAName(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()

	_, _, err := IssueAPI(t.Context(), store, APISpec{Scopes: []string{"administer"}, Name: "n"}, mintedAt)
	require.ErrorIs(t, err, ErrMalformedToken)

	_, _, err = IssueAPI(t.Context(), store, APISpec{Scopes: []string{"administer"}, Subject: "user:ada"}, mintedAt)
	require.ErrorIs(t, err, ErrMalformedToken)

	require.Empty(t, store.Rows())
}

// The life is absolute. The credential is admitted up to its expiry and refused
// after it, in the same words as a token that was never minted.
func TestAnAPICredentialExpiresWhenItWasToldTo(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	now := mintedAt
	verifier := NewVerifier(store, func() time.Time { return now })

	token, _, err := IssueAPI(t.Context(), store, APISpec{
		Scopes: []string{"administer"}, Subject: "user:ada", Name: "short", ExpiresAt: mintedAt.Add(time.Hour),
	}, mintedAt)
	require.NoError(t, err)

	now = mintedAt.Add(59 * time.Minute)
	cred, err := verifier.Verify(t.Context(), token, TransportHTTP)
	require.NoError(t, err)
	require.Equal(t, "user:ada", cred.Subject)
	require.Equal(t, now, cred.LastSeen, "a presented credential records when it was used")

	now = mintedAt.Add(time.Hour)
	_, expiredErr := verifier.Verify(t.Context(), token, TransportHTTP)
	require.Error(t, expiredErr)
	requireIndistinguishableRefusal(t, expiredErr)

	neverMinted, _, _, err := Mint()
	require.NoError(t, err)

	_, unknownErr := verifier.Verify(t.Context(), neverMinted, TransportHTTP)
	requireSameRendering(t, expiredErr, unknownErr)
}

// After a revocation the next request is refused and the subject's listing does
// not show the credential.
func TestARevokedAPICredentialIsRefusedAndGoneFromTheListing(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	verifier := NewVerifier(store, func() time.Time { return mintedAt.Add(time.Minute) })

	first, kept, err := IssueAPI(
		t.Context(),
		store,
		APISpec{Scopes: []string{"administer"}, Subject: "user:ada", Name: "kept"},
		mintedAt,
	)
	require.NoError(t, err)

	second, revoked, err := IssueAPI(t.Context(), store,
		APISpec{Scopes: []string{"administer"}, Subject: "user:ada", Name: "revoked"}, mintedAt.Add(time.Second))
	require.NoError(t, err)

	_, _, err = IssueAPI(
		t.Context(),
		store,
		APISpec{Scopes: []string{"administer"}, Subject: "user:bob", Name: "somebody else's"},
		mintedAt,
	)
	require.NoError(t, err)

	held, err := store.ListSubject(t.Context(), "user:ada")
	require.NoError(t, err)
	require.Len(t, held, 2)
	require.Equal(t, []string{kept.PublicID, revoked.PublicID}, []string{held[0].PublicID, held[1].PublicID},
		"the listing is oldest first")

	require.NoError(t, verifier.Revoke(t.Context(), revoked.PublicID))

	_, err = verifier.Verify(t.Context(), second, TransportHTTP)
	require.Error(t, err, "a revoked credential is refused on the next request")

	_, err = verifier.Verify(t.Context(), first, TransportHTTP)
	require.NoError(t, err, "revoking one credential leaves the subject's others in force")

	held, err = store.ListSubject(t.Context(), "user:ada")
	require.NoError(t, err)
	require.Len(t, held, 1)
	require.Equal(t, kept.PublicID, held[0].PublicID)

	other, err := store.ListSubject(t.Context(), "user:bob")
	require.NoError(t, err)
	require.Len(t, other, 1, "another subject's listing is untouched")

	none, err := store.ListSubject(t.Context(), "user:nobody")
	require.NoError(t, err)
	require.Empty(t, none, "a subject holding nothing is an empty listing and not an error")
}

// An api credential is accepted on the stream the way a session is. Revocation
// and expiry refuse it there in the same words as everywhere else. The stream
// re-verifies on a tick, so that refusal ends a stream that is already open.
func TestAnAPICredentialOpensTheStreamUntilItIsRevokedOrExpires(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	clock := mintedAt
	verifier := NewVerifier(store, func() time.Time { return clock })

	token, cred, err := IssueAPI(
		t.Context(),
		store,
		APISpec{
			Scopes:    []string{"administer"},
			Subject:   "user:ada",
			Name:      "n",
			ExpiresAt: mintedAt.Add(time.Hour),
		},
		mintedAt,
	)
	require.NoError(t, err)

	clock = mintedAt.Add(time.Minute)

	resolved, err := verifier.Verify(t.Context(), token, TransportSSE)
	require.NoError(t, err, "an api credential must open the stream")
	require.Equal(t, "user:ada", resolved.Subject)
	require.Equal(t, KindAPI, resolved.Kind)

	clock = mintedAt.Add(time.Hour)

	_, err = verifier.Verify(t.Context(), token, TransportSSE)
	require.Error(t, err, "an expired api credential must be refused on the stream")
	requireIndistinguishableRefusal(t, err)

	clock = mintedAt.Add(time.Minute)

	_, err = verifier.Verify(t.Context(), token, TransportSSE)
	require.NoError(t, err, "the same credential is accepted again inside its life")

	require.NoError(t, verifier.Revoke(t.Context(), cred.PublicID))

	_, err = verifier.Verify(t.Context(), token, TransportSSE)
	require.Error(t, err, "a revoked api credential must be refused on the stream")
	requireIndistinguishableRefusal(t, err)
}

// ListSubject is fail-closed. A listing that answered empty for a broken store
// would read as a subject holding nothing.
func TestAListingOverAStoreThatCannotAnswerIsAnError(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	broken := errors.New("database is unreachable")

	_, _, err := IssueAPI(
		t.Context(),
		store,
		APISpec{Scopes: []string{"administer"}, Subject: "user:ada", Name: "n"},
		mintedAt,
	)
	require.NoError(t, err)

	store.Break(broken)

	_, err = store.ListSubject(t.Context(), "user:ada")
	require.ErrorIs(t, err, broken)
}
