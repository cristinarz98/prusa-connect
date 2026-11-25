package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prusa3d/prusa-connect/internal/platform/auth"
	"github.com/prusa3d/prusa-connect/internal/platform/auth/dbstore"
	"github.com/prusa3d/prusa-connect/internal/platform/auth/session"
	"github.com/prusa3d/prusa-connect/internal/transport/http/httpapi"
	"github.com/prusa3d/prusa-connect/sdk/fault"
)

var credentialClock = time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)

// requestBearing is one request carrying a token as a bearer.
func requestBearing(token auth.Token) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/principal", nil)
	r.Header.Set("Authorization", "Bearer "+string(token))

	return r
}

// TestTheKindOfTheRowDecidesHowTheSubjectIsRead is the mapping in both
// directions. A session names a bare id and the human type is stamped on it;
// an api credential names the graph subject in full and is read as is, which
// is how a token comes to speak for a service account.
func TestTheKindOfTheRowDecidesHowTheSubjectIsRead(t *testing.T) {
	t.Parallel()

	store := auth.NewMemoryStore()
	verifier := auth.NewVerifier(store, func() time.Time { return credentialClock.Add(time.Minute) })
	principals := credentialPrincipals{inner: session.NewPrincipals(verifier, nil)}

	sessionToken, _, err := auth.Issue(t.Context(), store, "operator", auth.KindSession, credentialClock)
	require.NoError(t, err)

	personToken, _, err := auth.IssueAPI(t.Context(), store,
		auth.APISpec{Scopes: []string{"administer"}, Subject: "user:operator", Name: "mine"}, credentialClock)
	require.NoError(t, err)

	serviceToken, _, err := auth.IssueAPI(t.Context(), store,
		auth.APISpec{Scopes: []string{"administer"}, Subject: "service_account:ci", Name: "ci"}, credentialClock)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		token auth.Token
		want  string
	}{
		"a session is typed as a person":       {token: sessionToken, want: "user:operator"},
		"a person's api credential is theirs":  {token: personToken, want: "user:operator"},
		"a service account's speaks as itself": {token: serviceToken, want: "service_account:ci"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resolved, resolveErr := principals.Principal(requestBearing(tc.token))
			require.NoError(t, resolveErr)
			require.Equal(t, tc.want, resolved)
		})
	}
}

// requestStreaming is one request opening the event stream with a token as a
// bearer, which is how a client SDK subscribes.
func requestStreaming(token auth.Token) *http.Request {
	r := httptest.NewRequest(http.MethodGet, httpapi.EventsPath, nil)
	r.Header.Set("Authorization", "Bearer "+string(token))
	r.Header.Set("Accept", "text/event-stream")

	return r
}

// TestAnAPICredentialOpensTheStreamAsTheSamePrincipal is the stream half of
// the credential, through the resolver the composition root wires: the same
// path, the same graph subject, and a session still admitted beside it. The
// two ways a token stops being accepted are what the stream's re-check runs
// into, so both are held here in the words every other refusal uses.
func TestAnAPICredentialOpensTheStreamAsTheSamePrincipal(t *testing.T) {
	t.Parallel()

	store := auth.NewMemoryStore()
	clock := credentialClock
	verifier := auth.NewVerifier(store, func() time.Time { return clock })
	principals := credentialPrincipals{
		inner: session.NewPrincipals(verifier, nil, httpapi.StreamPaths()...),
	}

	sessionToken, _, err := auth.Issue(t.Context(), store, "operator", auth.KindSession, credentialClock)
	require.NoError(t, err)

	token, cred, err := auth.IssueAPI(
		t.Context(),
		store,
		auth.APISpec{
			Scopes:    []string{"administer"},
			Subject:   "user:operator",
			Name:      "sdk",
			ExpiresAt: credentialClock.Add(time.Hour),
		},
		credentialClock,
	)
	require.NoError(t, err)

	overHTTP, err := principals.Principal(requestBearing(token))
	require.NoError(t, err)

	onStream, err := principals.Principal(requestStreaming(token))
	require.NoError(t, err, "an api credential must open the stream")
	require.Equal(t, overHTTP, onStream, "the stream resolved the token to somebody else")
	require.Equal(t, "user:operator", onStream)

	asSession, err := principals.Principal(requestStreaming(sessionToken))
	require.NoError(t, err, "the session path must be as it was")
	require.Equal(t, "user:operator", asSession)

	clock = credentialClock.Add(time.Hour)

	_, err = principals.Principal(requestStreaming(token))
	require.True(t, auth.Refused(err), "an expired api credential opened the stream: %v", err)

	clock = credentialClock.Add(time.Minute)

	require.NoError(t, verifier.Revoke(t.Context(), cred.PublicID))

	_, err = principals.Principal(requestStreaming(token))
	require.True(t, auth.Refused(err), "a revoked api credential opened the stream: %v", err)

	_, err = principals.Principal(requestStreaming(sessionToken))
	require.NoError(t, err, "revoking the api credential touched the session")
}

// TestAnAPICredentialRowTheGraphCannotKeyOnIsRefused is the fail-closed half:
// a row that names no principal, however it got there, is refused in the same
// words as a bad credential rather than rendered into a subject that matches
// nothing.
func TestAnAPICredentialRowTheGraphCannotKeyOnIsRefused(t *testing.T) {
	t.Parallel()

	store := auth.NewMemoryStore()
	verifier := auth.NewVerifier(store, func() time.Time { return credentialClock.Add(time.Minute) })
	principals := credentialPrincipals{inner: session.NewPrincipals(verifier, nil)}

	for name, subject := range map[string]string{
		"a bare id":  "operator",
		"a userset":  "org:local#admin",
		"no subject": "device_credential:",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token, _, err := auth.IssueAPI(t.Context(), store,
				auth.APISpec{Scopes: []string{"administer"}, Subject: subject, Name: "n"}, credentialClock)
			require.NoError(t, err)

			_, err = principals.Principal(requestBearing(token))
			require.Error(t, err)
			require.True(t, auth.Refused(err), "it reads as any other refusal: %v", err)
		})
	}
}

// TestTheMinterRendersRowsWithoutTheSecretAndMapsTheRefusals is the adapter
// between the platform and the surface: the token is in the mint's answer and
// in nothing after it, a session is not listed as an api credential, an expiry
// in the past is the caller's code, and an unknown id is the caller's other
// code.
func TestTheMinterRendersRowsWithoutTheSecretAndMapsTheRefusals(t *testing.T) {
	t.Parallel()

	store := auth.NewMemoryStore()
	verifier := auth.NewVerifier(store, func() time.Time { return credentialClock.Add(time.Minute) })
	minter := apiCredentials{store: store, verifier: verifier, now: func() time.Time { return credentialClock }}

	_, sessionCred, err := auth.Issue(t.Context(), store, "user:operator", auth.KindSession, credentialClock)
	require.NoError(t, err)

	issued, err := minter.Issue(
		t.Context(),
		httpapi.NewCredential{Scopes: []string{"administer"}, Subject: "user:operator", Name: "nightly"},
	)
	require.NoError(t, err)
	require.NotEmpty(t, issued.Token)
	require.Equal(t, "nightly", issued.Name)
	require.Nil(t, issued.LastUsedAt, "a credential nobody has presented has no last-used time")
	require.Equal(t, credentialClock.Add(auth.APILifetime), issued.ExpiresAt)

	listed, err := minter.List(t.Context(), "user:operator")
	require.NoError(t, err)
	require.Len(t, listed, 1, "the session must not be listed as an api credential")
	require.Equal(t, issued.ID, listed[0].ID)

	_, err = minter.Get(t.Context(), sessionCred.PublicID)
	require.True(t, fault.HasCode(err, fault.AuthCredentialUnknown.Code()),
		"a session is not an api credential and must not be revocable as one: %v", err)

	_, err = minter.Get(t.Context(), "n0Such0Cr3d3nt1al00000")
	require.True(t, fault.HasCode(err, fault.AuthCredentialUnknown.Code()), "%v", err)

	_, err = minter.Issue(t.Context(), httpapi.NewCredential{
		Scopes: []string{
			"administer",
		},
		Subject:   "user:operator",
		Name:      "old",
		ExpiresAt: credentialClock.Add(-time.Hour),
	})
	require.True(t, fault.HasCode(err, fault.AuthCredentialExpired.Code()), "%v", err)

	_, err = verifier.Verify(t.Context(), auth.Token(issued.Token), auth.TransportHTTP)
	require.NoError(t, err)

	listed, err = minter.List(t.Context(), "user:operator")
	require.NoError(t, err)
	require.NotNil(t, listed[0].LastUsedAt, "presenting the credential records when")

	require.NoError(t, minter.Revoke(t.Context(), issued.ID))

	_, err = verifier.Verify(t.Context(), auth.Token(issued.Token), auth.TransportHTTP)
	require.True(t, auth.Refused(err), "a revoked credential was accepted")
}

// TestDeletingAnAccountEndsItsAPICredentialsToo is the account deletion sweep
// over the second spelling. A session is held under the bare id and an api
// credential under the graph subject, and a deleted person leaves neither.
func TestDeletingAnAccountEndsItsAPICredentialsToo(t *testing.T) {
	t.Parallel()

	host := testHost(t)

	store, err := dbstore.NewCredentials(host.db, host.engine)
	require.NoError(t, err)

	verifier := auth.NewVerifier(store, nil)

	local, err := openAccounts(t.Context(), localCore(t), host, store, verifier, discard())
	require.NoError(t, err)

	_, err = local.Setup(t.Context(), httpapi.NewAccount{Username: testOwner, Password: testPassword})
	require.NoError(t, err)

	added, err := local.Create(t.Context(), httpapi.NewAccount{
		Username: "colleague@example.com",
		Password: "another good password",
	})
	require.NoError(t, err)

	minter := apiCredentials{store: store, verifier: verifier, now: time.Now}

	theirs, err := minter.Issue(
		t.Context(),
		httpapi.NewCredential{Scopes: []string{"administer"}, Subject: "user:" + added.ID, Name: "theirs"},
	)
	require.NoError(t, err)

	_, err = verifier.Verify(t.Context(), auth.Token(theirs.Token), auth.TransportHTTP)
	require.NoError(t, err)

	require.NoError(t, local.Delete(t.Context(), added.ID))

	_, err = verifier.Verify(t.Context(), auth.Token(theirs.Token), auth.TransportHTTP)
	require.True(t, auth.Refused(err), "a deleted account kept a live api credential")
}

// TestAStolenTokenCannotMintASiblingThatOutlivesIt runs the stolen-phone case
// over the shipping composition. The token is refused a mint, so revoking it
// leaves nothing behind. A session still mints, within the upper limit.
func TestAStolenTokenCannotMintASiblingThatOutlivesIt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	running := start(t, dir, bearerStreamConfig(dir))

	owner := signUpTheOwner(t, running)
	phone := mintOver(t, running, owner, `{"name":"phone","scopes":["administer"]}`)

	sibling := send(t, running, http.MethodPost, "/api/v1/auth/credentials",
		`{"name":"sibling"}`, bearerOf(phone))
	require.Equal(t, http.StatusForbidden, sibling.status, "a token minted a sibling: %s", sibling.body)
	require.Contains(t, sibling.body, fault.AuthSessionRequired.Code().String())

	listed := send(t, running, http.MethodGet, "/api/v1/auth/credentials", "", owner)
	require.Equal(t, http.StatusOK, listed.status, listed.body)
	require.NotContains(t, listed.body, "sibling", "the refused mint left a credential behind")

	farOff := time.Now().Add(auth.APIMaxLifetime + 24*time.Hour).UTC().Format(time.RFC3339)
	tooLong := send(t, running, http.MethodPost, "/api/v1/auth/credentials",
		`{"name":"forever","expires_at":"`+farOff+`"}`, owner)
	require.Equal(t, http.StatusUnprocessableEntity, tooLong.status,
		"a session minted a credential past the upper limit: %s", tooLong.body)

	withinLimit := time.Now().Add(auth.APIMaxLifetime - 24*time.Hour).UTC().Format(time.RFC3339)
	mintOver(t, running, owner, `{"name":"a year","scopes":["administer"],"expires_at":"`+withinLimit+`"}`)
}

// TestAYearFromABrowserClockSlightlyAheadIsLoweredToTheLimit is the 365-day
// mint from a browser whose clock runs a second ahead of this server's. The
// mint is answered with the expiry lowered to 365 days from the server's now.
func TestAYearFromABrowserClockSlightlyAheadIsLoweredToTheLimit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	running := start(t, dir, bearerStreamConfig(dir))

	owner := signUpTheOwner(t, running)

	before := time.Now()
	ahead := before.Add(auth.APIMaxLifetime + time.Second).UTC().Format(time.RFC3339Nano)
	got := send(t, running, http.MethodPost, "/api/v1/auth/credentials",
		`{"name":"a year","scopes":["administer"],"expires_at":"`+ahead+`"}`, owner)
	after := time.Now()
	require.Equal(t, http.StatusCreated, got.status, "a year a second ahead was refused: %s", got.body)

	var minted struct {
		ExpiresAt time.Time `json:"expires_at"`
	}

	require.NoError(t, json.Unmarshal([]byte(got.body), &minted))
	require.False(t, minted.ExpiresAt.Before(before.Add(auth.APIMaxLifetime).Truncate(time.Second)),
		"the expiry %s was lowered below 365 days from the mint", minted.ExpiresAt)
	require.False(t, minted.ExpiresAt.After(after.Add(auth.APIMaxLifetime)),
		"the expiry %s is past 365 days from the mint", minted.ExpiresAt)
}

// TestAStolenAdministratorTokenCannotAdministerIdentity is the path around the
// mint rule. With an administrator's token alone, a caller could create an
// account, reset a password or pair an outside account, and then sign in. Each
// of those takes a session.
func TestAStolenAdministratorTokenCannotAdministerIdentity(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	running := start(t, dir, bearerStreamConfig(dir))

	owner := signUpTheOwner(t, running)
	stolen := bearerOf(mintOver(t, running, owner, `{"name":"stolen","scopes":["administer"]}`))

	added := send(t, running, http.MethodPost, "/api/v1/auth/accounts",
		`{"username":"colleague@example.com","password":"another good password"}`, owner)
	require.Equal(t, http.StatusCreated, added.status, added.body)

	var colleague httpapi.Account

	require.NoError(t, json.Unmarshal([]byte(added.body), &colleague))

	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/auth/accounts", `{"username":"intruder@example.com","password":"a known password"}`},
		{http.MethodPost, "/api/v1/auth/accounts/" + colleague.ID + "/password", `{"new_password":"a known password"}`},
		{
			http.MethodPost, "/api/v1/auth/pairings",
			`{"provider":"prusa-account","subject":"intruder","principal":"user:operator"}`,
		},
	} {
		got := send(t, running, c.method, c.path, c.body, stolen)
		require.Equalf(t, http.StatusForbidden, got.status, "%s %s answered: %s", c.method, c.path, got.body)
		require.Contains(t, got.body, fault.AuthSessionRequired.Code().String())
	}

	logInOver(t, running, "colleague@example.com", "another good password")

	listed := send(t, running, http.MethodGet, "/api/v1/auth/accounts", "", owner)
	require.Equal(t, http.StatusOK, listed.status, listed.body)
	require.NotContains(t, listed.body, "intruder", "the token created an account")
}
