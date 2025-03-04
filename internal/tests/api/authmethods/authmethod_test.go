package authmethods_test

import (
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers/controller"
	tests_api "github.com/hashicorp/boundary/internal/tests/api"
	capoidc "github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const global = "global"

func TestCrud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	eventConfig := event.TestEventerConfig(t, "TestCrud", event.TestWithAuditSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(event.InitSysEventer(testLogger, testLock, "TestCrud", event.WithEventerConfig(&eventConfig.EventerConfig)))
	tcConfig, err := config.DevController()
	require.NoError(err)
	tcConfig.Eventing = &eventConfig.EventerConfig

	tc := controller.NewTestController(t, &controller.TestControllerOpts{Config: tcConfig})
	t.Cleanup(tc.Shutdown)

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := authmethods.NewClient(client)

	checkAuthMethod := func(step string, u *authmethods.AuthMethod, wantedName string, wantedVersion uint32) {
		require.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != "" {
			gotName = u.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	require.NotNil(eventConfig.AuditEvents)
	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	pw, err := amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("bar"))
	require.NoError(err)
	t.Cleanup(func() {
		_, err = amClient.Delete(tc.Context(), pw.Item.Id)
		require.NoError(err)
	})
	checkAuthMethod("create", pw.Item, "bar", 1)

	got := tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())
	reqItem := tests_api.GetEventDetails(t, got, "request")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, reqItem)
	tests_api.AssertRedactedValues(t, reqItem["Attrs"])
	tests_api.AssertRedactedValues(t, reqItem["Attrs"].(map[string]interface{})["PasswordAuthMethodAttributes"])

	respItem := tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["Attrs"])
	tests_api.AssertRedactedValues(t, respItem["Attrs"].(map[string]interface{})["PasswordAuthMethodAttributes"])

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	pw, err = amClient.Read(tc.Context(), pw.Item.Id)
	require.NoError(err)
	checkAuthMethod("read", pw.Item, "bar", 1)

	got = tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())
	tests_api.AssertRedactedValues(t, tests_api.GetEventDetails(t, got, "request"))

	respItem = tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["Attrs"])
	tests_api.AssertRedactedValues(t, respItem["Attrs"].(map[string]interface{})["PasswordAuthMethodAttributes"])

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	pw, err = amClient.Update(tc.Context(), pw.Item.Id, pw.Item.Version, authmethods.WithName("buz"))
	require.NoError(err)
	checkAuthMethod("update", pw.Item, "buz", 2)
	got = tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

	tests_api.AssertRedactedValues(t, tests_api.GetEventDetails(t, got, "request")["item"].(map[string]interface{}))

	respItem = tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["Attrs"])
	tests_api.AssertRedactedValues(t, respItem["Attrs"].(map[string]interface{})["PasswordAuthMethodAttributes"])

	pw, err = amClient.Update(tc.Context(), pw.Item.Id, pw.Item.Version, authmethods.DefaultName())
	require.NoError(err)
	checkAuthMethod("update", pw.Item, "", 3)

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	// OIDC auth methods
	oidc, err := amClient.Create(tc.Context(), "oidc", global,
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://api.com"),
		authmethods.WithOidcAuthMethodIssuer("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"))
	require.NoError(err)
	t.Cleanup(func() {
		_, err = amClient.Delete(tc.Context(), oidc.Item.Id)
		require.NoError(err)
	})
	checkAuthMethod("create", oidc.Item, "foo", 1)
	got = tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

	reqItem = tests_api.GetEventDetails(t, got, "request")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, reqItem)
	tests_api.AssertRedactedValues(t, reqItem["Attrs"])
	tests_api.AssertRedactedValues(t, reqItem["Attrs"].(map[string]interface{})["OidcAuthMethodsAttributes"])

	respItem = tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["Attrs"])
	tests_api.AssertRedactedValues(t, respItem["Attrs"].(map[string]interface{})["OidcAuthMethodsAttributes"])

	oidc, err = amClient.Read(tc.Context(), oidc.Item.Id)
	require.NoError(err)
	checkAuthMethod("read", oidc.Item, "foo", 1)

	oidc, err = amClient.Update(tc.Context(), oidc.Item.Id, oidc.Item.Version, authmethods.WithName("bar"))
	require.NoError(err)
	checkAuthMethod("update", oidc.Item, "bar", 2)

	oidc, err = amClient.Update(tc.Context(), oidc.Item.Id, oidc.Item.Version, authmethods.DefaultName())
	require.NoError(err)
	checkAuthMethod("update", oidc.Item, "", 3)
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tcConfig, err := config.DevController()
	require.NoError(err)

	tc := controller.NewTestController(t, &controller.TestControllerOpts{Config: tcConfig})
	t.Cleanup(tc.Shutdown)

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := authmethods.NewClient(client)

	result, err := amClient.List(tc.Context(), global)
	require.NoError(err)
	require.Len(result.Items, 2)
	genOIDCAM := result.Items[0]
	genPWAM := result.Items[1]

	pwAM, err := amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("bar"),
		authmethods.WithPasswordAuthMethodMinPasswordLength(10),
	)
	require.NoError(err)
	t.Cleanup(func() {
		_, err = amClient.Delete(tc.Context(), pwAM.Item.Id)
		require.NoError(err)
	})

	result, err = amClient.List(tc.Context(), global)
	require.NoError(err)
	require.Len(result.Items, 3)
	assert.Empty(
		cmp.Diff(
			result.Items,
			[]*authmethods.AuthMethod{genOIDCAM, genPWAM, pwAM.Item},
			cmpopts.IgnoreUnexported(authmethods.AuthMethod{}),
			cmpopts.SortSlices(func(a, b *authmethods.AuthMethod) bool {
				return a.Name < b.Name
			}),
		),
	)

	oidcAM, err := amClient.Create(tc.Context(), "oidc", global,
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://api.com"),
		authmethods.WithOidcAuthMethodIssuer("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"))
	require.NoError(err)
	t.Cleanup(func() {
		_, err = amClient.Delete(tc.Context(), oidcAM.Item.Id)
		require.NoError(err)
	})

	result, err = amClient.List(tc.Context(), global)
	require.NoError(err)
	require.Len(result.Items, 4)
	assert.Empty(
		cmp.Diff(
			result.Items,
			[]*authmethods.AuthMethod{genOIDCAM, genPWAM, pwAM.Item, oidcAM.Item},
			cmpopts.IgnoreUnexported(authmethods.AuthMethod{}),
			cmpopts.SortSlices(func(a, b *authmethods.AuthMethod) bool {
				return a.Name < b.Name
			}),
		),
	)

	result, err = amClient.List(tc.Context(), global,
		authmethods.WithFilter(`"/item/attributes/client_id"=="client-id"`))
	require.NoError(err)
	require.Len(result.Items, 1)
	assert.Empty(cmp.Diff(oidcAM.Item, result.Items[0], cmpopts.IgnoreUnexported(authmethods.AuthMethod{})))

	result, err = amClient.List(tc.Context(), global,
		authmethods.WithFilter(`"/item/attributes/min_login_name_length"==3`))
	require.NoError(err)
	require.Len(result.Items, 2)
	assert.Empty(
		cmp.Diff(
			result.Items,
			[]*authmethods.AuthMethod{genPWAM, pwAM.Item},
			cmpopts.IgnoreUnexported(authmethods.AuthMethod{}),
			cmpopts.SortSlices(func(a, b *authmethods.AuthMethod) bool {
				return a.Name < b.Name
			}),
		),
	)

	result, err = amClient.List(tc.Context(), global,
		authmethods.WithFilter(`"/item/attributes/min_password_length"==10`))
	require.NoError(err)
	require.Len(result.Items, 1)
	assert.Empty(cmp.Diff(pwAM.Item, result.Items[0], cmpopts.IgnoreUnexported(authmethods.AuthMethod{})))
}

func TestCustomMethods(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	eventConfig := event.TestEventerConfig(t, "TestCrud", event.TestWithAuditSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(event.InitSysEventer(testLogger, testLock, "TestCrud", event.WithEventerConfig(&eventConfig.EventerConfig)))
	tcConfig, err := config.DevController()
	require.NoError(err)
	tcConfig.Eventing = &eventConfig.EventerConfig

	tc := controller.NewTestController(t, &controller.TestControllerOpts{Config: tcConfig})
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)

	amClient := authmethods.NewClient(client)

	tp := capoidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)

	u, err := amClient.Create(tc.Context(), "oidc", global,
		authmethods.WithName("foo"),
		authmethods.WithOidcAuthMethodIssuer(tp.Addr()),
		authmethods.WithOidcAuthMethodApiUrlPrefix("https://example.com"),
		authmethods.WithOidcAuthMethodClientSecret("secret"),
		authmethods.WithOidcAuthMethodClientId("client-id"),
		authmethods.WithOidcAuthMethodSigningAlgorithms([]string{string("EdDSA")}),
		authmethods.WithOidcAuthMethodIdpCaCerts([]string{tp.CACert()}))
	require.NoError(err)

	const newState = "active-private"
	nilU, err := amClient.ChangeState(tc.Context(), u.Item.Id, u.Item.Version, newState)
	require.Error(err)
	assert.Nil(nilU)

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	u, err = amClient.ChangeState(tc.Context(), u.Item.Id, u.Item.Version, newState, authmethods.WithOidcAuthMethodDisableDiscoveredConfigValidation(true))
	require.NoError(err)
	assert.NotNil(u)
	assert.Equal(newState, u.Item.Attributes["state"])
	got := tests_api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

	reqDetails := tests_api.GetEventDetails(t, got, "request")
	tests_api.AssertRedactedValues(t, reqDetails)
	tests_api.AssertRedactedValues(t, reqDetails["Attrs"])
	tests_api.AssertRedactedValues(t, reqDetails["Attrs"].(map[string]interface{})["OidcChangeStateAttributes"])

	respItem := tests_api.GetEventDetails(t, got, "response")["item"].(map[string]interface{})
	tests_api.AssertRedactedValues(t, respItem)
	tests_api.AssertRedactedValues(t, respItem["Attrs"].(map[string]interface{})["OidcAuthMethodsAttributes"])

	_, err = amClient.ChangeState(tc.Context(), u.Item.Id, u.Item.Version, "", authmethods.WithOidcAuthMethodDisableDiscoveredConfigValidation(true))
	assert.Error(err)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := authmethods.NewClient(client)

	u, err := amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("foo"))
	require.NoError(err)
	assert.NotNil(u)

	// Updating the wrong version should fail.
	_, err = amClient.Update(tc.Context(), u.Item.Id, 73, authmethods.WithName("anything"))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Create another resource with the same name.
	_, err = amClient.Create(tc.Context(), "password", global,
		authmethods.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)

	// TODO: Confirm that we can't create an oidc auth method with the same name.

	_, err = amClient.Read(tc.Context(), password.AuthMethodPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = amClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

	_, err = amClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
