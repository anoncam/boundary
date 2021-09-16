package targets_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/api/credentialstores"
	"github.com/hashicorp/boundary/api/hostcatalogs"
	"github.com/hashicorp/boundary/api/hostsets"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostSourcesASD(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	token := tc.Token()
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	client := tc.Client().Clone()
	client.SetToken(token.Token)

	hc, err := hostcatalogs.NewClient(client).Create(tc.Context(), "static", proj.GetPublicId())
	require.NoError(err)

	hSetClient := hostsets.NewClient(client)
	hSet, err := hSetClient.Create(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.NotNil(hSet)
	hSet2, err := hSetClient.Create(tc.Context(), hc.Item.Id)
	require.NoError(err)
	require.NotNil(hSet2)

	tarClient := targets.NewClient(client)
	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	require.NoError(err)
	require.NotNil(tar)
	assert.Empty(tar.Item.HostSourceIds)

	tar, err = tarClient.AddHostSources(tc.Context(), tar.Item.Id, tar.Item.Version, []string{hSet.Item.Id})
	require.NoError(err)
	require.NotNil(tar)
	assert.ElementsMatch(tar.Item.HostSourceIds, []string{hSet.Item.Id})

	tar, err = tarClient.SetHostSources(tc.Context(), tar.Item.Id, tar.Item.Version, []string{hSet2.Item.Id})
	require.NoError(err)
	require.NotNil(tar)
	assert.ElementsMatch(tar.Item.HostSourceIds, []string{hSet2.Item.Id})

	tar, err = tarClient.RemoveHostSources(tc.Context(), tar.Item.Id, tar.Item.Version, []string{hSet2.Item.Id})
	require.NoError(err)
	require.NotNil(tar)
	assert.Empty(tar.Item.HostSourceIds)
}

func defaultCredSource(r *credentiallibraries.CredentialLibrary) *targets.CredentialSource {
	return &targets.CredentialSource{Id: r.Id, CredentialStoreId: r.CredentialStoreId}
}

func TestCredentialSourcesASD(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()
	vaultServ := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestNoTLS))
	_, vaultTok := vaultServ.CreateToken(t)

	token := tc.Token()
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	client := tc.Client().Clone()
	client.SetToken(token.Token)

	cs, err := credentialstores.NewClient(client).Create(tc.Context(), "vault", proj.GetPublicId(),
		credentialstores.WithVaultCredentialStoreAddress(vaultServ.Addr), credentialstores.WithVaultCredentialStoreToken(vaultTok))
	require.NoError(err)
	require.NotNil(cs)

	lClient := credentiallibraries.NewClient(client)
	r1, err := lClient.Create(tc.Context(), cs.Item.Id, credentiallibraries.WithVaultCredentialLibraryPath("something1"))
	require.NoError(err)
	require.NotNil(r1)

	r2, err := lClient.Create(tc.Context(), cs.Item.Id, credentiallibraries.WithVaultCredentialLibraryPath("something2"))
	require.NoError(err)
	require.NotNil(r1)

	tarClient := targets.NewClient(client)
	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	require.NoError(err)
	require.NotNil(tar)
	assert.Empty(tar.Item.ApplicationCredentialSourceIds)

	tar, err = tarClient.AddCredentialSources(tc.Context(), tar.Item.Id, tar.Item.Version, targets.WithApplicationCredentialSourceIds([]string{r1.Item.Id}))
	require.NoError(err)
	require.NotNil(tar)
	assert.ElementsMatch(tar.Item.ApplicationCredentialSourceIds, []string{r1.Item.Id})
	assert.ElementsMatch(tar.Item.ApplicationCredentialSources, []*targets.CredentialSource{defaultCredSource(r1.Item)})

	tar, err = tarClient.SetCredentialSources(tc.Context(), tar.Item.Id, tar.Item.Version,
		targets.WithApplicationCredentialSourceIds([]string{r2.Item.Id}))
	require.NoError(err)
	require.NotNil(tar)
	assert.ElementsMatch(tar.Item.ApplicationCredentialSourceIds, []string{r2.Item.Id})
	assert.ElementsMatch(tar.Item.ApplicationCredentialSources, []*targets.CredentialSource{defaultCredSource(r2.Item)})

	tar, err = tarClient.RemoveCredentialSources(tc.Context(), tar.Item.Id, tar.Item.Version,
		targets.WithApplicationCredentialSourceIds([]string{r2.Item.Id}))
	require.NoError(err)
	require.NotNil(tar)
	assert.Empty(tar.Item.ApplicationCredentialSourceIds)
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)
	ul, err := tarClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.Empty(ul.Items)

	var expected []*targets.Target
	for i := 0; i < 10; i++ {
		expected = append(expected, &targets.Target{Name: fmt.Sprint(i)})
	}

	tcr, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName(expected[0].Name))
	require.NoError(err)
	expected[0] = tcr.Item

	ul, err = tarClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ul.Items))

	for i := 1; i < 10; i++ {
		tcr, err = tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName(expected[i].Name))
		require.NoError(err)
		expected[i] = tcr.Item
	}
	ul, err = tarClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ul.Items))

	filterItem := ul.Items[3]
	ul, err = tarClient.List(tc.Context(), proj.GetPublicId(),
		targets.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(ul.Items, 1)
	assert.Equal(filterItem.Id, ul.Items[0].Id)
}

func comparableSlice(in []*targets.Target) []targets.Target {
	var filtered []targets.Target
	for _, i := range in {
		p := targets.Target{
			Id:          i.Id,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func TestCrud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	checkResource := func(t *testing.T, step string, h *targets.Target, err error, wantedName string, wantVersion uint32) {
		t.Helper()
		require.NoError(err, step)
		assert.NotNil(h, "returned no resource", step)
		gotName := ""
		if h.Name != "" {
			gotName = h.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantVersion, h.Version)
	}

	tarClient := targets.NewClient(client)

	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	checkResource(t, "create", tar.Item, err, "foo", 1)

	tar, err = tarClient.Read(tc.Context(), tar.Item.Id)
	checkResource(t, "read", tar.Item, err, "foo", 1)

	tar, err = tarClient.Update(tc.Context(), tar.Item.Id, tar.Item.Version, targets.WithName("bar"))
	checkResource(t, "update", tar.Item, err, "bar", 2)

	_, err = tarClient.Delete(tc.Context(), tar.Item.Id)
	assert.NoError(err)

	_, err = tarClient.Delete(tc.Context(), tar.Item.Id)
	assert.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
}

func TestSet_Errors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	tarClient := targets.NewClient(client)

	tar, err := tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	require.NoError(err)
	assert.NotNil(tar)

	// Updating the wrong version should fail.
	_, err = tarClient.Update(tc.Context(), tar.Item.Id, 73, targets.WithName("anything"))
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	tar, err = tarClient.Create(tc.Context(), "tcp", proj.GetPublicId(), targets.WithName("foo"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.Nil(tar)

	_, err = tarClient.Read(tc.Context(), target.TcpTargetPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = tarClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
