package authmethods_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	requestauth "github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPassword  = "thetestpassword"
	testLoginName = "default"
)

var (
	pwAuthorizedActions = []string{
		action.NoOp.String(),
		action.Read.String(),
		action.Update.String(),
		action.Delete.String(),
		action.Authenticate.String(),
	}
	oidcAuthorizedActions = []string{
		action.NoOp.String(),
		action.Read.String(),
		action.Update.String(),
		action.Delete.String(),
		action.ChangeState.String(),
		action.Authenticate.String(),
	}
)

var authorizedCollectionActions = map[string]*structpb.ListValue{
	"accounts": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
	"managed-groups": {
		Values: []*structpb.Value{
			structpb.NewStringValue("create"),
			structpb.NewStringValue("list"),
		},
	},
}

func TestGet(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kmsCache)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	iam.TestSetPrimaryAuthMethod(t, iamRepo, o, am.GetPublicId())

	wantPw := &pb.AuthMethod{
		Id:          am.GetPublicId(),
		ScopeId:     am.GetScopeId(),
		CreatedTime: am.CreateTime.GetTimestamp(),
		UpdatedTime: am.UpdateTime.GetTimestamp(),
		Type:        "password",
		Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
			PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
				MinPasswordLength:  8,
				MinLoginNameLength: 3,
			},
		},
		Version: 1,
		Scope: &scopepb.ScopeInfo{
			Id:            o.GetPublicId(),
			Type:          o.GetType(),
			ParentScopeId: scope.Global.String(),
		},
		IsPrimary:                   true,
		AuthorizedActions:           pwAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
	}

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), oidc.InactiveState, "alice_rp", "secret",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]))

	wantOidc := &pb.AuthMethod{
		Id:          oidcam.GetPublicId(),
		ScopeId:     oidcam.GetScopeId(),
		CreatedTime: oidcam.CreateTime.GetTimestamp(),
		UpdatedTime: oidcam.UpdateTime.GetTimestamp(),
		Type:        oidc.Subtype.String(),
		Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
			OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
				Issuer:           wrapperspb.String("https://alice.com"),
				ClientId:         wrapperspb.String("alice_rp"),
				ClientSecretHmac: "<hmac>",
				State:            string(oidc.InactiveState),
				ApiUrlPrefix:     wrapperspb.String("https://api.com"),
				CallbackUrl:      fmt.Sprintf(oidc.CallbackEndpoint, "https://api.com"),
			},
		},
		Version: 1,
		Scope: &scopepb.ScopeInfo{
			Id:            o.GetPublicId(),
			Type:          o.GetType(),
			ParentScopeId: scope.Global.String(),
		},
		AuthorizedActions:           oidcAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
	}

	cases := []struct {
		name    string
		scopeId string
		req     *pbs.GetAuthMethodRequest
		res     *pbs.GetAuthMethodResponse
		err     error
	}{
		{
			name:    "Get an Existing PW AuthMethod",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: am.GetPublicId()},
			res:     &pbs.GetAuthMethodResponse{Item: wantPw},
		},
		{
			name:    "Get an Existing OIDC AuthMethod",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: oidcam.GetPublicId()},
			res:     &pbs.GetAuthMethodResponse{Item: wantOidc},
		},
		{
			name:    "Get a non existant AuthMethod",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: password.AuthMethodPrefix + "_DoesntExis"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name:    "Wrong id prefix",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: "j_1234567890"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name:    "space in id",
			scopeId: o.GetPublicId(),
			req:     &pbs.GetAuthMethodRequest{Id: password.AuthMethodPrefix + "_1 23456789"},
			res:     nil,
			err:     handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := authmethods.NewService(kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
			require.NoError(err, "Couldn't create new auth_method service.")

			got, gErr := s.GetAuthMethod(requestauth.DisabledAuthTestContext(iamRepoFn, tc.scopeId), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "GetAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if oidcAttrs := got.Item.GetOidcAuthMethodsAttributes(); oidcAttrs != nil {
				assert.NotEqual("secret", oidcAttrs.ClientSecretHmac)
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.IgnoreFields(&pb.OidcAuthMethodAttributes{}, "client_secret_hmac")), "GetAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kmsCache)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	oNoAuthMethods, _ := iam.TestScopes(t, iamRepo)
	oWithAuthMethods, _ := iam.TestScopes(t, iamRepo)
	oWithOtherAuthMethods, _ := iam.TestScopes(t, iamRepo)

	var wantSomeAuthMethods []*pb.AuthMethod
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), oWithAuthMethods.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, oWithAuthMethods.GetPublicId(), oidc.ActivePublicState, "alice_rp", "secret",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]), oidc.WithSigningAlgs(oidc.EdDSA))
	iam.TestSetPrimaryAuthMethod(t, iamRepo, oWithAuthMethods, oidcam.GetPublicId())

	wantSomeAuthMethods = append(wantSomeAuthMethods, &pb.AuthMethod{
		Id:          oidcam.GetPublicId(),
		ScopeId:     oWithAuthMethods.GetPublicId(),
		CreatedTime: oidcam.GetCreateTime().GetTimestamp(),
		UpdatedTime: oidcam.GetUpdateTime().GetTimestamp(),
		Scope:       &scopepb.ScopeInfo{Id: oWithAuthMethods.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
		Version:     2,
		Type:        oidc.Subtype.String(),
		Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
			OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
				Issuer:           wrapperspb.String("https://alice.com"),
				ClientId:         wrapperspb.String("alice_rp"),
				ClientSecretHmac: "<hmac>",
				State:            string(oidc.ActivePublicState),
				ApiUrlPrefix:     wrapperspb.String("https://api.com"),
				CallbackUrl:      fmt.Sprintf(oidc.CallbackEndpoint, "https://api.com"),
				SigningAlgorithms: []string{
					string(oidc.EdDSA),
				},
			},
		},
		IsPrimary:                   true,
		AuthorizedActions:           oidcAuthorizedActions,
		AuthorizedCollectionActions: authorizedCollectionActions,
	})

	for _, am := range password.TestAuthMethods(t, conn, oWithAuthMethods.GetPublicId(), 3) {
		wantSomeAuthMethods = append(wantSomeAuthMethods, &pb.AuthMethod{
			Id:          am.GetPublicId(),
			ScopeId:     oWithAuthMethods.GetPublicId(),
			CreatedTime: am.GetCreateTime().GetTimestamp(),
			UpdatedTime: am.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: oWithAuthMethods.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:     1,
			Type:        "password",
			Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
				PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
					MinPasswordLength:  8,
					MinLoginNameLength: 3,
				},
			},
			AuthorizedActions:           pwAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions,
		})
	}

	var wantOtherAuthMethods []*pb.AuthMethod
	for _, aa := range password.TestAuthMethods(t, conn, oWithOtherAuthMethods.GetPublicId(), 3) {
		wantOtherAuthMethods = append(wantOtherAuthMethods, &pb.AuthMethod{
			Id:          aa.GetPublicId(),
			ScopeId:     oWithOtherAuthMethods.GetPublicId(),
			CreatedTime: aa.GetCreateTime().GetTimestamp(),
			UpdatedTime: aa.GetUpdateTime().GetTimestamp(),
			Scope:       &scopepb.ScopeInfo{Id: oWithOtherAuthMethods.GetPublicId(), Type: scope.Org.String(), ParentScopeId: scope.Global.String()},
			Version:     1,
			Type:        "password",
			Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
				PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
					MinPasswordLength:  8,
					MinLoginNameLength: 3,
				},
			},
			AuthorizedActions:           pwAuthorizedActions,
			AuthorizedCollectionActions: authorizedCollectionActions,
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListAuthMethodsRequest
		res  *pbs.ListAuthMethodsResponse
		err  error
	}{
		{
			name: "List Some Auth Methods",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oWithAuthMethods.GetPublicId()},
			res:  &pbs.ListAuthMethodsResponse{Items: wantSomeAuthMethods},
		},
		{
			name: "List Other Auth Methods",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oWithOtherAuthMethods.GetPublicId()},
			res:  &pbs.ListAuthMethodsResponse{Items: wantOtherAuthMethods},
		},
		{
			name: "List No Auth Methods",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oNoAuthMethods.GetPublicId()},
			res:  &pbs.ListAuthMethodsResponse{},
		},
		{
			name: "Unfound Auth Method",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: "o_DoesntExis"},
			err:  handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "List All Auth Methods Recursively",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: "global", Recursive: true},
			res: &pbs.ListAuthMethodsResponse{
				Items: append(wantSomeAuthMethods, wantOtherAuthMethods...),
			},
		},
		{
			name: "Filter To Some Auth Methods",
			req: &pbs.ListAuthMethodsRequest{
				ScopeId: "global", Recursive: true,
				Filter: fmt.Sprintf(`"/item/scope/id"==%q`, oWithAuthMethods.GetPublicId()),
			},
			res: &pbs.ListAuthMethodsResponse{Items: wantSomeAuthMethods},
		},
		{
			name: "Filter All Auth Methods",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oWithAuthMethods.GetPublicId(), Filter: `"/item/id"=="nothingmatchesthis"`},
			res:  &pbs.ListAuthMethodsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListAuthMethodsRequest{ScopeId: oWithAuthMethods.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := authmethods.NewService(kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
			require.NoError(err, "Couldn't create new auth_method service.")

			// First check with non-anonymous user
			got, gErr := s.ListAuthMethods(requestauth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "ListAuthMethods() for scope %q got error %v, wanted %v", tc.req.GetScopeId(), gErr, tc.err)
				return
			}
			require.NoError(gErr)
			for _, g := range got.Items {
				if oidcAttrs := g.GetOidcAuthMethodsAttributes(); oidcAttrs != nil {
					assert.NotEqual("secret", oidcAttrs.ClientSecretHmac)
				}
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.IgnoreFields(&pb.OidcAuthMethodAttributes{}, "client_secret_hmac")),
				"ListAuthMethods() for scope %q got response %q, wanted %q", tc.req.GetScopeId(), got, tc.res)

			// Now check with anonymous user
			got, gErr = s.ListAuthMethods(requestauth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), requestauth.WithUserId(requestauth.AnonymousUserId)), tc.req)
			require.NoError(gErr)
			assert.Len(got.Items, len(tc.res.Items))
			for _, g := range got.GetItems() {
				assert.Nil(g.Attrs)
				assert.Nil(g.CreatedTime)
				assert.Nil(g.UpdatedTime)
				assert.Empty(g.Version)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kmsCache)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kmsCache)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	pwam := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), o.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), oidc.InactiveState, "alice_rp", "my-dogs-name",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]))

	s, err := authmethods.NewService(kmsCache, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
	require.NoError(t, err, "Error when getting new auth_method service.")

	cases := []struct {
		name string
		req  *pbs.DeleteAuthMethodRequest
		res  *pbs.DeleteAuthMethodResponse
		err  error
	}{
		{
			name: "Delete an Existing PW AuthMethod",
			req: &pbs.DeleteAuthMethodRequest{
				Id: pwam.GetPublicId(),
			},
			res: &pbs.DeleteAuthMethodResponse{},
		},
		{
			name: "Delete an Existing OIDC AuthMethod",
			req: &pbs.DeleteAuthMethodRequest{
				Id: oidcam.GetPublicId(),
			},
			res: &pbs.DeleteAuthMethodResponse{},
		},
		{
			name: "Delete bad auth_method id",
			req: &pbs.DeleteAuthMethodRequest{
				Id: password.AuthMethodPrefix + "_doesntexis",
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Bad AuthMethod Id formatting",
			req: &pbs.DeleteAuthMethodRequest{
				Id: "bad_format",
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, gErr := s.DeleteAuthMethod(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "DeleteAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}
			assert.EqualValuesf(tc.res, got, "DeleteAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	ctx := context.TODO()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	s, err := authmethods.NewService(kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
	require.NoError(err, "Error when getting new auth_method service.")

	req := &pbs.DeleteAuthMethodRequest{
		Id: am.GetPublicId(),
	}
	_, gErr := s.DeleteAuthMethod(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.NoError(gErr, "First attempt")
	_, gErr = s.DeleteAuthMethod(requestauth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), req)
	assert.Error(gErr, "Second attempt")
	assert.True(errors.Is(gErr, handlers.ApiErrorWithCode(codes.NotFound)), "Expected permission denied for the second delete.")
}

func TestCreate(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(rw, rw, kms)
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	defaultAm := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	defaultCreated := defaultAm.GetCreateTime().GetTimestamp()

	cases := []struct {
		name     string
		req      *pbs.CreateAuthMethodRequest
		res      *pbs.CreateAuthMethodResponse
		idPrefix string
		err      error
	}{
		{
			name: "Create a valid Password AuthMethod",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
				Type:        "password",
			}},
			idPrefix: password.AuthMethodPrefix + "_",
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", password.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     o.GetPublicId(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Scope:       &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()},
					Version:     1,
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinPasswordLength:  8,
							MinLoginNameLength: 3,
						},
					},
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Create a valid OIDC AuthMethod",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						Issuer:           wrapperspb.String("https://example.discovery.url:4821/.well-known/openid-configuration/"),
						ClientId:         wrapperspb.String("someclientid"),
						ClientSecret:     wrapperspb.String("secret"),
						ApiUrlPrefix:     wrapperspb.String("https://callback.prefix:9281/path"),
						AllowedAudiences: []string{"foo", "bar"},
						ClaimsScopes:     []string{"email", "profile"},
						AccountClaimMaps: []string{"display_name=name", "oid=sub"},
					},
				},
			}},
			idPrefix: oidc.AuthMethodPrefix + "_",
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", oidc.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     o.GetPublicId(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Scope:       &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()},
					Version:     1,
					Type:        oidc.Subtype.String(),
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							Issuer:           wrapperspb.String("https://example.discovery.url:4821/"),
							ClientId:         wrapperspb.String("someclientid"),
							ClientSecretHmac: "<hmac>",
							State:            string(oidc.InactiveState),
							ApiUrlPrefix:     wrapperspb.String("https://callback.prefix:9281/path"),
							CallbackUrl:      "https://callback.prefix:9281/path/v1/auth-methods/oidc:authenticate:callback",
							AllowedAudiences: []string{"foo", "bar"},
							ClaimsScopes:     []string{"email", "profile"},
							AccountClaimMaps: []string{"display_name=name", "oid=sub"},
						},
					},
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Create a global Password AuthMethod",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     scope.Global.String(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
				Type:        "password",
			}},
			idPrefix: password.AuthMethodPrefix + "_",
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", password.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     scope.Global.String(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Scope:       &scopepb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Version:     1,
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinPasswordLength:  8,
							MinLoginNameLength: 3,
						},
					},
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Create a global OIDC AuthMethod",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: scope.Global.String(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						Issuer:       wrapperspb.String("https://example.discovery.url"),
						ApiUrlPrefix: wrapperspb.String("https://api.com"),
						ClientId:     wrapperspb.String("someclientid"),
						ClientSecret: wrapperspb.String("secret"),
					},
				},
			}},
			idPrefix: oidc.AuthMethodPrefix + "_",
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", oidc.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     scope.Global.String(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Scope:       &scopepb.ScopeInfo{Id: scope.Global.String(), Type: scope.Global.String(), Name: scope.Global.String(), Description: "Global Scope"},
					Version:     1,
					Type:        oidc.Subtype.String(),
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							ApiUrlPrefix:     wrapperspb.String("https://api.com"),
							Issuer:           wrapperspb.String("https://example.discovery.url"),
							ClientId:         wrapperspb.String("someclientid"),
							ClientSecretHmac: "<hmac>",
							State:            string(oidc.InactiveState),
						},
					},
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Id:      password.AuthMethodPrefix + "_notallowed",
				Type:    "password",
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				CreatedTime: timestamppb.Now(),
				Type:        password.Subtype.String(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				UpdatedTime: timestamppb.Now(),
				Type:        password.Subtype.String(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify IsPrimary",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:   o.GetPublicId(),
				Type:      password.Subtype.String(),
				IsPrimary: true,
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				UpdatedTime: timestamppb.Now(),
				Type:        password.Subtype.String(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify type",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "must specify type"},
				Description: &wrapperspb.StringValue{Value: "must specify type"},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod Doesn't Require Issuer",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						ApiUrlPrefix: wrapperspb.String("https://api.com"),
						ClientId:     wrapperspb.String("someclientid"),
						ClientSecret: wrapperspb.String("secret"),
					},
				},
			}},
			res: &pbs.CreateAuthMethodResponse{
				Uri: fmt.Sprintf("auth-methods/%s_", oidc.AuthMethodPrefix),
				Item: &pb.AuthMethod{
					Id:          defaultAm.GetPublicId(),
					ScopeId:     o.GetPublicId(),
					CreatedTime: defaultAm.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultAm.GetUpdateTime().GetTimestamp(),
					Scope:       &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()},
					Version:     1,
					Type:        oidc.Subtype.String(),
					Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
						OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
							ApiUrlPrefix:     wrapperspb.String("https://api.com"),
							ClientId:         wrapperspb.String("someclientid"),
							ClientSecretHmac: "<hmac>",
							State:            string(oidc.InactiveState),
						},
					},
					AuthorizedActions:           oidcAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "OIDC AuthMethod Requires ApiUrl",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						ClientId:     wrapperspb.String("someclientid"),
						ClientSecret: wrapperspb.String("secret"),
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod Requires Client Id",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						ApiUrlPrefix: wrapperspb.String("https://api.com"),
						Issuer:       wrapperspb.String("https://example.discovery.url:4821/.well-known/openid-configuration/"),
						ClientSecret: wrapperspb.String("secret"),
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod Requires Client Secret",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						ApiUrlPrefix: wrapperspb.String("https://api.com"),
						Issuer:       wrapperspb.String("https://example.discovery.url:4821/.well-known/openid-configuration/"),
						ClientId:     wrapperspb.String("someclientid"),
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod cant specify client secret hmac",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						ApiUrlPrefix:     wrapperspb.String("https://api.com"),
						Issuer:           wrapperspb.String("https://example.discovery.url:4821/.well-known/openid-configuration/"),
						ClientId:         wrapperspb.String("someclientid"),
						ClientSecret:     wrapperspb.String("secret"),
						ClientSecretHmac: "hmac",
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod cant specify state",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						ApiUrlPrefix: wrapperspb.String("https://api.com"),
						Issuer:       wrapperspb.String("https://example.discovery.url:4821/.well-known/openid-configuration/"),
						ClientId:     wrapperspb.String("someclientid"),
						ClientSecret: wrapperspb.String("secret"),
						State:        string(oidc.InactiveState),
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod Must Match Standard Alg Names",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						ApiUrlPrefix:      wrapperspb.String("https://api.com"),
						Issuer:            wrapperspb.String("https://example2.discovery.url:4821"),
						ClientId:          wrapperspb.String("someclientid"),
						ClientSecret:      wrapperspb.String("secret"),
						SigningAlgorithms: []string{string(oidc.ES256), strings.ToLower(string(oidc.EdDSA))},
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod API Urls Prefix Format",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						Issuer:       wrapperspb.String("https://example2.discovery.url:4821"),
						ClientId:     wrapperspb.String("someclientid"),
						ClientSecret: wrapperspb.String("secret"),
						ApiUrlPrefix: wrapperspb.String("invalid path"),
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod Callback Url Read Only",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						Issuer:       wrapperspb.String("https://example2.discovery.url:4821"),
						ClientId:     wrapperspb.String("someclientid"),
						ClientSecret: wrapperspb.String("secret"),
						CallbackUrl:  "http://another.url.com:82471",
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod unparseable certificates",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						ApiUrlPrefix: wrapperspb.String("https://api.com"),
						Issuer:       wrapperspb.String("https://example2.discovery.url:4821"),
						ClientId:     wrapperspb.String("someclientid"),
						ClientSecret: wrapperspb.String("secret"),
						IdpCaCerts:   []string{"unparseable"},
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "OIDC AuthMethod cant specify default claims scopes of openid",
			req: &pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId: o.GetPublicId(),
				Type:    oidc.Subtype.String(),
				Attrs: &pb.AuthMethod_OidcAuthMethodsAttributes{
					OidcAuthMethodsAttributes: &pb.OidcAuthMethodAttributes{
						ApiUrlPrefix: wrapperspb.String("https://api.com"),
						Issuer:       wrapperspb.String("https://example.discovery.url:4821/.well-known/openid-configuration/"),
						ClientId:     wrapperspb.String("someclientid"),
						ClientSecret: wrapperspb.String("secret"),
						ClaimsScopes: []string{"openid"},
					},
				},
			}},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := authmethods.NewService(kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn)
			require.NoError(err, "Error when getting new auth_method service.")

			got, gErr := s.CreateAuthMethod(requestauth.DisabledAuthTestContext(iamRepoFn, tc.req.GetItem().GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if tc.res == nil {
				require.Nil(got)
			}
			cmpOptions := []cmp.Option{protocmp.Transform()}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), tc.idPrefix))
				gotCreateTime := got.GetItem().GetCreatedTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime()

				// Verify it is a auth_method created after the test setup's default auth_method
				assert.True(gotCreateTime.AsTime().After(defaultCreated.AsTime()), "New auth_method should have been created after default auth_method. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.AsTime().After(defaultCreated.AsTime()), "New auth_method should have been updated after default auth_method. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Ignore all values which are hard to compare against.
				cmpOptions = append(
					cmpOptions,
					protocmp.IgnoreFields(&pbs.CreateAuthMethodResponse{}, "uri"),
					protocmp.IgnoreFields(&pb.AuthMethod{}, "id", "created_time", "updated_time"),
				)
				if oidcAttrs := got.Item.GetOidcAuthMethodsAttributes(); oidcAttrs != nil {
					assert.NotEqual(oidcAttrs.ClientSecret, oidcAttrs.ClientSecretHmac)
					exp := tc.res.Item.Attrs.(*pb.AuthMethod_OidcAuthMethodsAttributes).OidcAuthMethodsAttributes.CallbackUrl
					gVal := oidcAttrs.CallbackUrl
					matches, err := regexp.MatchString(exp, gVal)
					require.NoError(err)
					assert.True(matches, "%q doesn't match %q", gVal, exp)
					cmpOptions = append(
						cmpOptions,
						protocmp.SortRepeatedFields(&pb.OidcAuthMethodAttributes{}, "account_claim_maps"),
						protocmp.IgnoreFields(&pb.OidcAuthMethodAttributes{}, "client_secret_hmac", "callback_url"),
					)
				}
			}
			assert.Empty(cmp.Diff(got, tc.res, cmpOptions...), "CreateAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}
