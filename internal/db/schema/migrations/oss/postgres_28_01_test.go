package oss_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/hashicorp/go-dbw"
	extraKms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrations_Kms uses the to be deprecated internal boundary kms to seed
// the system with KEKs/DEKs which are then converted by migration 28001.
// Post-migration, the test uses the new go-kms-wrapping/extras/kms package to
// verify that the converted db tables are compatible.  As this work progresses,
// this test will likely change to use kms functions marked as Deprecated for a
// period of time, since the schema these deprecated functions rely on will only
// be available in this test..  At some point, those deprecated functions should
// be removed and this test can be deleted as well.
func TestMigrations_Kms(t *testing.T) {
	const (
		priorMigration   = 27002
		currentMigration = 28001
		pt               = "this is the plaintext for testing"
	)
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(err)
	t.Cleanup(func() {
		require.NoError(c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(err)

	// migration to the prior migration (before the one we want to test)
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
	))
	require.NoError(err)

	require.NoError(m.ApplyMigrations(ctx))
	state, err := m.CurrentState(ctx)
	require.NoError(err)
	want := &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   priorMigration,
				DatabaseSchemaVersion: priorMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)

	// get a connection
	dbType, err := db.StringToDbType(dialect)
	require.NoError(err)
	conn, err := db.Open(dbType, u)
	require.NoError(err)
	rw := db.New(conn)

	rootWrapper := db.TestWrapper(t)

	// okay, now we can see the kms with a set of wrappers and then use those
	// initial wrappers for crypto operations... which we should be able to
	// repeat after we've migrated to the new kms tables.
	kms.CreateKeysTx(ctx, rw, rw, rootWrapper, rand.Reader, "global")
	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	org, prj := testDeprecatedScopes(t, iamRepo)
	deprecatedKmsCache := testDeprecatedKms(t, conn, rootWrapper)

	type blobs struct {
		purpose kms.KeyPurpose
		org     *wrapping.BlobInfo
		proj    *wrapping.BlobInfo
	}
	var testBlobs []blobs
	for _, p := range kms.ValidDekPurposes() {
		if p == kms.KeyPurposeAudit {
			continue
		}
		orgDbWrapper, err := deprecatedKmsCache.GetWrapper(ctx, org.PublicId, p)
		require.NoError(err)
		orgBlob, err := orgDbWrapper.Encrypt(ctx, []byte(pt))
		require.NoError(err)

		prjBlob, err := deprecatedKmsCache.GetWrapper(ctx, prj.PublicId, p)
		require.NoError(err)
		prjDbBlob, err := prjBlob.Encrypt(ctx, []byte(pt))
		require.NoError(err)
		testBlobs = append(testBlobs, blobs{
			purpose: p,
			org:     orgBlob,
			proj:    prjDbBlob,
		})
	}
	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(err)

	require.NoError(m.ApplyMigrations(ctx))
	state, err = m.CurrentState(ctx)
	require.NoError(err)
	want = &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   currentMigration,
				DatabaseSchemaVersion: currentMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(want, state)

	// now we have migrated and we will validate functionality
	{
		kmsRw := dbw.New(rw.UnderlyingDB())
		newKmsPurposes := make([]extraKms.KeyPurpose, 0, len(testBlobs))
		for _, p := range testBlobs {
			newKmsPurposes = append(newKmsPurposes, extraKms.KeyPurpose(p.purpose.String()))
		}
		k, err := extraKms.New(kmsRw, kmsRw, newKmsPurposes, extraKms.WithCache(true))
		require.NoError(err)
		k.AddExternalWrapper(ctx, extraKms.KeyPurposeRootKey, rootWrapper)

		for _, b := range testBlobs {
			newOrgWrapper, err := k.GetWrapper(ctx, org.PublicId, extraKms.KeyPurpose(b.purpose.String()))
			require.NoError(err)
			gotPt, err := newOrgWrapper.Decrypt(ctx, b.org)
			require.NoError(err)
			assert.Equal(pt, string(gotPt))

			newPrjWrapper, err := k.GetWrapper(ctx, prj.PublicId, extraKms.KeyPurpose(b.purpose.String()))
			require.NoError(err)
			gotPt, err = newPrjWrapper.Decrypt(ctx, b.proj)
			require.NoError(err)
			assert.Equal(pt, string(gotPt))
		}
	}
}

func testDeprecatedKms(t *testing.T, conn *db.DB, rootWrapper wrapping.Wrapper) *kms.Kms {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	kmsRepo, err := kms.NewRepository(rw, rw)
	require.NoError(err)
	k, err := kms.NewKms(kmsRepo)
	require.NoError(err)
	err = k.AddExternalWrappers(context.Background(), kms.WithRootWrapper(rootWrapper))
	require.NoError(err)
	return k
}

func testDeprecatedScopes(t *testing.T, repo *iam.Repository) (org *iam.Scope, prj *iam.Scope) {
	t.Helper()
	require := require.New(t)

	org, err := iam.NewOrg()
	require.NoError(err)
	org, err = repo.CreateScope(context.Background(), org, "", iam.WithDeprecatedCreateKeys())
	require.NoError(err)
	require.NotNil(org)
	require.NotEmpty(org.GetPublicId())

	prj, err = iam.NewProject(org.GetPublicId())
	require.NoError(err)
	prj, err = repo.CreateScope(context.Background(), prj, "", iam.WithDeprecatedCreateKeys())
	require.NoError(err)
	require.NotNil(prj)
	require.NotEmpty(prj.GetPublicId())

	return
}
