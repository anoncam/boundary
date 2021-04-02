package vault

import (
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A CredentialLibrary contains a Vault path and is owned by a credential
// store.
type CredentialLibrary struct {
	*store.CredentialLibrary
	tableName string `gorm:"-"`
}

// NewCredentialLibrary creates a new in memory CredentialLibrary
// for a Vault backend at vaultPath assigned to storeId.
// Name and description are the only valid options.
// All other options are ignored.
func NewCredentialLibrary(storeId string, vaultPath string, opt ...Option) (*CredentialLibrary, error) {
	const op = "vault.NewCredentialLibrary"
	if storeId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no store id")
	}
	if vaultPath == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no vault path")
	}

	opts := getOpts(opt...)
	l := &CredentialLibrary{
		CredentialLibrary: &store.CredentialLibrary{
			StoreId:     storeId,
			Name:        opts.withName,
			Description: opts.withDescription,
			VaultPath:   vaultPath,
		},
	}
	return l, nil
}

func allocCredentialLibrary() *CredentialLibrary {
	return &CredentialLibrary{
		CredentialLibrary: &store.CredentialLibrary{},
	}
}

func (l *CredentialLibrary) clone() *CredentialLibrary {
	cp := proto.Clone(l.CredentialLibrary)
	return &CredentialLibrary{
		CredentialLibrary: cp.(*store.CredentialLibrary),
	}
}

// TableName returns the table name.
func (l *CredentialLibrary) TableName() string {
	if l.tableName != "" {
		return l.tableName
	}
	return "credential_vault_library"
}

// SetTableName sets the table name.
func (l *CredentialLibrary) SetTableName(n string) {
	l.tableName = n
}

func (l *CredentialLibrary) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{l.PublicId},
		"resource-type":      []string{"credential-vault-library"},
		"op-type":            []string{op.String()},
	}
	if l.StoreId != "" {
		metadata["store-id"] = []string{l.StoreId}
	}
	return metadata
}
