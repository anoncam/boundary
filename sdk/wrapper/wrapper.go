package wrapper

import (
	"context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	configutil "github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

func GetWrapperFromPath(ctx context.Context, path, purpose string, opt ...configutil.Option) (wrapping.Wrapper, func() error, error) {
	kmses, err := configutil.LoadConfigKMSes(path)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing config file: %w", err)
	}

	return getWrapper(ctx, kmses, purpose, opt...)
}

func GetWrapperFromHcl(ctx context.Context, inHcl, purpose string, opt ...configutil.Option) (wrapping.Wrapper, func() error, error) {
	kmses, err := configutil.ParseKMSes(inHcl)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing KMS HCL: %w", err)
	}

	return getWrapper(ctx, kmses, purpose, opt...)
}

func getWrapper(ctx context.Context, kmses []*configutil.KMS, purpose string, opt ...configutil.Option) (wrapping.Wrapper, func() error, error) {
	var kms *configutil.KMS
	for _, v := range kmses {
		if strutil.StrListContains(v.Purpose, purpose) {
			if kms != nil {
				return nil, nil, fmt.Errorf("Only one %q block marked for %q purpose is allowed", "kms", purpose)
			}
			kms = v
		}
	}
	if kms == nil {
		return nil, nil, nil
	}

	wrapper, cleanup, err := configutil.ConfigureWrapper(
		ctx,
		kms,
		nil,
		nil,
		opt...,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("Error configuring kms: %w", err)
	}

	return wrapper, cleanup, nil
}
