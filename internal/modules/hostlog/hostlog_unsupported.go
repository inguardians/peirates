//go:build !linux

package hostlog

import (
	"context"

	"github.com/inguardians/peirates/internal/modules/escapeutil"
)

func probePlatform(ctx context.Context) ([]escapeutil.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []escapeutil.Finding{{
		Technique: Technique,
		Status:    escapeutil.StatusUnsupported,
		Summary:   ErrUnsupported.Error(),
	}}, nil
}

func readFilePlatform(ctx context.Context, _ Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{}, ErrUnsupported
}
