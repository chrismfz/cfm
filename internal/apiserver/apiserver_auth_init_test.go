package apiserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chrismfz/goauth"
)

func TestInitGoAuthWithRetry_RetriesSQLiteBusyThenSucceeds(t *testing.T) {
	orig := newGoAuthForInit
	t.Cleanup(func() { newGoAuthForInit = orig })

	calls := 0
	newGoAuthForInit = func(cfg goauth.Config) (*goauth.Manager, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("database is locked")
		}
		return &goauth.Manager{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mgr, err := initGoAuthWithRetry(ctx, goauth.Config{})
	if err != nil {
		t.Fatalf("expected success after retries, got err=%v", err)
	}
	if mgr == nil {
		t.Fatal("expected manager")
	}
	if calls != 3 {
		t.Fatalf("expected 3 init attempts, got %d", calls)
	}
}

func TestInitGoAuthWithRetry_DoesNotRetryNonSQLiteBusy(t *testing.T) {
	orig := newGoAuthForInit
	t.Cleanup(func() { newGoAuthForInit = orig })

	calls := 0
	newGoAuthForInit = func(cfg goauth.Config) (*goauth.Manager, error) {
		calls++
		return nil, errors.New("bad config")
	}

	_, err := initGoAuthWithRetry(context.Background(), goauth.Config{})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected single attempt for non-busy error, got %d", calls)
	}
}
