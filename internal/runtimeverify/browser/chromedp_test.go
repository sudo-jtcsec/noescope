package browser

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type contextKey string

func TestCookieInspectionUsesActiveActionContext(t *testing.T) {
	active := context.WithValue(context.Background(), contextKey("target"), "active-tab")
	var received context.Context
	var destination []Cookie
	action := inspectCookiesAction(func(ctx context.Context) ([]Cookie, error) {
		received = ctx
		if ctx.Value(contextKey("target")) != "active-tab" {
			t.Fatal("cookie reader did not receive the active target action context")
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("target context canceled before cookie inspection: %v", err)
		}
		return []Cookie{{Name: "session", HTTPOnly: true}}, nil
	}, &destination)
	if err := action.Do(active); err != nil {
		t.Fatal(err)
	}
	if received != active || len(destination) != 1 || destination[0].Name != "session" {
		t.Fatalf("cookie inspection used the wrong context or result: %#v", destination)
	}
}

func TestCookieInspectionReturnsFocusedError(t *testing.T) {
	action := inspectCookiesAction(func(context.Context) ([]Cookie, error) {
		return nil, errors.New("invalid context")
	}, new([]Cookie))
	err := action.Do(context.Background())
	observationErr := BrowserObservationError{Operation: "cookies", Err: err}
	if !errors.Is(observationErr, err) || observationErr.Error() != "inspect cookies: invalid context" {
		t.Fatalf("unexpected focused observation error: %v", observationErr)
	}
}

func TestResolveExecutableOrderAndFailure(t *testing.T) {
	var attempted []string
	path, err := resolveExecutable("/configured/chrome", func(name string) (string, error) {
		attempted = append(attempted, name)
		if name == "chromium" {
			return "/usr/bin/chromium", nil
		}
		return "", errors.New("missing")
	})
	if err != nil || path != "/usr/bin/chromium" {
		t.Fatalf("unexpected executable resolution: %q, %v", path, err)
	}
	want := []string{"/configured/chrome", "google-chrome", "google-chrome-stable", "chromium"}
	if !reflect.DeepEqual(attempted, want) {
		t.Fatalf("unexpected executable search order: %v", attempted)
	}

	_, err = resolveExecutable("", func(name string) (string, error) {
		return "", errors.New("missing")
	})
	if err == nil {
		t.Fatal("expected missing executable error")
	}
	for _, name := range defaultExecutableNames {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("missing executable error does not list %q: %v", name, err)
		}
	}
}

func TestResolveExecutablePrefersConfiguredExecutable(t *testing.T) {
	path, err := resolveExecutable("/configured/chrome", func(name string) (string, error) {
		if name != "/configured/chrome" {
			t.Fatalf("searched fallback before configured executable: %s", name)
		}
		return name, nil
	})
	if err != nil || path != "/configured/chrome" {
		t.Fatalf("configured executable was not preferred: %q, %v", path, err)
	}
}
