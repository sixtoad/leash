package runner

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Why leash pre-pulls at all, given both `run` invocations pass --pull=missing:
// the manager image's OCI labels are validated (validateManagerImage) and the
// target image's configured user is captured (captureTargetContainerUser) with
// `image inspect` *before* either container is created. Both need the image in
// the local store, so a pull deferred to `run --pull=missing` would arrive too
// late and the run would fail on that inspect instead, with a worse message.
// The pre-pull therefore stays, but it only runs when the engine reports the
// image absent, and a failure names the engine's real reason rather than
// assuming registry authentication (issue #170). leash has no "always pull"
// option, so an image present locally is never re-pulled.

// imageInspectRetryDelay spaces the single retry of an `image inspect` that
// failed for a reason other than "image not found" (a daemon blip, e.g. Docker
// Desktop's resource saver waking the VM).
const imageInspectRetryDelay = 250 * time.Millisecond

// pullDetailLimit bounds how much engine output is quoted in a pull error.
const pullDetailLimit = 400

// exitStatusPrefix matches the "<command>: exit status N: " wrapper the
// command helpers put in front of the engine's own words.
var exitStatusPrefix = regexp.MustCompile(`^[^:]*: exit status \d+: `)

// isNoSuchImageError reports whether an `image inspect` failure means the image
// is absent from the local store. Docker says "No such image" (older engines
// "No such object"); Podman says "image not known" (older releases "no such
// image" / "failed to find image").
func isNoSuchImageError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{"no such image", "no such object", "image not known", "failed to find image"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// inspectImage reports whether image is present in the engine's local store.
// A failure that is not "image not found" is retried once before it is
// returned, so a transient daemon error does not end the run.
func (r *runner) inspectImage(ctx context.Context, image string) (bool, error) {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(imageInspectRetryDelay):
			}
		}
		_, err = r.rt().Output(ctx, "image", "inspect", image)
		if err == nil {
			return true, nil
		}
		if isNoSuchImageError(err) {
			return false, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
	}
	return false, err
}

// ensureLocalImage makes image available in the local store, pulling it only
// when the engine reports it absent. role ("target" or "manager") names the
// image in errors.
func (r *runner) ensureLocalImage(ctx context.Context, role, image string) error {
	engine := r.rt().Name()
	present, err := r.inspectImage(ctx, image)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("inspect %s image %q: %w", role, image, err)
		}
		return fmt.Errorf("inspect %s image %q with %s: %s", role, image, engine, engineDetail(err))
	}
	if present {
		return nil
	}

	r.diagnosticf("Pulling container image %s...\n", image)
	pullErr := r.rt().Run(ctx, "pull", image)
	if pullErr == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("pull %s image %q: %w", role, image, ctxErr)
	}
	// The first inspect may have been a false "missing" (the trigger reported
	// in issue #170): if the image is there after all, the failed pull is moot.
	if present, inspectErr := r.inspectImage(ctx, image); inspectErr == nil && present {
		r.diagnosticf("Warning: pull of %s failed, but the image is present locally; continuing with the local copy.\n", image)
		return nil
	}
	return describePullFailure(role, image, engine, pullErr)
}

type pullFailureKind int

const (
	pullFailureUnknown pullFailureKind = iota
	pullFailureNotFound
	pullFailureNotFoundOrAuth
	pullFailureAuth
	pullFailureNetwork
	pullFailureShortName
)

// classifyPullFailure maps engine pull output onto the cause an operator acts
// on. Order matters: network and short-name failures can mention a manifest,
// and Docker Hub answers "access denied" for repositories that do not exist,
// so that phrasing is reported as ambiguous rather than as an auth failure.
func classifyPullFailure(err error) pullFailureKind {
	msg := strings.ToLower(err.Error())
	containsAny := func(markers ...string) bool {
		for _, m := range markers {
			if strings.Contains(msg, m) {
				return true
			}
		}
		return false
	}
	switch {
	case containsAny("short-name", "short name"):
		return pullFailureShortName
	case containsAny("dial tcp", "no such host", "i/o timeout", "connection refused", "connection reset",
		"network is unreachable", "no route to host", "tls handshake timeout", "temporary failure in name resolution",
		"server misbehaving", "context deadline exceeded", "client.timeout exceeded", "x509:"):
		return pullFailureNetwork
	case containsAny("repository does not exist or may require", "pull access denied", "requested access to the resource is denied", "error from registry: denied"):
		return pullFailureNotFoundOrAuth
	case containsAny("unauthorized", "authentication required", "no basic auth credentials",
		"incorrect username or password", "403 forbidden", "denied:"):
		return pullFailureAuth
	case containsAny("manifest unknown", "name unknown", "repository does not exist", "not found"):
		return pullFailureNotFound
	}
	return pullFailureUnknown
}

func describePullFailure(role, image, engine string, pullErr error) error {
	var cause string
	kind := classifyPullFailure(pullErr)
	switch kind {
	case pullFailureNotFound:
		cause = "the registry has no such image or tag"
	case pullFailureNotFoundOrAuth:
		cause = fmt.Sprintf("the registry refused it: the repository does not exist there, or it is private and needs `%s login`", engine)
	case pullFailureAuth:
		cause = fmt.Sprintf("the registry requires authentication or rejected the credentials (try `%s login %s`)", engine, registryHostOrDefault(image))
	case pullFailureNetwork:
		cause = "the registry could not be reached (network, DNS, proxy or TLS error)"
	case pullFailureShortName:
		cause = fmt.Sprintf("%s could not resolve the unqualified name to a registry", engine)
	default:
		cause = "the pull failed"
	}
	msg := fmt.Sprintf("%s image %q is not in the local %s image store, and pulling it failed: %s", role, image, engine, cause)
	if !imageHasRegistryHost(image) && kind != pullFailureNetwork && kind != pullFailureAuth {
		msg += fmt.Sprintf("; if it is a locally built image, build or tag it in %s's store under this exact name (`%s image ls` shows what is present)", engine, engine)
		if engine == "podman" {
			msg += "; podman stores local builds as localhost/<name>, so a fully qualified reference avoids registry lookup"
		}
	}
	if detail := engineDetail(pullErr); detail != "" {
		msg += fmt.Sprintf(" (%s said: %s)", engine, detail)
	}
	return errors.New(msg)
}

// engineDetail condenses an engine failure to a few sanitized, bounded lines,
// preferring the ones that carry the error over progress chatter.
func engineDetail(err error) string {
	if err == nil {
		return ""
	}
	var lines, errLines []string
	for _, line := range strings.FieldsFunc(err.Error(), func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = exitStatusPrefix.ReplaceAllString(sanitizeControl(line), "")
		if line == "" {
			continue
		}
		lines = append(lines, line)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") || strings.Contains(lower, "denied") {
			errLines = append(errLines, line)
		}
	}
	picked := errLines
	if len(picked) == 0 {
		picked = lines
		if len(picked) > 3 {
			picked = picked[len(picked)-3:]
		}
	} else if len(picked) > 3 {
		picked = picked[:3]
	}
	out := strings.Join(picked, "; ")
	if utf8.RuneCountInString(out) > pullDetailLimit {
		out = string([]rune(out)[:pullDetailLimit]) + "..."
	}
	return out
}

// imageHasRegistryHost applies the reference rule docker and podman share: the
// first path component names a registry when it contains "." or ":" or is
// "localhost".
func imageHasRegistryHost(image string) bool {
	first, _, ok := strings.Cut(image, "/")
	if !ok {
		return false
	}
	return first == "localhost" || strings.ContainsAny(first, ".:")
}

func registryHostOrDefault(image string) string {
	if imageHasRegistryHost(image) {
		first, _, _ := strings.Cut(image, "/")
		return first
	}
	return "docker.io"
}
