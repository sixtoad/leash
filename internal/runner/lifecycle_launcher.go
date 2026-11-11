package runner

import "context"

// The decorator measures the existing gates without changing their order,
// authority, cancellation or errors. Only an opted-in runner installs it.
type telemetryLauncher struct {
	launcher
	telemetry *lifecycleTelemetry
}

func (l telemetryLauncher) PullImages(ctx context.Context) (err error) {
	finish := l.telemetry.phase("image_prepare")
	defer func() { finish(err) }()
	return l.launcher.PullImages(ctx)
}

func (l telemetryLauncher) Provision(ctx context.Context, signal string) (path string, err error) {
	finish := l.telemetry.phase("provision")
	defer func() { finish(err) }()
	return l.launcher.Provision(ctx, signal)
}

func (l telemetryLauncher) StartEnforcement(ctx context.Context, path string) (err error) {
	finish := l.telemetry.phase("enforcement")
	defer func() { finish(err) }()
	return l.launcher.StartEnforcement(ctx, path)
}

func (l telemetryLauncher) WaitReady(ctx context.Context) (err error) {
	finish := l.telemetry.phase("attach")
	defer func() { finish(err) }()
	return l.launcher.WaitReady(ctx)
}

func (l telemetryLauncher) Remove(ctx context.Context) (err error) {
	finish := l.telemetry.phase("cleanup")
	defer func() { finish(err) }()
	return l.launcher.Remove(ctx)
}
