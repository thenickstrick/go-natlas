// Package web is the agent's HTTP/HTTPS screenshot transport, implemented
// over chromedp (headless Chrome via the DevTools protocol).
//
// One Chrome process serves the lifetime of the agent; each capture opens a
// fresh tab, navigates, settles, screenshots, and closes the tab. That
// model is roughly an order of magnitude cheaper than spinning up one
// Chrome per scan but doesn't pile session state across captures.
//
// Cert errors are ignored (HTTPS scans regularly hit self-signed certs and
// hostname mismatches). The viewport is fixed at 1280x800 — wide enough to
// avoid mobile-CSS triggers, narrow enough to keep PNG sizes reasonable.
package web

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// Options configures the chromedp capturer.
type Options struct {
	// ChromePath is the absolute path to a Chrome/Chromium binary. Empty =
	// chromedp's default discovery (CHROMEDP_PATH env, then a fixed list of
	// platform-typical locations).
	ChromePath string

	// CaptureTimeout caps a single navigate+screenshot cycle. The agent
	// passes through the dispatcher-controlled WebScreenshotTimeoutS here.
	CaptureTimeout time.Duration

	// ViewportWidth/Height set the headless viewport. Defaults are
	// 1280x800 if zero.
	ViewportWidth  int
	ViewportHeight int

	// Quality is the JPEG quality knob chromedp uses internally for the
	// PNG-encoded screenshot's compression hints. 90 is the chromedp
	// default; lower trades fidelity for file size.
	Quality int
}

// Capturer is the agent-side screenshots.Capturer for HTTP/HTTPS targets.
//
// The browser is allocated lazily on first Capture. That keeps natlas-agent
// startup cheap on hosts where screenshots end up disabled at runtime
// (AgentConfig.WebScreenshots = false).
type Capturer struct {
	opts Options

	once       sync.Once
	allocCtx   context.Context
	allocStop  context.CancelFunc
	browserCtx context.Context
	browserCnl context.CancelFunc
	initErr    error
}

// New returns a Capturer.
func New(opts Options) *Capturer {
	if opts.CaptureTimeout <= 0 {
		opts.CaptureTimeout = 60 * time.Second
	}
	if opts.ViewportWidth <= 0 {
		opts.ViewportWidth = 1280
	}
	if opts.ViewportHeight <= 0 {
		opts.ViewportHeight = 800
	}
	if opts.Quality <= 0 {
		opts.Quality = 90
	}
	return &Capturer{opts: opts}
}

// Close tears down the browser allocator. Safe to call multiple times.
func (c *Capturer) Close() {
	if c.browserCnl != nil {
		c.browserCnl()
	}
	if c.allocStop != nil {
		c.allocStop()
	}
}

// Capture navigates to scheme://target:port/ and returns the PNG bytes.
// service must be "HTTP" or "HTTPS"; anything else is rejected.
func (c *Capturer) Capture(ctx context.Context, target string, port int, service string) ([]byte, error) {
	scheme := "http"
	switch service {
	case "HTTP":
		scheme = "http"
	case "HTTPS":
		scheme = "https"
	default:
		return nil, fmt.Errorf("web capturer: unsupported service %q", service)
	}

	c.once.Do(c.bootstrap)
	if c.initErr != nil {
		return nil, c.initErr
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, target, port)

	tabCtx, cancelTab := chromedp.NewContext(c.browserCtx)
	defer cancelTab()

	captureCtx, cancelCapture := context.WithTimeout(tabCtx, c.opts.CaptureTimeout)
	defer cancelCapture()

	var buf []byte
	err := chromedp.Run(captureCtx,
		chromedp.EmulateViewport(int64(c.opts.ViewportWidth), int64(c.opts.ViewportHeight)),
		chromedp.Navigate(url),
		// Settle: wait briefly for inline script + layout to flush. A real
		// "page is done loading" signal varies wildly across servers; this
		// is a pragmatic upper bound that won't trigger the per-capture
		// timeout on its own.
		chromedp.Sleep(2*time.Second),
		chromedp.FullScreenshot(&buf, c.opts.Quality),
	)
	if err != nil {
		if errors.Is(captureCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("web capturer: timeout after %s on %s", c.opts.CaptureTimeout, url)
		}
		return nil, fmt.Errorf("web capturer: %w", err)
	}
	return buf, nil
}

// bootstrap stands up the long-lived browser process. Errors are stashed
// onto initErr so subsequent Capture calls fail fast rather than retrying
// the allocator over and over.
func (c *Capturer) bootstrap() {
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		chromedp.Headless,
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("hide-scrollbars", true),
	)
	if c.opts.ChromePath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(c.opts.ChromePath))
	}
	c.allocCtx, c.allocStop = chromedp.NewExecAllocator(context.Background(), allocOpts...)
	c.browserCtx, c.browserCnl = chromedp.NewContext(c.allocCtx)

	// Force the browser to actually launch now (rather than at first tab),
	// so initErr is populated when bootstrap completes.
	if err := chromedp.Run(c.browserCtx); err != nil {
		c.initErr = fmt.Errorf("web capturer: chromedp launch: %w", err)
	}
}
