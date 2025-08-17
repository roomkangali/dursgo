// internal/renderer/renderer.go
package renderer

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
)

// Renderer is a component that manages interactions with a headless browser (Chromedp).
type Renderer struct {
	allocCtx context.Context    // Context for the browser allocator.
	cancel   context.CancelFunc // Function to cancel the allocator context and close the browser.
}

// New creates a new renderer instance and initializes the browser allocator.
func New() (*Renderer, error) {
	// Options to run Chrome/Chromium in an optimized headless mode.
	// "no-sandbox" and "disable-dev-shm-usage" are important for stability in server/Docker environments.
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),              // Run in headless mode (no UI).
		chromedp.Flag("disable-gpu", true),           // Disable GPU hardware acceleration.
		chromedp.Flag("no-sandbox", true),            // Disable sandbox for better compatibility.
		chromedp.Flag("disable-dev-shm-usage", true), // Overcome limited resource issues in some environments.
	)

	// Create a new execution allocator context.
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)

	return &Renderer{
		allocCtx: allocCtx,
		cancel:   cancel,
	}, nil
}

// GetRenderedHTML navigates to a URL, waits for JavaScript to execute, and returns the final HTML.
func (r *Renderer) GetRenderedHTML(urlStr string, timeout time.Duration) (string, error) {
	// Create a new context with a timeout for each rendering task.
	taskCtx, cancelTask := context.WithTimeout(r.allocCtx, timeout)
	defer cancelTask() // Ensure the task context is cancelled.

	// Create a new Chrome tab instance for this task.
	taskCtx, cancelTask = chromedp.NewContext(taskCtx)
	defer cancelTask() // Ensure the tab context is cancelled.

	var htmlContent string
	// Execute a sequence of actions within the browser.
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(urlStr),     // 1. Navigate to the given URL.
		chromedp.Sleep(2*time.Second), // 2. Wait for 2 seconds to allow SPAs to load and render.
		chromedp.OuterHTML("html", &htmlContent), // 3. Get the outer HTML of the <html> element.
	)

	if err != nil {
		return "", err // Return error if any action fails.
	}
	return htmlContent, nil // Return the rendered HTML content.
}

// GetAllocatorContext returns the allocator context of the renderer.
func (r *Renderer) GetAllocatorContext() context.Context {
	return r.allocCtx
}

// Close closes the headless browser and cleans up resources.
func (r *Renderer) Close() {
	r.cancel() // Call the cancel function to shut down the allocator.
}
