package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

var isTerminal = term.IsTerminal(int(os.Stderr.Fd()))

// Reader tracks read progress.
type Reader struct {
	r        io.Reader
	total    int64
	current  int64
	mu       sync.Mutex
	ticker   *time.Ticker
	done     chan struct{}
	prefix   string
	start    time.Time
	finished bool
}

// NewReader wraps an io.Reader with a progress bar on stderr.
func NewReader(r io.Reader, total int64, prefix string) *Reader {
	pr := &Reader{
		r:      r,
		total:  total,
		prefix: prefix,
		start:  time.Now(),
		done:   make(chan struct{}),
	}

	if isTerminal {
		pr.ticker = time.NewTicker(100 * time.Millisecond)
		go pr.render()
	}

	return pr
}

func (pr *Reader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	pr.mu.Lock()
	pr.current += int64(n)
	pr.mu.Unlock()

	if err != nil {
		pr.Finish()
	}
	return n, err
}

// Finish stops the progress bar.
func (pr *Reader) Finish() {
	if pr.finished {
		return
	}
	pr.finished = true
	if pr.ticker != nil {
		pr.ticker.Stop()
		close(pr.done)
		pr.render()
		fmt.Fprint(os.Stderr, "\n")
	}
}

func (pr *Reader) render() {
	for {
		select {
		case <-pr.ticker.C:
			pr.draw()
		case <-pr.done:
			pr.draw()
			return
		}
	}
}

func (pr *Reader) draw() {
	if !isTerminal {
		return
	}

	pr.mu.Lock()
	current := pr.current
	pr.mu.Unlock()

	total := pr.total
	elapsed := time.Since(pr.start)
	speed := float64(current) / elapsed.Seconds()

	width, _, _ := term.GetSize(int(os.Stderr.Fd()))
	barWidth := width - 50
	if barWidth < 10 {
		barWidth = 10
	}

	var bar string
	var percent float64
	if total > 0 {
		percent = float64(current) / float64(total)
		filled := int(percent * float64(barWidth))
		bar = strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	} else {
		bar = strings.Repeat("~", barWidth)
	}

	status := fmt.Sprintf("%s %s %3.0f%%  %s/%s  %s/s",
		pr.prefix,
		bar,
		percent*100,
		humanSize(current),
		humanSize(total),
		humanSize(int64(speed)),
	)

	fmt.Fprintf(os.Stderr, "\r%-*s", width, status)
}

// Writer tracks write progress.
type Writer struct {
	w        io.Writer
	total    int64
	current  int64
	mu       sync.Mutex
	ticker   *time.Ticker
	done     chan struct{}
	prefix   string
	start    time.Time
	finished bool
}

// NewWriter wraps an io.Writer with a progress bar.
func NewWriter(w io.Writer, total int64, prefix string) *Writer {
	pw := &Writer{
		w:      w,
		total:  total,
		prefix: prefix,
		start:  time.Now(),
		done:   make(chan struct{}),
	}

	if isTerminal {
		pw.ticker = time.NewTicker(100 * time.Millisecond)
		go pw.render()
	}

	return pw
}

func (pw *Writer) Write(p []byte) (int, error) {
	n, err := pw.w.Write(p)
	pw.mu.Lock()
	pw.current += int64(n)
	pw.mu.Unlock()

	if err != nil {
		pw.Finish()
	}
	return n, err
}

// Finish stops the progress bar.
func (pw *Writer) Finish() {
	if pw.finished {
		return
	}
	pw.finished = true
	if pw.ticker != nil {
		pw.ticker.Stop()
		close(pw.done)
		pw.render()
		fmt.Fprint(os.Stderr, "\n")
	}
}

func (pw *Writer) render() {
	for {
		select {
		case <-pw.ticker.C:
			pw.draw()
		case <-pw.done:
			pw.draw()
			return
		}
	}
}

func (pw *Writer) draw() {
	if !isTerminal {
		return
	}

	pw.mu.Lock()
	current := pw.current
	pw.mu.Unlock()

	elapsed := time.Since(pw.start)
	speed := float64(current) / elapsed.Seconds()

	width, _, _ := term.GetSize(int(os.Stderr.Fd()))
	barWidth := width - 50
	if barWidth < 10 {
		barWidth = 10
	}

	var bar string
	if pw.total > 0 {
		filled := int(float64(current) / float64(pw.total) * float64(barWidth))
		bar = strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	} else {
		bar = strings.Repeat("~", barWidth)
	}

	fmt.Fprintf(os.Stderr, "\r%s %s  %s/%s  %s/s",
		pw.prefix, bar, humanSize(current), humanSize(pw.total), humanSize(int64(speed)))
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
