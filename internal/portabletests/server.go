package portabletests

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	bundle  *Bundle
	options RunOptions
	mu      sync.Mutex
	running bool
	current string
	lastErr string
	nonce   string
}

func NewServer(bundle *Bundle, options RunOptions) *Server {
	return &Server{bundle: bundle, options: options, nonce: newSuffix()}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("POST /run", s.run)
	return mux
}

func (s *Server) Serve(ctx context.Context, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("portable test UI refuses non-loopback address %q", address)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = server.Shutdown(context.Background()) }()
	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) index(writer http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	running, current, lastErr := s.running, s.current, s.lastErr
	bundle := *s.bundle
	bundle.History = append([]Execution(nil), s.bundle.History...)
	bundle.Evidence = append([]Evidence(nil), s.bundle.Evidence...)
	s.mu.Unlock()
	htmlReport, err := HTML(&bundle)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	var controls strings.Builder
	controls.WriteString(`<section class="meta"><h2>Run tests</h2>`)
	if running {
		controls.WriteString(`<p><strong>Running: ` + template.HTMLEscapeString(current) + `</strong></p><meta http-equiv="refresh" content="2">`)
	}
	if lastErr != "" {
		controls.WriteString(`<p class="warning">` + template.HTMLEscapeString(lastErr) + `</p>`)
	}
	if !running {
		controls.WriteString(`<form method="post" action="/run"><input type="hidden" name="ui_nonce" value="` + template.HTMLEscapeString(s.nonce) + `"><button type="submit">Run All Eligible Tests</button></form>`)
	}
	for _, test := range sortedTests(s.bundle.Tests) {
		controls.WriteString(`<form method="post" action="/run"><input type="hidden" name="ui_nonce" value="` + template.HTMLEscapeString(s.nonce) + `"><input type="hidden" name="test" value="` + template.HTMLEscapeString(test.ID) + `"><button type="submit">Run Test: ` + template.HTMLEscapeString(test.Name) + `</button></form>`)
	}
	controls.WriteString(`</section>`)
	page := strings.Replace(string(htmlReport), `<h2>Tests</h2>`, controls.String()+`<h2>Tests</h2>`, 1)
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = writer.Write([]byte(page))
}

func (s *Server) run(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid form", http.StatusBadRequest)
		return
	}
	if request.Form.Get("ui_nonce") != s.nonce {
		http.Error(writer, "invalid UI request token", http.StatusForbidden)
		return
	}
	testID := request.Form.Get("test")
	if testID != "" {
		test, ok := findTest(s.bundle.Tests, testID)
		if !ok {
			http.Error(writer, "test not found", http.StatusNotFound)
			return
		}
		if test.Safety.Mutating {
			if !s.options.Mutations {
				http.Error(writer, "mutating tests are disabled", http.StatusForbidden)
				return
			}
			if request.Form.Get("confirm") != "yes" {
				writer.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprintf(writer, `<!doctype html><title>Confirm mutating test</title><h1>This test modifies application data.</h1><p>Test: %s</p><p>Cleanup: Always</p><form method="post" action="/run"><input type="hidden" name="ui_nonce" value="%s"><input type="hidden" name="test" value="%s"><input type="hidden" name="confirm" value="yes"><button type="submit">Run Mutating Test</button></form><a href="/">Cancel</a>`, template.HTMLEscapeString(test.Name), template.HTMLEscapeString(s.nonce), template.HTMLEscapeString(test.ID))
				return
			}
		}
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		http.Error(writer, "a test run is already active", http.StatusConflict)
		return
	}
	s.running, s.current, s.lastErr = true, testID, ""
	if testID == "" {
		s.current = "all eligible tests"
	}
	s.mu.Unlock()
	go func() {
		options := s.options
		options.SelectedTestID = testID
		// "Run All Eligible" remains read-only. Mutating UI execution is
		// available only through an individually confirmed test action.
		if testID == "" {
			options.Mutations = false
		}
		runner := Runner{Bundle: s.bundle, Options: options}
		execution, _, err := runner.Run(context.Background())
		s.mu.Lock()
		if err != nil {
			s.lastErr = err.Error()
		}
		if execution != nil {
			s.bundle.History = append(s.bundle.History, *execution)
			s.bundle.Evidence = append(s.bundle.Evidence, runner.evidence...)
		}
		s.running, s.current = false, ""
		s.mu.Unlock()
	}()
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}
