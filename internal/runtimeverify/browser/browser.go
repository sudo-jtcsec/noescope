package browser

import (
	"context"
	"fmt"
)

type Options struct {
	Headless        bool
	IgnoreTLSErrors bool
	ExecutablePath  string
}

// BrowserObservationError describes an optional observation that failed after
// browser navigation completed. It is deliberately distinct from a navigation
// error so callers do not misclassify a reachable application as unreachable.
type BrowserObservationError struct {
	Operation string
	Err       error
}

func (e BrowserObservationError) Error() string {
	return fmt.Sprintf("inspect %s: %v", e.Operation, e.Err)
}

func (e BrowserObservationError) Unwrap() error { return e.Err }

type Credentials struct {
	Username string `json:"-" yaml:"-"`
	Password string `json:"-" yaml:"-"`
}

type Engine interface {
	Navigate(context.Context, string) (Page, error)
	SubmitLogin(context.Context, LoginForm, Credentials) (Page, error)
	Screenshot(context.Context, string) error
	Close() error
}

// MutationEngine is the deliberately small browser capability used by the
// deterministic Core Test executor. Plans select controls from a live Form;
// model output never supplies arbitrary selectors or script.
type MutationEngine interface {
	Engine
	SubmitForm(context.Context, FormSubmission) (Page, error)
	Activate(context.Context, Activation) (Page, error)
}

type Page struct {
	RequestedURL      string
	FinalURL          string
	Title             string
	HTTPStatus        int
	Ready             bool
	Forms             []Form
	Elements          []Element
	Links             []Link
	Network           []NetworkObservation
	ConsoleErrors     []string
	Cookies           []Cookie
	ObservationErrors []BrowserObservationError
}

type Form struct {
	Selector             string
	Action               string
	Method               string
	Controls             []FormControl
	UsernameField        string
	UsernameID           string
	UsernameType         string
	UsernameAutocomplete string
	PasswordField        string
	PasswordID           string
	PasswordType         string
	PasswordAutocomplete string
	SubmitType           string
	SubmitLabel          string
	UsernameSelector     string
	PasswordSelector     string
	SubmitSelector       string
}

type FormControl struct {
	ID           string
	Name         string
	Type         string
	Label        string
	Autocomplete string
	Selector     string
	Options      []SelectOption
}

type SelectOption struct {
	Value string
	Text  string
}

type FormEntry struct {
	Selector string
	Type     string
	Value    string
}

type FormSubmission struct {
	PageURL        string
	FormSelector   string
	SubmitSelector string
	Entries        []FormEntry
}

type Activation struct {
	PageURL  string
	Selector string
	Label    string
}

type LoginForm struct {
	PageURL string
	Form    Form
}

type Element struct {
	Role string
	Name string
	Text string
}

type Link struct {
	URL      string
	Text     string
	Selector string
}

type NetworkObservation struct {
	Method string
	URL    string
	Status int
	Type   string
}

type Cookie struct {
	Name     string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
}

func DetectLoginForm(page Page) (LoginForm, bool) {
	for _, form := range page.Forms {
		if form.PasswordSelector != "" && form.UsernameSelector != "" {
			return LoginForm{PageURL: page.FinalURL, Form: form}, true
		}
	}
	return LoginForm{}, false
}
