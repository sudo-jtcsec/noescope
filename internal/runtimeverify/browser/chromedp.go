package browser

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	cdpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
)

type Chrome struct {
	allocatorCancel context.CancelFunc
	// targetCtx owns the active Chrome tab. Every target-dependent CDP action,
	// including cookies and final observations, runs through chromedp.Run on it.
	targetCtx    context.Context
	targetCancel context.CancelFunc

	mu          sync.Mutex
	network     []NetworkObservation
	console     []string
	documentURL string
	document    int
}

func NewChrome(parent context.Context, options Options) (*Chrome, error) {
	executablePath, err := ResolveExecutable(options.ExecutablePath)
	if err != nil {
		return nil, err
	}
	allocatorOptions := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(executablePath),
		chromedp.Flag("headless", options.Headless),
		chromedp.Flag("ignore-certificate-errors", options.IgnoreTLSErrors),
		chromedp.Flag("disable-background-networking", true),
	)
	allocatorContext, allocatorCancel := chromedp.NewExecAllocator(parent, allocatorOptions...)
	return newChrome(allocatorContext, allocatorCancel)
}

func NewRemoteChrome(parent context.Context, endpoint string) (*Chrome, error) {
	allocatorContext, allocatorCancel := chromedp.NewRemoteAllocator(parent, endpoint)
	return newChrome(allocatorContext, allocatorCancel)
}

func newChrome(
	allocatorContext context.Context,
	allocatorCancel context.CancelFunc,
) (*Chrome, error) {
	targetCtx, targetCancel := chromedp.NewContext(allocatorContext)
	chrome := &Chrome{
		allocatorCancel: allocatorCancel,
		targetCtx:       targetCtx,
		targetCancel:    targetCancel,
	}
	chromedp.ListenTarget(targetCtx, chrome.handleEvent)
	if err := chromedp.Run(targetCtx, network.Enable(), log.Enable()); err != nil {
		chrome.Close()
		return nil, fmt.Errorf("start Chromium: %w", err)
	}
	return chrome, nil
}

func (c *Chrome) Close() error {
	if c.targetCancel != nil {
		c.targetCancel()
	}
	if c.allocatorCancel != nil {
		c.allocatorCancel()
	}
	return nil
}

func (c *Chrome) Navigate(ctx context.Context, target string) (Page, error) {
	c.reset(target)
	if err := chromedp.Run(c.targetCtx, chromedp.Navigate(target)); err != nil {
		return Page{RequestedURL: target}, fmt.Errorf("navigate: %w", err)
	}
	readyErr := chromedp.Run(c.targetCtx, chromedp.WaitReady("body", chromedp.ByQuery))
	page, err := c.observe(ctx, target)
	if readyErr != nil {
		page.ObservationErrors = append(page.ObservationErrors, BrowserObservationError{
			Operation: "document ready", Err: readyErr,
		})
	}
	return page, err
}

func (c *Chrome) SubmitLogin(
	ctx context.Context,
	login LoginForm,
	credentials Credentials,
) (Page, error) {
	c.reset(login.PageURL)
	actions := loginSubmissionActions(newLoginSubmissionPlan(login.Form), credentials)
	if _, err := chromedp.RunResponse(c.targetCtx, actions...); err != nil {
		return Page{RequestedURL: login.PageURL}, fmt.Errorf("submit login form: %w", err)
	}
	readyErr := chromedp.Run(c.targetCtx, chromedp.WaitReady("body", chromedp.ByQuery))
	page, err := c.observe(ctx, login.PageURL)
	if readyErr != nil {
		page.ObservationErrors = append(page.ObservationErrors, BrowserObservationError{
			Operation: "document ready", Err: readyErr,
		})
	}
	return page, err
}

func (c *Chrome) SubmitForm(_ context.Context, submission FormSubmission) (Page, error) {
	c.reset(submission.PageURL)
	actions := make([]chromedp.Action, 0, len(submission.Entries)*5+1)
	for _, entry := range submission.Entries {
		if entry.Selector == "" {
			return Page{RequestedURL: submission.PageURL}, fmt.Errorf("submit form: empty control selector")
		}
		switch entry.Type {
		case "select", "select-one", "select-multiple":
			actions = append(actions, chromedp.SetValue(entry.Selector, entry.Value, chromedp.ByQuery))
		default:
			actions = append(actions, liveControlEntryActions(entry.Selector, entry.Value)...)
		}
	}
	if submission.SubmitSelector == "" {
		return Page{RequestedURL: submission.PageURL}, fmt.Errorf("submit form: no native submit control")
	}
	actions = append(actions, chromedp.Click(submission.SubmitSelector, chromedp.ByQuery))
	if _, err := chromedp.RunResponse(c.targetCtx, actions...); err != nil {
		return Page{RequestedURL: submission.PageURL}, fmt.Errorf("submit form: %w", err)
	}
	readyErr := chromedp.Run(c.targetCtx, chromedp.WaitReady("body", chromedp.ByQuery))
	page, err := c.observe(c.targetCtx, submission.PageURL)
	if readyErr != nil {
		page.ObservationErrors = append(page.ObservationErrors, BrowserObservationError{Operation: "document ready", Err: readyErr})
	}
	return page, err
}

func (c *Chrome) SubmitOneTimeCode(_ context.Context, submission FormSubmission) (Page, error) {
	if len(submission.Entries) != 1 || submission.Entries[0].Selector == "" {
		return Page{RequestedURL: submission.PageURL}, fmt.Errorf("submit one-time code: exactly one bound control is required")
	}
	c.reset(submission.PageURL)
	entry := submission.Entries[0]
	actions := liveControlEntryActions(entry.Selector, entry.Value)
	if submission.SubmitSelector != "" {
		actions = append(actions, chromedp.Click(submission.SubmitSelector, chromedp.ByQuery))
	} else {
		actions = append(actions, chromedp.SendKeys(entry.Selector, kb.Enter, chromedp.ByQuery))
	}
	if _, err := chromedp.RunResponse(c.targetCtx, actions...); err != nil {
		return Page{RequestedURL: submission.PageURL}, fmt.Errorf("submit one-time code: %w", err)
	}
	readyErr := chromedp.Run(c.targetCtx, chromedp.WaitReady("body", chromedp.ByQuery))
	page, err := c.observe(c.targetCtx, submission.PageURL)
	if readyErr != nil {
		page.ObservationErrors = append(page.ObservationErrors, BrowserObservationError{Operation: "document ready", Err: readyErr})
	}
	return page, err
}

func (c *Chrome) Activate(_ context.Context, activation Activation) (Page, error) {
	if activation.Selector == "" {
		return Page{RequestedURL: activation.PageURL}, fmt.Errorf("activate control: empty selector")
	}
	c.reset(activation.PageURL)
	if _, err := chromedp.RunResponse(c.targetCtx, chromedp.Click(activation.Selector, chromedp.ByQuery)); err != nil {
		return Page{RequestedURL: activation.PageURL}, fmt.Errorf("activate control: %w", err)
	}
	readyErr := chromedp.Run(c.targetCtx, chromedp.WaitReady("body", chromedp.ByQuery))
	page, err := c.observe(c.targetCtx, activation.PageURL)
	if readyErr != nil {
		page.ObservationErrors = append(page.ObservationErrors, BrowserObservationError{Operation: "document ready", Err: readyErr})
	}
	return page, err
}

type loginSubmissionPlan struct {
	UsernameSelector string
	PasswordSelector string
	SubmitSelector   string
}

func newLoginSubmissionPlan(form Form) loginSubmissionPlan {
	return loginSubmissionPlan{
		UsernameSelector: form.UsernameSelector,
		PasswordSelector: form.PasswordSelector,
		SubmitSelector:   form.SubmitSelector,
	}
}

func loginSubmissionActions(plan loginSubmissionPlan, credentials Credentials) []chromedp.Action {
	// Every query is resolved against the live DOM when this action sequence is
	// executed. No DOM NodeID from form discovery is retained or reused.
	actions := make([]chromedp.Action, 0, 13)
	actions = append(actions, liveControlEntryActions(plan.UsernameSelector, credentials.Username)...)
	actions = append(actions, liveControlEntryActions(plan.PasswordSelector, credentials.Password)...)
	if plan.SubmitSelector != "" {
		return append(actions, chromedp.Click(plan.SubmitSelector, chromedp.ByQuery))
	}
	return append(actions, chromedp.SendKeys(plan.PasswordSelector, kb.Enter, chromedp.ByQuery))
}

func liveControlEntryActions(selector, value string) []chromedp.Action {
	return []chromedp.Action{
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		chromedp.Focus(selector, chromedp.ByQuery),
		chromedp.KeyEvent("a", chromedp.KeyModifiers(input.ModifierCtrl)),
		chromedp.KeyEvent(kb.Backspace),
		chromedp.SendKeys(selector, value, chromedp.ByQuery),
	}
}

func (c *Chrome) Screenshot(_ context.Context, path string) error {
	var image []byte
	if err := chromedp.Run(c.targetCtx, chromedp.FullScreenshot(&image, 85)); err != nil {
		return fmt.Errorf("capture screenshot: %w", err)
	}
	if err := writeScreenshot(path, image); err != nil {
		return err
	}
	return nil
}

func (c *Chrome) observe(_ context.Context, requestedURL string) (Page, error) {
	page := Page{RequestedURL: requestedURL, Ready: true}
	var finalURL string
	if err := chromedp.Run(c.targetCtx, chromedp.Location(&finalURL)); err != nil {
		page.ObservationErrors = append(page.ObservationErrors, BrowserObservationError{
			Operation: "final URL", Err: err,
		})
	} else {
		page.FinalURL = finalURL
	}
	if page.FinalURL == "" {
		page.FinalURL = requestedURL
	}
	if err := chromedp.Run(c.targetCtx, chromedp.Title(&page.Title)); err != nil {
		page.ObservationErrors = append(page.ObservationErrors, BrowserObservationError{
			Operation: "title", Err: err,
		})
	}
	var snapshot pageSnapshot
	if err := chromedp.Run(c.targetCtx, chromedp.Evaluate(snapshotScript, &snapshot)); err != nil {
		page.ObservationErrors = append(page.ObservationErrors, BrowserObservationError{
			Operation: "DOM", Err: err,
		})
	} else {
		page.Forms = formsFromSnapshot(snapshot.Forms)
		page.Elements = snapshot.Elements
		page.Links = snapshot.Links
	}
	if err := chromedp.Run(c.targetCtx, inspectCookiesAction(readCDPCookies, &page.Cookies)); err != nil {
		page.ObservationErrors = append(page.ObservationErrors, BrowserObservationError{
			Operation: "cookies", Err: err,
		})
	}
	sort.Slice(page.Cookies, func(i, j int) bool {
		return page.Cookies[i].Name+page.Cookies[i].Domain <
			page.Cookies[j].Name+page.Cookies[j].Domain
	})
	c.mu.Lock()
	page.HTTPStatus = c.document
	page.Network = append([]NetworkObservation(nil), c.network...)
	page.ConsoleErrors = append([]string(nil), c.console...)
	c.mu.Unlock()
	return page, nil
}

type cookieReader func(context.Context) ([]Cookie, error)

func inspectCookiesAction(read cookieReader, destination *[]Cookie) chromedp.ActionFunc {
	return func(actionCtx context.Context) error {
		cookies, err := read(actionCtx)
		if err != nil {
			return err
		}
		*destination = append((*destination)[:0], cookies...)
		return nil
	}
}

func readCDPCookies(actionCtx context.Context) ([]Cookie, error) {
	cookies, err := storage.GetCookies().Do(actionCtx)
	if err != nil {
		return nil, err
	}
	result := make([]Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		result = append(result, Cookie{
			Name: cookie.Name, Domain: cookie.Domain, Path: cookie.Path,
			Secure: cookie.Secure, HTTPOnly: cookie.HTTPOnly,
		})
	}
	return result, nil
}

func (c *Chrome) reset(target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.network = nil
	c.console = nil
	c.documentURL = target
	c.document = 0
}

func (c *Chrome) handleEvent(event any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch value := event.(type) {
	case *network.EventRequestWillBeSent:
		if value.Type == network.ResourceTypeDocument ||
			value.Type == network.ResourceTypeXHR ||
			value.Type == network.ResourceTypeFetch {
			c.network = append(c.network, NetworkObservation{
				Method: value.Request.Method, URL: value.Request.URL, Type: string(value.Type),
			})
		}
	case *network.EventResponseReceived:
		if value.Type == network.ResourceTypeDocument {
			c.document = int(value.Response.Status)
		}
		for index := len(c.network) - 1; index >= 0; index-- {
			if c.network[index].URL == value.Response.URL && c.network[index].Status == 0 {
				c.network[index].Status = int(value.Response.Status)
				break
			}
		}
	case *cdpruntime.EventConsoleAPICalled:
		if value.Type == cdpruntime.APITypeError {
			c.console = append(c.console, "browser console error")
		}
	case *cdpruntime.EventExceptionThrown:
		c.console = append(c.console, "uncaught browser exception")
	case *log.EventEntryAdded:
		if value.Entry.Level == log.LevelError {
			c.console = append(c.console, value.Entry.Text)
		}
	}
}

type pageSnapshot struct {
	Forms    []formSnapshot `json:"forms"`
	Elements []Element      `json:"elements"`
	Links    []Link         `json:"links"`
}

type formSnapshot struct {
	Selector string            `json:"selector"`
	Action   string            `json:"action"`
	Method   string            `json:"method"`
	Controls []controlSnapshot `json:"controls"`
	Submit   *controlSnapshot  `json:"submit"`
}

type controlSnapshot struct {
	Name         string         `json:"name"`
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Autocomplete string         `json:"autocomplete"`
	Text         string         `json:"text"`
	Selector     string         `json:"selector"`
	Label        string         `json:"label"`
	Options      []SelectOption `json:"options"`
}

func formsFromSnapshot(snapshots []formSnapshot) []Form {
	forms := make([]Form, 0, len(snapshots))
	for _, snapshot := range snapshots {
		form := Form{Selector: snapshot.Selector, Action: snapshot.Action, Method: snapshot.Method, Controls: []FormControl{}}
		var username *controlSnapshot
		var password *controlSnapshot
		usernamePreferred := false
		for index := range snapshot.Controls {
			candidate := &snapshot.Controls[index]
			if safeMutableControlType(candidate.Type) {
				form.Controls = append(form.Controls, FormControl{
					ID: candidate.ID, Name: candidate.Name, Type: candidate.Type,
					Label: candidate.Label, Autocomplete: candidate.Autocomplete,
					Selector: candidate.Selector, Options: append([]SelectOption(nil), candidate.Options...),
				})
			}
			if password == nil && candidate.Type == "password" {
				password = candidate
			}
			if candidate.Type != "text" && candidate.Type != "email" && candidate.Type != "" {
				continue
			}
			if username == nil || (!usernamePreferred && candidate.Autocomplete == "username") {
				username = candidate
				usernamePreferred = candidate.Autocomplete == "username"
			}
		}
		if username != nil {
			form.UsernameField = username.Name
			form.UsernameID = username.ID
			form.UsernameType = username.Type
			form.UsernameAutocomplete = username.Autocomplete
			form.UsernameSelector = username.Selector
		}
		if password != nil {
			form.PasswordField = password.Name
			form.PasswordID = password.ID
			form.PasswordType = password.Type
			form.PasswordAutocomplete = password.Autocomplete
			form.PasswordSelector = password.Selector
		}
		if snapshot.Submit != nil {
			form.SubmitType = snapshot.Submit.Type
			form.SubmitLabel = snapshot.Submit.Text
			form.SubmitSelector = snapshot.Submit.Selector
		}
		forms = append(forms, form)
	}
	return forms
}

func safeMutableControlType(controlType string) bool {
	switch controlType {
	case "", "text", "email", "number", "date", "datetime-local", "textarea", "select-one", "select-multiple", "select":
		return true
	default:
		return false
	}
}

const snapshotScript = `(() => {
  const selector = (element) => {
    if (element.id) {
      const byID = '#' + CSS.escape(element.id);
      if (document.querySelectorAll(byID).length === 1) return byID;
    }
    if (element.name) {
      const byName = element.tagName.toLowerCase() + '[name=' + JSON.stringify(element.name) + ']';
      const owner = element.closest('form');
      if ((owner || document).querySelectorAll(byName).length === 1) return byName;
    }
    const parts = [];
    while (element && element.nodeType === Node.ELEMENT_NODE && parts.length < 8) {
      let part = element.tagName.toLowerCase();
      const siblings = element.parentElement ? Array.from(element.parentElement.children).filter(x => x.tagName === element.tagName) : [];
      if (siblings.length > 1) part += ':nth-of-type(' + (siblings.indexOf(element) + 1) + ')';
      parts.unshift(part);
      element = element.parentElement;
    }
    return parts.join(' > ');
  };
	const control = (element, elementSelector) => element ? ({
		name: element.name || '',
		id: element.id || '',
		type: (element.type || element.tagName || '').toLowerCase(),
		autocomplete: element.autocomplete || '',
		text: ((element.innerText || '').trim()).slice(0, 120),
		selector: elementSelector,
		label: (() => {
			if (element.getAttribute('aria-label')) return element.getAttribute('aria-label').slice(0, 120);
			if (element.labels && element.labels.length) return (element.labels[0].innerText || '').trim().slice(0, 120);
			return '';
		})(),
		options: element.tagName && element.tagName.toLowerCase() === 'select' ?
			Array.from(element.options).slice(0, 100).map(option => ({value: option.value, text: (option.text || '').trim().slice(0, 120)})) : []
	}) : null;
  const forms = Array.from(document.forms).slice(0, 20).map(form => {
		const inputs = Array.from(form.querySelectorAll('input,textarea,select'));
    const submit = form.querySelector('button[type=submit], input[type=submit], button:not([type])');
		const action = form.getAttribute('action') || '';
		const formSelector = form.id ? '#' + CSS.escape(form.id) :
			(action ? 'form[action=' + JSON.stringify(action) + ']' : selector(form));
		let submitPart = '';
		if (submit) {
			if (submit.id) submitPart = '#' + CSS.escape(submit.id);
			else if (submit.tagName.toLowerCase() === 'input') submitPart = 'input[type="submit"]';
			else if (submit.hasAttribute('type')) submitPart = 'button[type="submit"]';
			else submitPart = 'button:not([type])';
		}
    return {
		  selector: formSelector,
		  action,
      method: (form.method || 'get').toUpperCase(),
		  controls: inputs.map(input => control(input, selector(input))),
		  submit: control(submit, submit ? formSelector + ' ' + submitPart : '')
    };
  });
  const elements = Array.from(document.querySelectorAll('h1,h2,h3,main,[role=heading],[aria-label],nav a'))
    .slice(0, 40).map(element => ({
      role: element.getAttribute('role') || element.tagName.toLowerCase(),
      name: (element.getAttribute('aria-label') || '').slice(0, 160),
      text: (element.innerText || '').trim().replace(/\s+/g, ' ').slice(0, 240)
    })).filter(element => element.name || element.text);
  const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 200)
		.map(link => ({url: link.href, text: (link.innerText || '').trim().replace(/\s+/g, ' ').slice(0, 160), selector: selector(link)}));
  return {forms, elements, links};
})()`
