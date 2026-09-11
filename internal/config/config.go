package config

type Config struct {
	Project     ProjectConfig     `yaml:"project"`
	Source      SourceConfig      `yaml:"source"`
	Application ApplicationConfig `yaml:"application"`
	Identities  []IdentityConfig  `yaml:"identities"`
	Runtime     RuntimeConfig     `yaml:"runtime"`
	AI          AIConfig          `yaml:"ai"`
	Discovery   DiscoveryConfig   `yaml:"discovery"`
}

type ProjectConfig struct {
	Name string `yaml:"name"`
}

type SourceConfig struct {
	Path   string   `yaml:"path"`
	Ignore []string `yaml:"ignore"`
	Deny   []string `yaml:"deny"`
}

type ApplicationConfig struct {
	URL string `yaml:"url"`
}

type IdentityConfig struct {
	ID           string `yaml:"id"`
	ExpectedRole string `yaml:"expected_role"`
	UsernameEnv  string `yaml:"username_env"`
	PasswordEnv  string `yaml:"password_env"`
}

type RuntimeConfig struct {
	BaseURL  string               `yaml:"base_url"`
	Browser  RuntimeBrowserConfig `yaml:"browser"`
	Identity string               `yaml:"identity"`
}

type RuntimeBrowserConfig struct {
	Headless        bool   `yaml:"headless"`
	IgnoreTLSErrors bool   `yaml:"ignore_tls_errors"`
	Executable      string `yaml:"executable"`
}

type AIConfig struct {
	BaseURL string `yaml:"base_url"`
	Model   string `yaml:"model"`
	APIKey  string `yaml:"api_key"`
}

type DiscoveryConfig struct {
	AllowedHosts       []string `yaml:"allowed_hosts"`
	ExternalNavigation bool     `yaml:"external_navigation"`
	DestructiveActions bool     `yaml:"destructive_actions"`
	MaxPages           int      `yaml:"max_pages"`
}
