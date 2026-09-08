package config

type Config struct {
	Project     ProjectConfig     `yaml:"project"`
	Source      SourceConfig      `yaml:"source"`
	Application ApplicationConfig `yaml:"application"`
	Identities  []IdentityConfig  `yaml:"identities"`
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
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
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
