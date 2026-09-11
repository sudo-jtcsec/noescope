package config

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// RuntimeCredentials exist only in process memory and intentionally have no
// serialization tags or persistence path.
type RuntimeCredentials struct {
	Username string `json:"-" yaml:"-"`
	Password string `json:"-" yaml:"-"`
}

func (i *IdentityConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("identity configuration must be an object")
	}
	for index := 0; index+1 < len(value.Content); index += 2 {
		switch value.Content[index].Value {
		case "username", "password":
			return fmt.Errorf(
				"identity credentials must use username_env and password_env, not literal %s",
				value.Content[index].Value,
			)
		}
	}
	type identityAlias IdentityConfig
	var decoded identityAlias
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*i = IdentityConfig(decoded)
	return nil
}

func (c Config) Identity(id string) (IdentityConfig, error) {
	if id == "" {
		return IdentityConfig{}, fmt.Errorf("runtime.identity is not configured")
	}
	for _, identity := range c.Identities {
		if identity.ID == id {
			return identity, nil
		}
	}
	return IdentityConfig{}, fmt.Errorf("runtime identity %q is not configured", id)
}

func (i IdentityConfig) ResolveCredentials(
	lookup func(string) (string, bool),
) (RuntimeCredentials, error) {
	if !environmentNamePattern.MatchString(i.UsernameEnv) ||
		!environmentNamePattern.MatchString(i.PasswordEnv) {
		return RuntimeCredentials{}, fmt.Errorf(
			"identity %q must use username_env and password_env environment variable names",
			i.ID,
		)
	}
	username, usernameOK := lookup(i.UsernameEnv)
	password, passwordOK := lookup(i.PasswordEnv)
	if !usernameOK || username == "" {
		return RuntimeCredentials{}, fmt.Errorf(
			"identity %q environment variable %s is not set",
			i.ID, i.UsernameEnv,
		)
	}
	if !passwordOK || password == "" {
		return RuntimeCredentials{}, fmt.Errorf(
			"identity %q environment variable %s is not set",
			i.ID, i.PasswordEnv,
		)
	}
	return RuntimeCredentials{Username: username, Password: password}, nil
}
