package config

import (
	"fmt"
	"regexp"
	"strings"

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
	if i.TOTP != nil {
		if !environmentNamePattern.MatchString(i.TOTP.SecretEnv) {
			return fmt.Errorf("identity %q totp.secret_env must be an environment variable name", i.ID)
		}
		if i.TOTP.Period != 0 && (i.TOTP.Period < 5 || i.TOTP.Period > 300) {
			return fmt.Errorf("identity %q totp.period must be between 5 and 300 seconds", i.ID)
		}
		if i.TOTP.Digits != 0 && i.TOTP.Digits != 6 && i.TOTP.Digits != 8 {
			return fmt.Errorf("identity %q totp.digits must be 6 or 8", i.ID)
		}
		algorithm := strings.ToUpper(strings.TrimSpace(i.TOTP.Algorithm))
		if algorithm != "" && algorithm != "SHA1" && algorithm != "SHA256" && algorithm != "SHA512" {
			return fmt.Errorf("identity %q totp.algorithm must be SHA1, SHA256, or SHA512", i.ID)
		}
		i.TOTP.Algorithm = algorithm
	}
	return nil
}

func (t *TOTPConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("totp configuration must be an object")
	}
	for index := 0; index+1 < len(value.Content); index += 2 {
		switch value.Content[index].Value {
		case "secret", "seed", "otpauth_uri":
			return fmt.Errorf("TOTP credentials must use secret_env, not literal %s", value.Content[index].Value)
		}
	}
	type totpAlias TOTPConfig
	var decoded totpAlias
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*t = TOTPConfig(decoded)
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
