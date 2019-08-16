// Package config provides configuration for client apps based on the Cryptowatch SDK.
package config // import "code.cryptowat.ch/cw-sdk-go/config"

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/juju/errors"
	"gopkg.in/yaml.v2"
)

// Default URLs used if one of the URLs isn't specified.
const (
	DefaultAPIURL    = "https://api.cryptowat.ch"
	DefaultStreamURL = "wss://stream.cryptowat.ch"
	DefaultTradeURL  = "wss://trading.service.cryptowat.ch"

	Filepath = ".cw/credentials.yml"
)

// Various validation errors.
var (
	ErrNilConfig      = Error{Type: "config", Why: "config is nil", How: "create and load config first"}
	ErrEmptyAPIKey    = Error{Type: "config", What: "api_url", Why: "is empty", How: "specify an api_key"}
	ErrEmptySecretKey = Error{Type: "config", What: "secret_key", Why: "is empty", How: "specify a secret_key"}
	ErrInvalidHTTPURL = Error{Type: "config", Why: "wrong url", How: "URL must be a valid http or https url"}
	ErrInvalidWSURL   = Error{Type: "config", Why: "wrong url", How: "URL must be a valid ws or wss url"}
	ErrInvalidScheme  = Error{Type: "config", Why: "invalid scheme", How: "scheme must be http(s) or ws(s)"}

	ErrNilArgs = Error{Type: "args", Why: "args is nil", How: "create an instance of args"}
)

// CW holds the configuration.
type CW struct {
	mu        sync.Mutex `yaml:"-"` // protects the fields below
	APIKey    string     `yaml:"api_key"`
	SecretKey string     `yaml:"secret_key"`
	StreamURL string     `yaml:"stream_url"`
	TradeURL  string     `yaml:"trade_url"`
	APIURL    string     `yaml:"api_url"`
}

// New creates a new CW from a file by the given name.
func New(name string) (*CW, error) {
	return NewFromFilename(name)
}

// NewFromFilename creates a new CW from a file by the given filename.
func NewFromFilename(filename string) (*CW, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return NewFromRaw(data)
}

// NewFromRaw creates a new CW by unmarshaling the given raw data.
func NewFromRaw(raw []byte) (*CW, error) {
	cfg := &CW{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, errors.Trace(err)
	}

	return cfg, nil
}

// ValidateFunc validates the config by applying each of given vfs to it.
func (c *CW) ValidateFunc(vfs ...ValidateFuncCW) error {
	if c == nil {
		return ErrNilConfig
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, f := range vfs {
		if err := f(c); err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// Validate validates the config by applying ValidatorDefault.
func (c *CW) Validate() error {
	return c.ValidateFunc(ValidateCWDefault)
}

func (c *CW) Example() *CW {
	cw := &CW{}

	cw.APIKey = "example_api_key"
	cw.SecretKey = "example_api_key"
	cw.StreamURL = DefaultStreamURL
	cw.TradeURL = DefaultTradeURL
	cw.APIURL = DefaultAPIURL

	return cw
}

// String can't be defined on a value receiver here because of the mutex.
func (c *CW) String() string {
	raw, err := yaml.Marshal(c)
	if err != nil {
		return err.Error()
	}

	return string(raw)
}

// DefaultFilepath determines and returns default config path.
// It can return an error if detecting the user's home directory has failed.
func DefaultFilepath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Trace(err)
	}

	return filepath.Join(home, Filepath), nil
}

// Error holds detials about an error occured during validation process.
type Error struct {
	Type string
	What string
	Why  string
	How  string
}

func (e Error) Error() string {
	if e.What == "" {
		return fmt.Sprintf("invalid %s: %s. Possible fix: %s", e.Type, e.Why, e.How)
	}

	return fmt.Sprintf("invalid %s: %s - %s. Possible fix: %s", e.Type, e.What, e.Why, e.How)
}

// ValidateFuncCW takes an instance of CW and returns an error if any occured during validation process.
type ValidateFuncCW func(*CW) error

// CheckURL checks that the url has the correct scheme.
func CheckURL(given string, schemes ...string) error {
	u, err := url.Parse(given)
	if err != nil {
		return errors.Trace(err)
	}

	for _, s := range schemes {
		if u.Scheme == s {
			return nil
		}
	}

	return ErrInvalidScheme
}

// ValidateCWDefault performs validation of the given config by checking all the fields for correctness.
// It does set default values for an url if one wasn't specified.
func ValidateCWDefault(c *CW) error {
	if c.APIKey == "" {
		return ErrEmptyAPIKey
	}

	if c.SecretKey == "" {
		return ErrEmptySecretKey
	}

	if c.APIURL == "" {
		c.APIURL = DefaultAPIURL
	} else {
		if err := CheckURL(c.APIURL, "http", "https"); err != nil {
			return ErrInvalidHTTPURL
		}
	}

	if c.StreamURL == "" {
		c.StreamURL = DefaultStreamURL
	} else {
		if err := CheckURL(c.StreamURL, "ws", "wss"); err != nil {
			return ErrInvalidWSURL
		}
	}

	if c.TradeURL == "" {
		c.TradeURL = DefaultTradeURL
	} else {
		if err := CheckURL(c.TradeURL, "ws", "wss"); err != nil {
			return ErrInvalidWSURL
		}
	}

	return nil
}
