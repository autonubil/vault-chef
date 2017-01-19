package chef

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `config`,
		Fields: map[string]*framework.FieldSchema{
			"base_url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "ldap URL to connect to",
			},

			"ttl": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Duration after which authentication will be expired`,
			},
			"max_ttl": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Maximum duration after which authentication will be expired`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRead,
			logical.UpdateOperation: b.pathConfigWrite,
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

/*
 * Construct ConfigEntry struct using stored configuration.
 */
func (b *backend) Config(req *logical.Request) (*ConfigEntry, error) {
	// Schema for ConfigEntry
	fd, err := b.getConfigFieldData()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Field DATA: %+v\n", fd)

	// Create a new ConfigEntry, filling in defaults where appropriate
	result, err := b.newConfigEntry(fd)
	if err != nil {
		return nil, err
	}

	storedConfig, err := req.Storage.Get("config")
	if err != nil {
		return nil, err
	}

	if storedConfig == nil {
		// No user overrides, return default configuration
		return result, nil
	}

	// Deserialize stored configuration.
	// Fields not specified in storedConfig will retain their defaults.
	if err := storedConfig.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return result, nil
}

func (b *backend) pathConfigRead(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	cfg, err := b.Config(req)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: structs.New(cfg).Map(),
	}
	resp.AddWarning("Read access to this endpoint should be controlled via ACLs as it will return the configuration information as-is, including any passwords.")
	return resp, nil
}

/*
 * Creates and initializes a ConfigEntry object with its default values,
 * as specified by the passed schema.
 */
func (b *backend) newConfigEntry(d *framework.FieldData) (*ConfigEntry, error) {
	cfg := new(ConfigEntry)

	url := d.Get("base_url").(string)
	if url != "" {
		cfg.BaseURL = strings.ToLower(url)
	}

	var err error
	ttl := d.Get("ttl").(string)
	if ttl != "" {
		cfg.TTL, err = time.ParseDuration(ttl)
		if err != nil {
			return nil, fmt.Errorf("Invalid 'ttl':%s", err)
		}
	}

	maxTTL := d.Get("max_ttl").(string)
	if ttl != "" {
		cfg.MaxTTL, err = time.ParseDuration(maxTTL)
		if err != nil {
			return nil, fmt.Errorf("Invalid 'max_ttl':%s", err)
		}
	}

	return cfg, nil
}

func (b *backend) pathConfigWrite(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	baseURL := data.Get("base_url").(string)
	if len(baseURL) != 0 {
		_, err := url.Parse(baseURL)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Error parsing given base_url: %s", err)), nil
		}
	}

	var ttl time.Duration
	var err error
	ttlRaw, ok := data.GetOk("ttl")
	if !ok || len(ttlRaw.(string)) == 0 {
		ttl = 0
	} else {
		ttl, err = time.ParseDuration(ttlRaw.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Invalid 'ttl':%s", err)), nil
		}
	}

	var maxTTL time.Duration
	maxTTLRaw, ok := data.GetOk("max_ttl")
	if !ok || len(maxTTLRaw.(string)) == 0 {
		maxTTL = 0
	} else {
		maxTTL, err = time.ParseDuration(maxTTLRaw.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Invalid 'max_ttl':%s", err)), nil
		}
	}

	entry, err := logical.StorageEntryJSON("config", ConfigEntry{
		BaseURL: baseURL,
		TTL:     ttl,
		MaxTTL:  maxTTL,
	})

	if err != nil {
		return nil, err
	}

	if b.Logger().IsDebug() {
		b.Logger().Debug("auth/chef: Writing Config: ", "base_url", baseURL, "ttl", ttl, "maxTtl", maxTTL)
	}

	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return nil, nil
}

type ConfigEntry struct {
	BaseURL string        `json:"base_url" structs:"base_url" mapstructure:"base_url"`
	TTL     time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL  time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
}

/*
 * Returns FieldData describing our ConfigEntry struct schema
 */
func (b *backend) getConfigFieldData() (*framework.FieldData, error) {
	configPath := b.Route("config")

	if configPath == nil {
		return nil, logical.ErrUnsupportedPath
	}

	raw := make(map[string]interface{}, len(configPath.Fields))

	fd := framework.FieldData{
		Raw:    raw,
		Schema: configPath.Fields,
	}

	return &fd, nil
}

const pathConfigHelpSyn = `
Configure the Ched server to connect to, along with its options.
`

const pathConfigHelpDesc = `
This endpoint allows you to configure the Chef server to connect to and its
configuration options.

The Chef URL can use either the "http://" or "https://" schema. 
`
