package chef

import (
	"fmt"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: framework.GenericNameRegex("org") + "/login/" + framework.GenericNameRegex("userid"),
		Fields: map[string]*framework.FieldSchema{
			"key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "user's or node's private key",
			},
			"org": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "chef organization",
			},
			"userid": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "user's or node's name",
			},

			"max_ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: "maximim TTL for token",
			},
			"ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: "default TTL for token",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLogin,
		},
	}
}

func (b *backend) pathLogin(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	fmt.Printf("auth/chef: login called with  %v", data)

	key := data.Get("key").(string)
	org := data.Get("org").(string)
	userid := data.Get("userid").(string)

	fmt.Printf("\n\npahtLogin\n", userid)
	fmt.Printf("\n\nauth/chef: userid %s\n", userid)
	fmt.Printf("auth/chef: org %s\n", org)
	fmt.Printf("auth/chef: key %s\n\n", key)

	b.Login(req, org, userid, key)

	return nil, fmt.Errorf("ups!")
}

func (b *backend) pathLoginRenew(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	if req.Auth == nil {
		return nil, fmt.Errorf("request auth was nil")
	}

	tokenRaw, ok := req.Auth.InternalData["token"]
	if !ok {
		return nil, fmt.Errorf("token created in previous version of Vault cannot be validated properly at renewal time")
	}
	token := tokenRaw.(string)

	var verifyResp *verifyCredentialsResp
	if verifyResponse, resp, err := b.verifyCredentials(req, token); err != nil {
		return nil, err
	} else if resp != nil {
		return resp, nil
	} else {
		verifyResp = verifyResponse
	}
	if !policyutil.EquivalentPolicies(verifyResp.Policies, req.Auth.Policies) {
		return nil, fmt.Errorf("policies do not match")
	}

	config, err := b.Config(req)
	if err != nil {
		return nil, err
	}
	return framework.LeaseExtend(config.TTL, config.MaxTTL, b.System())(req, d)
}

func (b *backend) verifyCredentials(req *logical.Request, token string) (*verifyCredentialsResp, *logical.Response, error) {
	return nil, nil, nil
}

type verifyCredentialsResp struct {
	Policies []string
}
