package chef

import (
	"fmt"
	"strings"
	"sort"
	"time"

	"github.com/autonubil/vault/helper/policyutil"
	"github.com/autonubil/vault/logical"
	"github.com/autonubil/vault/logical/framework"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login/" +framework.GenericNameRegex("org") +  "/" + framework.GenericNameRegex("userid"),
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

		HelpSynopsis:    pathLoginSyn,
		HelpDescription: pathLoginDesc,
	}
}

func (b *backend) pathLogin(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	fmt.Printf("auth/chef: login called\n")

	key := data.Get("key").(string)
	org := data.Get("org").(string)
	userid := data.Get("userid").(string)

	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
 
	policies, resp, login_err := b.Login(req, org, userid, key)

	if len(policies) == 0 {
		return resp, login_err
	}

	if (login_err != nil) {
		return nil, login_err
	}

	sort.Strings(policies)



	// Generate a response
	resp.Auth = &logical.Auth{
		Policies:    policies,
		Metadata: map[string]string{
			"org": 		org,
			"userid":   userid,
			"policies": strings.Join(policies, ","),
		},
		InternalData: map[string]interface{}{
			"userid":   userid,
			"org": 		org,
			"key" : 	key,
		},
		DisplayName: userid,
		LeaseOptions: logical.LeaseOptions{ 
			Renewable: true,
			TTL : ttl,
		},
	}

 
	fmt.Printf("auth/chef: policies ->  %v\n", policies)

	return resp, nil
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

const pathLoginSyn = `
Log in as user or node of an organization with an private key.
`

const pathLoginDesc = `
This endpoint authenticates against a chef server using a private key as user or node .
`
