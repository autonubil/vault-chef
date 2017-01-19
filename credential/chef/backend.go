package chef

import (
	"fmt"

	"github.com/go-chef/chef"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	fmt.Printf("auth/chef: NEW CHEF BACKEND")
	return Backend().Setup(conf)
}

func Backend() *backend {
	fmt.Printf("auth/chef: initializing")
	var b backend
	b.Map = &framework.PolicyMap{
		PathMap: framework.PathMap{
			Name: "org",
		},
		DefaultKey: "default",
	}

	b.Backend = &framework.Backend{
		Help: backendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				framework.GenericNameRegex("org") + "/login/" + framework.GenericNameRegex("userid"),
				"login/*",
			},
		},

		Paths: append([]*framework.Path{
			pathConfig(&b),
			pathLogin(&b),
		}, b.Map.Paths()...),

		AuthRenew: b.pathLoginRenew,
	}

	fmt.Printf("auth/chef:initialized %v \n", b)

	b.Logger().Info("auth/chef:initialized %v \n", b)

	return &b
}

func (b *backend) Login(req *logical.Request, org string, userid string, key string) ([]string, *logical.Response, error) {

	cfg, err := b.Config(req)
	if err != nil {
		return nil, nil, err
	}

	if cfg == nil {
		return nil, logical.ErrorResponse("chef backend not configured"), nil
	}
	baseURL := fmt.Sprintf("%s/organizations/%s/", cfg.BaseURL, org)

	fmt.Printf("\n\nauth/chef: userid %s\n", userid)
	fmt.Printf("auth/chef: org %s\n", org)
	fmt.Printf("auth/chef: key %s\n\n", key)

	fmt.Printf("auth/chef: baseURL %s\n\n", baseURL)

	// build a client
	client, err := chef.NewClient(&chef.Config{
		Name: userid,
		Key:  key,
		// goiardi is on port 4545 by default. chef-zero is 8889
		BaseURL: baseURL,
	})

	if err != nil {
		fmt.Println("Issue setting up client:", err)
	}

	// List Cookbooks
	principal, err := client.Principals.Get(userid)
	if err != nil {
		fmt.Println("Issue listing acls:", err)
	}

	// Print out the list
	fmt.Println(principal)

	chefResponse := &logical.Response{
		Data: map[string]interface{}{},
	}

	// Retrieve policies
	var policies []string

	return policies, chefResponse, nil
}

type backend struct {
	*framework.Backend

	Map *framework.PolicyMap
}

const backendHelp = `
The Chef credential provider allows authentication via Chef Server.


After enabling the credential provider, use the "config" route to
configure it.
`
