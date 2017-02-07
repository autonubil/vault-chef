package chef

import (
	"strings"
    
    "github.com/autonubil/vault/helper/policyutil"
	"github.com/autonubil/vault/logical"
	"github.com/autonubil/vault/logical/framework"
)

func pathGroupsList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "groups/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathGroupsList,
		},

		HelpSynopsis:    pathGroupsHelpSyn,
		HelpDescription: pathGroupsHelpDesc,
	}
}

func pathGroups(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `groups/(?P<group>[^/].+)$`,
		Fields: map[string]*framework.FieldSchema{
			"group": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Chef group to map to an policy.",
			},

			"policies": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Comma-separated list of policies associated to the group.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathGroupsDelete,
			logical.ReadOperation:   b.pathGroupsRead,
			logical.UpdateOperation: b.pathGroupsWrite,
		},

		HelpSynopsis:    pathGroupsHelpSyn,
		HelpDescription: pathGroupsHelpDesc,
	}
}

func (b *backend) Group(s logical.Storage, n string) (*GroupEntry, error) {
    entry, err := s.Get("groups/" + n )

    if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result GroupEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathGroupsDelete(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    
    err := req.Storage.Delete("groups/" + d.Get("group").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathGroupsRead(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path, err := b.Path(req.Storage,d.Get("group").(string))
	if err != nil {
		return nil, err
	}
	if path == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"policies": strings.Join(path.Policies, ","),
		},
	}, nil
}


   


func (b *backend) pathGroupsWrite(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

    group := d.Get("group").(string)
 
	// Store it
	entry, err := logical.StorageEntryJSON("groups/"+group, &GroupEntry{
		Policies: policyutil.ParsePolicies(d.Get("policies").(string)) ,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return nil, nil
}

 

func (b *backend) pathGroupsList(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	paths, err := req.Storage.List("groups/")

	if err != nil {
		return nil, err
	}

    response := logical.ListResponse(paths)
	return response, nil
}

type GroupEntry struct {
	Policies []string
}

const pathGroupsHelpSyn = `
Manage group to policy mappings.
`

const pathGroupsHelpDesc = `
This endpoint allows you to create, read, update, and delete configuration 
for chef groups that are associated to policies.

Deleting a group will not revoke auth for prior authenticated users.
To do this, do a revoke on "login/<username>" for
the usernames you want revoked.
`
