package chef

import (
	"strings"
    
    "github.com/autonubil/vault/helper/policyutil"
	"github.com/autonubil/vault/logical"
	"github.com/autonubil/vault/logical/framework"
)

func pathRolesList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRolesList,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `roles/(?P<role>[^/].+)$`,
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Chef role to map to an policy.",
			},

			"policies": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Comma-separated list of policies associated to the role.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathRolesDelete,
			logical.ReadOperation:   b.pathRolesRead,
			logical.UpdateOperation: b.pathRolesWrite,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) Role(s logical.Storage, n string) (*RoleEntry, error) {
    entry, err := s.Get("roles/" + n )

    if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result RoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathRolesDelete(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    
    err := req.Storage.Delete("roles/" + d.Get("role").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRolesRead(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path, err := b.Path(req.Storage,d.Get("role").(string))
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


   


func (b *backend) pathRolesWrite(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

    role := d.Get("role").(string)
 
	// Store it
	entry, err := logical.StorageEntryJSON("roles/"+role, &RoleEntry{
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

 

func (b *backend) pathRolesList(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	paths, err := req.Storage.List("roles/")

	if err != nil {
		return nil, err
	}

    response := logical.ListResponse(paths)
	return response, nil
}

type RoleEntry struct {
	Policies []string
}

const pathRolesHelpSyn = `
Manage role to policy mappings.
`

const pathRolesHelpDesc = `
This endpoint allows you to create, read, update, and delete configuration 
for chef roles that are associated policies to them.

Deleting a role will not revoke auth for prior authenticated users.
To do this, do a revoke on "login/<username>" for
the usernames you want revoked.
`
