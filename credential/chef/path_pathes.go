package chef

import (
    "fmt"
	"strings"
    
    "github.com/autonubil/vault/helper/strutil"
    "github.com/autonubil/vault/helper/policyutil"
	"github.com/autonubil/vault/logical"
	"github.com/autonubil/vault/logical/framework"
)

func pathPathesList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "pathes/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathPathesList,
		},

		HelpSynopsis:    pathPathesHelpSyn,
		HelpDescription: pathPathesHelpDesc,
	}
}

func pathPathes(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `pathes/(?P<path>.+)$`,
		Fields: map[string]*framework.FieldSchema{
			"path": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Chef path to map to an policy.",
			},

			"policies": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Comma-separated list of policies associated to the path.",
			},

            "constraint": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Comma-separated list of required access rights to the path.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathPathesDelete,
			logical.ReadOperation:   b.pathPathesRead,
			logical.UpdateOperation: b.pathPathesWrite,
		},

		HelpSynopsis:    pathPathesHelpSyn,
		HelpDescription: pathPathesHelpDesc,
	}
}

func (b *backend) Path(s logical.Storage, n string) (*PathEntry, error) {
    entry, err := s.Get("pathes/" + strings.Replace(n, "/", "\\", -1) )

    if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result PathEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathPathesDelete(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    path_translated := strings.Replace(d.Get("path").(string), "/", "\\", -1)

    err := req.Storage.Delete("pathes/" + path_translated)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathPathesRead(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    path_translated := strings.Replace(d.Get("path").(string), "/", "\\", -1)
	path, err := b.Path(req.Storage,path_translated)
	if err != nil {
		return nil, err
	}
	if path == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"policies": strings.Join(path.Policies, ","),
            "constraint": strings.Join(path.Constraint, ","),
		},
	}, nil
}


 
func ParseConstraint(constraintRaw string) []string {
	if constraintRaw == "" {
		return []string{"read"}
	}

	constraints := strings.Split(constraintRaw, ",")

	return SanitizeConstraint(constraints, true)
}


func SanitizeConstraint(constraints []string, addDefault bool) []string {
	var result []string
	for _, p := range constraints {
        test := strings.ToLower(strings.TrimSpace(p))
        
        // there is no write, it is update ;)
		if (test == "write") {
            test = "update"
        }
        // Eliminate unnamed / unknown policies.
        if test == "" || (!(test== "read" || test == "update" ||   test == "create" || test == "delete" || test == "grant") ) {
			continue
		}
 
        result = append(result, test)
		 
	}

	// Always add 'default' except only if the policies contain 'root'.
	if addDefault && (len(result) == 0  ) {
		result = append(result, "read")
	}

	return strutil.RemoveDuplicates(result, false)
}



func (b *backend) pathPathesWrite(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

    path_translated := strings.Replace(d.Get("path").(string), "/", "\\", -1)

    num_element :=  len(strings.Split(path_translated, "\\"))

    if (num_element < 1 ) {
		return nil, fmt.Errorf("Path must start with an organization as first element")
    }

    if (num_element != 1 &&  num_element > 3 ) {
		return nil, fmt.Errorf("Path be in form organization/type/object")
    }

 

	// Store it
	entry, err := logical.StorageEntryJSON("pathes/"+path_translated, &PathEntry{
		Policies: policyutil.ParsePolicies(d.Get("policies").(string)),
        Constraint: ParseConstraint(d.Get("constraint").(string)),
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return nil, nil
}


// ListResponse is used to format a response to a list operation.
func ListTranslatedResponse(keys []string) *logical.Response {
	resp := &logical.Response{
		Data: map[string]interface{}{},
	}
	if len(keys) != 0 {
        var translated_keys []string 
        for _, key := range keys {
            translated_keys = append(translated_keys,strings.Replace(key, "\\", "/", -1))
        }
		resp.Data["keys"] = translated_keys
	}
	return resp
}



func (b *backend) pathPathesList(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	paths, err := req.Storage.List("pathes/")

	if err != nil {
		return nil, err
	}

    response := ListTranslatedResponse(paths)
	return response, nil
}

type PathEntry struct {
	Policies []string
    Constraint []string
}

const pathPathesHelpSyn = `
Manage users and nodes allowed to authenticate.
`

const pathPathesHelpDesc = `
This endpoint allows you to create, read, update, and delete configuration 
for chef objects that have associated policies to them.

Deleting a path will not revoke auth for prior authenticated users.
To do this, do a revoke on "login/<username>" for
the usernames you want revoked.
`
