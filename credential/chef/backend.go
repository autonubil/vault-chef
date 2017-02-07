package chef

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/autonubil/chef"

	"github.com/autonubil/vault/helper/strutil"
	"github.com/autonubil/vault/logical"
	"github.com/autonubil/vault/logical/framework"
)

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	fmt.Printf("auth/chef: NEW CHEF BACKEND\n")
	return Backend().Setup(conf)
}

func Backend() *backend {
	fmt.Printf("auth/chef: initializing\n")
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
				"login/*",
			},
		},

		Paths: append([]*framework.Path{
			pathConfig(&b),
			pathLogin(&b),
			pathPathes(&b),
			pathPathesList(&b),
			pathRoles(&b),
			pathRolesList(&b),
			pathGroups(&b),
			pathGroupsList(&b),

		}, b.Map.Paths()...),

		AuthRenew: b.pathLoginRenew,
	}

	fmt.Printf("auth/chef:initialized %v \n", b)

	b.Logger().Info("auth/chef:initialized %v \n", b)

	return &b
}

func (b *backend)  isInGroups(groupname string, cached_groups map[string]chef.Group, client *chef.Client ) (contained bool, err error) {
	if _, ok := cached_groups[groupname]; !ok {
		new_group, err := client.Groups.Get(groupname)
		if err != nil {
			fmt.Println("Issue reading group", err)
			return false , err
		} else {
			cached_groups[groupname] = new_group
		}
	}

	if _, ok := cached_groups[groupname]; ok {
		return true, nil
	}

	return false, nil
}


func (b *backend)  isInAclGroups(user string, acl *chef.ACL, cached_groups map[string]chef.Group, client *chef.Client ) (permissions []string, err error) {
	// first run 
	for aclType, aCLitems := range *acl {
		aclApplies := false
		for _, actor := range aCLitems.Actors {
		//	fmt.Printf("auth/chef: check of '%s' for %s (%s)\n", aclType, user, actor)
			if (actor == user){
				permissions = append(permissions, aclType)
				aclApplies=true
				// fmt.Printf("auth/chef: MATCH of '%s' for %s (%s) in direct ACl\n", aclType, user, actor)
				break
			}
		}

		// group applies?
		if (!aclApplies) {
			// any group in ACLs that is not yet loaded?
			for _, groupname := range aCLitems.Groups {

				if _, ok := cached_groups[groupname]; !ok {
					new_group, err := client.Groups.Get(groupname)
					if err != nil {
						fmt.Println("Issue reading group", err)
						return nil , err
					} else {
						cached_groups[groupname] = new_group
					}
				 }

				 if chefGroup, ok := cached_groups[groupname]; ok {
					
					for _,actor := range chefGroup.Actors {
						if (actor == user){
							permissions = append(permissions, aclType)
							aclApplies=true
							break
						}
					}
				}
			}
		}

	}


	return strutil.RemoveDuplicates(permissions), nil
}

func (b *backend) getPathPolicies(username, org string, storage logical.Storage, chefClient *chef.Client, cached_groups map[string]chef.Group )  (policies []string, err error ) {

	// iterate of all mapped pathes
	paths, err := storage.List("pathes/")

	if (err != nil) {
		return nil, err
	}

	if ( len(paths) == 0) {	
		return policies, nil
	} else {
		for _, path := range paths {
			var permissions []string
			elements := strings.Split(path, "\\")
			has_permissions := false
			if ( len(elements) == 1  && elements[0] == org) {
				// members of the org can read the org... 
				permissions = append(permissions, "read")
			} else if (len(elements) > 2 && elements[0] == org){
				// orgs match, get acl
				acl, err := chefClient.ACLs.Get(elements[1], elements[2])
				if err != nil {
					fmt.Printf("Problem getting acl for path %s (does ist even exist?):\n", path)
					has_permissions = false
				}  else {
					
					permissions, err = b.isInAclGroups(username, &acl,  cached_groups, chefClient)
					if err != nil {
						fmt.Printf("Problem getting acl for path %s:\n", path)
						has_permissions = false
					}  else {
						has_permissions = (len(permissions) >0)
					}
				}
			}
			if (has_permissions) {
				
				path_config, err := b.Path(storage, path)
				if err != nil {
					fmt.Printf("Problem getting config for path %s:\n", path)
					continue
				} 

				if (path_config != nil){
					for _, present := range permissions {
						for _, required := range path_config.Constraint {
							if (present == required) {
								for _,policy := range path_config.Policies {
									fmt.Printf("auth/chef: Appending policy  %s from path\n", policy)
									policies = append(policies, policy )
								}
								// break
							}
						}
					}
				}
				// break;
			}
		}
	}

	return strutil.RemoveDuplicates(policies), nil
}


func (b *backend) getGroupPolicies(storage logical.Storage, chefClient *chef.Client, cached_groups map[string]chef.Group )  (policies []string, err error ) {
// iterate of all mapped groups
	groups, err := storage.List("groups/")

	if (err != nil) {
		return nil, err
	}

	if ( len(groups) == 0) {	
		return policies, nil
	} else {
		for _, groupname := range groups {
			var has_permissions bool
		
			// orgs match, get acl
			has_permissions, err = b.isInGroups(groupname,  cached_groups, chefClient)
			if err != nil {
				fmt.Printf("Problem getting group membership %s: (does it actually exist?)\n", groupname)
				continue
			}

//			fmt.Printf("auth/chef: grup permissions %v from path %s (%v)\n", has_permissions, groupname, cached_groups)

			if (has_permissions) {
				
				group_config, err := b.Group(storage, groupname)
				if err != nil {
					fmt.Printf("Problem getting config for path %s:\n", groupname)
					continue
				} 

				//fmt.Printf("auth/chef: group_config %v from path %s \n", group_config, groupname)
				
				if (group_config != nil)  {
					for _,policy := range group_config.Policies {
						fmt.Printf("auth/chef: Appending policy  %s from group %s\n", policy, groupname)
						policies = append(policies, policy )
					}
				}
				
			// break;
			}
		}
	}

	return strutil.RemoveDuplicates(policies), nil
}


func (b *backend) getRolesFromRunList(runlist []string) (roles []string) {
	var runlist_pattern = regexp.MustCompile(`role\[(?P<role>.*?)\]`)
	for _, run_item := range runlist {
		 match := runlist_pattern.FindStringSubmatch(run_item)
		 if (len(match) > 1) {
			roles = append(roles, match[1])
		 } 
	}

	return roles
}

func (b *backend) getContainedRolesList(rolename string, storage logical.Storage, chefClient *chef.Client,  cached_roles map[string][]string, recurse bool )  (roles []string, err error ) {
	// not yet in cache?
	if _,ok := cached_roles[rolename]; !ok {
		role, err :=  chefClient.Roles.Get(rolename)
		if (err != nil) {
			return nil, err
		}
		sub_roles := b.getRolesFromRunList(role.RunList)
		cached_roles[rolename] = sub_roles
	}

	if sub_roles,ok := cached_roles[rolename]; ok {
		for _, role := range sub_roles {
			roles = append(roles, role)
			if (recurse) {
				expanded_sub_rols, err := b.getContainedRolesList(role, storage, chefClient, cached_roles, true)
				if (err != nil) {
					return nil, err
				}
				for _, expanded_sub_role := range expanded_sub_rols {
					roles = append(roles, expanded_sub_role)
				}
			
			}

		}
	}

	return roles, nil
}

func (b *backend) getExpandedRoleList(nodename string, storage logical.Storage, chefClient *chef.Client) (roles []string, err error ) {
	cached_roles := make(map[string][]string)


	node, err := chefClient.Nodes.Get(nodename)
	if (err != nil) {
		return nil, err
	}

	
	for _, role := range   b.getRolesFromRunList(node.RunList) {
		roles = append(roles, role)
		sub_roles, err := b.getContainedRolesList(role, storage, chefClient, cached_roles, true)
		if (err != nil) {
			return nil, err
		}
		for _, sub_role := range  sub_roles {
			roles = append(roles, sub_role)
		}
		
	}
	
	return roles, nil
}



func (b *backend) getRolePolicies(nodename string, storage logical.Storage, chefClient *chef.Client )  (policies []string, err error ) {

	// iterate of all mapped pathes
	rolemappings, err := storage.List("roles/")
	if (err != nil) {
		return nil, err
	}

	all_roles , err :=  b.getExpandedRoleList(nodename, storage, chefClient)
	if (err != nil) {
		return nil, err
	}

	all_roles = strutil.RemoveDuplicates(all_roles) 

	// now check the overlapp
	for _, rolemapping := range rolemappings {
		for _, test_role := range  all_roles {
			if (test_role == rolemapping) {
				// we have a hit! 
				role_config, err := b.Role(storage, rolemapping)
				if err != nil {
					fmt.Printf("Problem getting config for role %s:\n", rolemapping)
					continue
				} 
				for _,policy := range role_config.Policies {
						fmt.Printf("auth/chef: Appending policy  %s from role\n", policy)
						policies = append(policies, policy )
				}

				fmt.Printf("auth/chef: MATCH: %s  %v\n", rolemapping, role_config)
			}
		}

	}
 
	return strutil.RemoveDuplicates(policies), nil
}


func (b *backend) Login(req *logical.Request, org string, userid string, key string) ([]string, *logical.Response, error) {

	cfg, err := b.Config(req)
	if err != nil {
		return nil, nil, err
	}

	if cfg == nil {
		return nil, logical.ErrorResponse("chef backend not configured"), nil
	}


	chefResponse := &logical.Response{
		Data: map[string]interface{}{},
	}



	baseURL := fmt.Sprintf("%s/organizations/%s/", cfg.BaseURL, org)

	fmt.Printf("auth/chef: baseURL %s\n\n", baseURL)
	fmt.Printf("auth/chef: userid %s\n", userid)
	fmt.Printf("auth/chef: org %s\n", org)
	// fmt.Printf("auth/chef: key %s\n\n", key)
 

	// build a client
	client, err := chef.NewClient(&chef.Config{
		Name: userid,
		Key:  key,
		BaseURL: baseURL,
	})
	if err != nil {
		fmt.Println("Issue setting up client:", err)
	}

	// get Principal
	principal, err := client.Principals.Get(userid)
	if err != nil {
		fmt.Println("Issue getting principal:", err)
	}
	fmt.Printf("auth/chef: principal %s [%s]\n",principal.Name, principal.Type)

	var isAdmin = false;

	if (principal.Type ==  "client")  {
		fmt.Printf("auth/chef: userid %s\n", userid)
		apiClient, err := client.Clients.Get(userid)
		if err != nil {
			errStr := fmt.Sprintf("Failed to login: %s", err)
			if len(chefResponse.Warnings()) > 0 {
				errStr = fmt.Sprintf("%s; additionally, %s", errStr, chefResponse.Warnings()[0])
			}
			chefResponse.Data["error"] = errStr
			return nil, chefResponse, nil
		}

		isAdmin = apiClient.Admin
	}


	cached_groups := make(map[string]chef.Group)


	// if the user has no admin rights, use the configured admin 
	var adminClient *chef.Client;
	if (!isAdmin) {
		fmt.Printf("auth/chef: Using %s as ADMIN user\n", cfg.AdminUser)
		adminClient, err = chef.NewClient(&chef.Config{
			Name: cfg.AdminUser,
			Key:  cfg.AdminKey,
			BaseURL: baseURL,
		})

		if err != nil {
			errStr := fmt.Sprintf("Failed to login as admin user: %s", err)
			if len(chefResponse.Warnings()) > 0 {
				errStr = fmt.Sprintf("%s; additionally, %s", errStr, chefResponse.Warnings()[0])
			}
			chefResponse.Data["error"] = errStr
			return nil, chefResponse, nil
		}
	} else {
		adminClient = client;
	}


	if (adminClient == nil) {
		errStr := fmt.Sprintf("No admin user specified - cannnot query policiy mappings")
		if len(chefResponse.Warnings()) > 0 {
			errStr = fmt.Sprintf("%s; additionally, %s", errStr, chefResponse.Warnings()[0])
		}

		chefResponse.Data["error"] = errStr
		return nil, chefResponse, nil
	}

	// Retrieve policies
	var policies []string


	// lookup policy mappings
	if ( principal.Type ==  "user" || principal.Type ==  "client" )  {
		path_policies, err := b.getPathPolicies(principal.Name, org, req.Storage, adminClient, cached_groups)
		if err != nil {
			fmt.Println("Issue getting path policies:", err)
			return nil, chefResponse, err
		}

		for _, path_policy := range path_policies {
			policies = append(policies, path_policy)
		}

		// users may have groups
		if ( principal.Type ==  "user" )  {
			role_policies, err := b.getGroupPolicies(req.Storage, adminClient, cached_groups)
			if err != nil {
				fmt.Println("Issue getting role policies:", err)
				return nil, chefResponse, err
			}

			for _, path_policy := range role_policies {
				policies = append(policies, path_policy)
			}

		}


		// clients may have roles
		if ( principal.Type ==  "client" )  {
			role_policies, err := b.getRolePolicies(principal.Name, req.Storage, adminClient)
			if err != nil {
				fmt.Println("Issue getting role policies:", err)
				return nil, chefResponse, err
			}

			for _, path_policy := range role_policies {
				policies = append(policies, path_policy)
			}

		}
 	
	}

	// must be member of the org
	if (!principal.OrgMember) {
		errStr := fmt.Sprintf("%s is not a member of the organization", principal.Type)
		if len(chefResponse.Warnings()) > 0 {
			errStr = fmt.Sprintf("%s; additionally, %s", errStr, chefResponse.Warnings()[0])
		}

		chefResponse.Data["error"] = errStr
		return nil, chefResponse, nil
	}



	chefResponse.Data["name"] = principal.Name
	chefResponse.Data["type"] = principal.Type
	chefResponse.Data["publicKey"] = principal.PublicKey
	chefResponse.Data["authz_id"] = principal.AuthzId
	chefResponse.Data["org_member"] = principal.OrgMember

	// fmt.Printf("auth/chef: data %v\n", chefResponse.Data)


	policies = append (policies, "default")

	// Policies from each group may overlap
	policies = strutil.RemoveDuplicates(policies)

	if len(policies) == 0 {
		errStr := fmt.Sprintf("%s is not a member of anypolicy mapping ", principal.Type)
		if len(chefResponse.Warnings()) > 0 {
			errStr = fmt.Sprintf("%s; additionally, %s", errStr, chefResponse.Warnings()[0])
		}

		chefResponse.Data["error"] = errStr
		return nil, chefResponse, nil
	}

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
