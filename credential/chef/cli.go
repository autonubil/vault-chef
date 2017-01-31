package chef

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/autonubil/vault/api"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (string, error) {
	var data map[string]interface{}
	var userid string
	var keyParam string
	var org string
	var mount string
	var ok bool

	// parameters with defaults
	mount, ok = m["mount"]
	if !ok {
		mount = "chef"
	}

	//mandatory parameters
	keyParam, ok = m["key"]
	if !ok {
		input, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		keyParam = string(input)
	}

	block, _ := pem.Decode([]byte(keyParam))
	_, parserErr := x509.ParsePKCS1PrivateKey(block.Bytes)

	if parserErr != nil {
		return "", fmt.Errorf("Failed to parse private key: " + parserErr.Error())
	}

	data = make(map[string]interface{})

	userid, ok = m["userid"]
	if !ok {
		return "", fmt.Errorf("'userid' parameter is missing")
	}
	data["userid"] = userid

	org, ok = m["org"]
	if !ok {
		return "", fmt.Errorf("'org' parameter is missing")
	}
	data["org"] = org

	data["key"] = keyParam

	path := fmt.Sprintf("auth/%s/login/%s/%s", mount, data["org"], data["userid"])

	fmt.Printf("auth/chef: calling %s\n", path)

	secret, err := c.Logical().Write(path, data)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("empty response from credential provider")
	}

	if secret.Auth == nil {
		return "", fmt.Errorf("empty response without authentication information from credential provider")
	}

	return  secret.Auth.ClientToken, nil
}

// CLI Help for Chef Authentication
func (h *CLIHandler) Help() string {
	help := `
The Chef credential provider allows you to authenticate against a Chef Server.
To use it, first configure it through the "config" endpoint, and then
login by specifying username and password. If password is not provided
on the command line, it will be read from stdin.

    Example: vault auth -method=chef org=autonubil userid=user key={private key data in pem format}'

    `

	return strings.TrimSpace(help)
}


/*
chef-server-ctl user-create application-vault Vault Application vault@autonubil.de "*****************"
# remember the app-key
 chef-server-ctl grant-server-admin-permissions application-vault

vault write  /auth/chef/config base_url="https://chef.access.autonubil.local" admin_user="application-vault" admin_key=@/home/czeumer/chef-repo/autonubil/.chef/application-vault.pem


*/

