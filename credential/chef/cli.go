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

	path := fmt.Sprintf("auth/%s/%s/login/%s", mount, data["org"], data["userid"])

	fmt.Printf("auth/chef: calling %s", path)

	secret, err := c.Logical().Write(path, data)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("empty response from credential provider")
	}

	return secret.Auth.ClientToken, nil
}

// CLI Help for Chef Authentication
func (h *CLIHandler) Help() string {
	help := `
The Chef credential provider allows you to authenticate against a Chef Server.
To use it, first configure it through the "config" endpoint, and then
login by specifying username and password. If password is not provided
on the command line, it will be read from stdin.

    Example: vault auth -method=chef server=chef.autonubil.com org=autonubil headers='{"X-Ops-Sign"=>"algorithm=sha1;version=1.1;", "X-Ops-Userid"=>"czeumer", "X-Ops-Timestamp"=>"2016-10-20T16:54:01Z", "X-Ops-Content-Hash"=>"2jmj7l5rSw0yVb/vlWAYkK/YBwk=", "X-Ops-Authorization-1"=>"rzgvCv0yddKs+a9fiZk3KEHJgbpyKgOeY4XLFgF4lTVQpwYoJuGbVKujLVqP", "X-Ops-Authorization-2"=>"FpFee6Te2Uxuc8R7ixP9KWeYxn5w1jQ979JeJLJNVa7ltSj18as1GmYWuYhJ", "X-Ops-Authorization-3"=>"roUR7C/kBRASwlB0yIXvkrcTXtS14xZt4fzwzGGuMTvY4Dcb7KoWX03rRw6J", "X-Ops-Authorization-4"=>"3rYQsj4hHnfawUL/X4w0K3u+dkwHPwO/71oj+nDzH+ZIVC+WWy6XnZVQzRLp", "X-Ops-Authorization-5"=>"gcSI1V0Yi64lij8k4BF+NZF6Ey0ZUEUu3fPHd8VO4okw8eDYd1jAsCnsUiJB", "X-Ops-Authorization-6"=>"/e4/CCkdnzm0eY+JRa4kZDUQkGrSE9BC3a11gxvoNg=="}'

    `

	return strings.TrimSpace(help)
}
