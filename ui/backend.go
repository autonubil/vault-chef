package ui

import (
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	fmt.Printf("ui: NEW UI BACKEND")
	return Backend().Setup(conf)
}

func Backend() *backend {
	fmt.Printf("ui: initializing")
	var b backend

	b.Backend = &framework.Backend{
		Help: backendHelp,

		Paths: append([]*framework.Path{
			pathStatic(&b),
		}, b.Map.Paths()...),
	}

	fmt.Printf("ui:initialized %v \n", b)

	b.Logger().Info("ui:initialized %v \n", b)

	return &b
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
Simple build in UI .

After enabling the backend you can navigate to it /v1/<mount-point>.
`
