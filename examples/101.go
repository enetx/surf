package main

import (
	"context"
	"fmt"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func main() {
	// url := "matitecnotucserber.uk" // websocket
	// url := "karylamasbuena-912.site" // websocket
	// url := "doblegconnection.cloud" // websocket
	// url := "thegodfatheriam.tech" // websocket
	// url := "vpsvip.tech" // websocket
	// url := "darkielproyect.online" // websocket
	// url := "ismaelmondaque.xyz" // websocket
	url := "dwvps01.xyz" // websocket
	// url := "kevincl.online"
	// url := "jhsfree.xyz"
	// url := "sinnombre.ovh"
	// url := "mlotekvps.xyz"
	// url := "vps-vip.xyz"
	// url := "zeroostore.net"
	// url := "barbosaoliveira.online"
	// url := "cyberzerovip.com"
	// url := "fexzurvps1.site"
	// url := "angelpolio2002.online"
	// url := "jhsvps05.online"
	// url := "ipshield.buzz"
	// url := "conejox.online"

	// url := "conejox.online"
	// url := "giayluoinam.edu.vn"
	// url := "g3net.website" // 101 stream error
	// url := "danielfdyer.xyz"
	// url := "louiejparkinson.xyz"
	// url := "juliogroup.uk" // 101 proxy
	// url := "bompreco.cloud" // 101 websocket

	fmt.Println("start")

	url = "anantha.eu"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	r := surf.NewClient().
		Builder().
		Impersonate().
		Chrome().
		Build().
		Get(g.String(url)).
		WithContext(ctx).
		Do()

	if r.IsErr() {
		fmt.Println(r.Err())
		return
	}

	r.Ok().Debug().Request(true).Response(true).Print()
}
