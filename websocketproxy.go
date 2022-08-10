package websocket

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/pretty66/websocketproxy"
)

const Namespace = "github.com/jozefiel/krakend-websocket"
const logPrefix = "[SERVICE: Websocket]"

// New creates a new metrics producer
func New(ctx context.Context, extraConfig config.ExtraConfig, logger logging.Logger) error {

	logger.Debug(logPrefix, "Parsing websocket config")

	cfg, ok := configGetter(extraConfig).(websocketConfig)
	if !ok {
		return ErrNoConfig
	}

	logger.Debug(logPrefix, cfg)

	for _, element := range cfg.endpoints {
		wp, err := websocketproxy.NewProxy(
			element.address, func(r *http.Request) error {
				return nil
			})
		if err != nil {
			log.Println(err)
		}
		http.HandleFunc(element.api, wp.Proxy)
	}

	// proxy path
	http.HandleFunc("/hello", getHello)
	log.Fatal(http.ListenAndServe(cfg.port, nil))

	return nil
}

func getHello(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got /hello request\n")
	io.WriteString(w, "Hello, HTTP!\n")
}
