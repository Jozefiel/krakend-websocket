package websocket

import (
	"context"
	"io"
	"log"
	"net/http"

	// jose "github.com/devopsfaith/krakend-jose/v2"

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

	mux := http.NewServeMux()

	for _, element := range cfg.endpoints {
		wp, err := websocketproxy.NewProxy(
			element.address, element.jwk_url, element.aud, element.token_prefix, element.rbac_roles, func(r *http.Request) error {
				return nil
			})
		if err != nil {
			log.Println(err)
		}
		mux.HandleFunc(element.api, wp.Proxy)
	}

	http.HandleFunc("/health", getHello)

	go func() {
		log.Fatal(http.ListenAndServe(cfg.port, mux))
	}()

	logger.Debug(logPrefix, "Service up and running")
	return nil
}

func getHello(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "OK\n")
}
