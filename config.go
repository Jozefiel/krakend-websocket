package websocket

import (
	"errors"
	"log"
	"reflect"

	"github.com/luraproject/lura/v2/config"
)

type websocketConfigEndpoints struct {
	address string
	api     string
}

type websocketConfig struct {
	port      string
	endpoints []websocketConfigEndpoints
}

func duplicateInArray(arr []websocketConfigEndpoints) error {
	visited := make(map[string]bool, 0)
	for i := 0; i < len(arr); i++ {
		if visited[arr[i].api] == true {
			return errors.New("Duplicated api")
		} else {
			visited[arr[i].api] = true
		}
	}
	return nil
}

func parse_interface(t interface{}) ([]websocketConfigEndpoints, error) {
	switch reflect.TypeOf(t).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(t)
		endpoints := []websocketConfigEndpoints{}
		for i := 0; i < s.Len(); i++ {
			castedConfig := s.Index(i).Interface().(map[string]interface{})
			endpoint := websocketConfigEndpoints{}

			if value, ok := castedConfig["address"]; ok {
				endpoint.address = value.(string)
			} else {
				return nil, errors.New("Bad endpoint address")
			}

			if value, ok := castedConfig["api"]; ok {
				endpoint.api = value.(string)
			} else {
				return nil, errors.New("Bad endpoint api")
			}

			endpoints = append(endpoints, endpoint)
		}
		err := duplicateInArray(endpoints)
		if err != nil {
			return nil, errors.New("Duplicated endpoints api")
		}
		return endpoints, nil
	}
	return nil, nil
}

func configGetter(extraConfig config.ExtraConfig) interface{} {
	value, ok := extraConfig[Namespace]
	if !ok {
		return nil
	}

	castedConfig, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}

	cfg := websocketConfig{}

	if value, ok := castedConfig["port"]; ok {
		cfg.port = ":" + value.(string)
	}

	if value, ok = castedConfig["websockets"]; ok {
		err := *new(error)
		cfg.endpoints, err = parse_interface(value)
		if err != nil {
			log.Println(err)
			return nil
		}
	}

	return cfg
}

var ErrNoConfig = errors.New("websocket: unable to load custom config")