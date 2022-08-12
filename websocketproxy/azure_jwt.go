package websocketproxy

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/open-networks/go-msgraph"
)

type GroupMapping struct {
	sync.RWMutex
	groupMapping   map[string]string
	queriedTenants map[string]time.Time
}

type AzureAdConfig struct {
	clientId                   string
	clientSecret               string
	groupUpdateIntervalMinutes float64
	groupTransformDisable      string
	groupMapping               GroupMapping
}

func (wp *WebsocketProxy) azureInitConfig() AzureAdConfig {

	cfg := AzureAdConfig{}

	// Disable transformation from group id to human readable group name
	cfg.groupTransformDisable = os.Getenv("AZURE_KRAKEND_PLUGIN_GROUP_DISABLE")
	if cfg.groupTransformDisable != "true" {

		cfg.groupMapping.groupMapping = make(map[string]string)
		cfg.groupMapping.queriedTenants = make(map[string]time.Time)

		// Required configuration for connection to azure ad
		cfg.clientId = os.Getenv("AZURE_KRAKEND_PLUGIN_CLIENT_ID")
		cfg.clientSecret = os.Getenv("AZURE_KRAKEND_PLUGIN_CLIENT_SECRET")

		if len(cfg.clientId) == 0 || len(cfg.clientSecret) == 0 {
			wp.logger.Fatal(logPrefix, "Unable to retrieve plugin credentials: AZURE_KRAKEND_PLUGIN_CLIENT_ID or AZURE_KRAKEND_PLUGIN_CLIENT_SECRET missing \n")
		}

		// Define
		cfg.groupUpdateIntervalMinutes = float64(120)
		groupUpdate := os.Getenv("AZURE_KRAKEND_PLUGIN_GROUP_UPDATE_IN_MINUTES")

		if len(groupUpdate) > 0 {
			groupUpdateIntervalMinutes, err := strconv.ParseFloat(groupUpdate, 64)

			if err != nil {
				cfg.groupUpdateIntervalMinutes = 120
				wp.logger.Fatal(logPrefix, "Unable to convert group refresh interval, using default: %v minutes \n", groupUpdateIntervalMinutes)
			}
			cfg.groupUpdateIntervalMinutes = groupUpdateIntervalMinutes
		}
	} else {
		wp.logger.Info(logPrefix, "Group transformation is disabled")
	}

	return cfg
}

func (wp *WebsocketProxy) authHeaders(writer http.ResponseWriter, req *http.Request, claims jwt.MapClaims) error {

	if claims["tid"] != nil {

		rolesValue := ""
		groupsValue := ""

		config, _ := wp.tokenTransConfig.(AzureAdConfig)

		if claims["roles"] != nil {
			for _, role := range claims["roles"].([]interface{}) {
				if rolesValue == "" {
					rolesValue = rolesValue + role.(string)
				} else {
					rolesValue = rolesValue + "," + role.(string)
				}
			}
		}

		if config.groupTransformDisable != "true" {

			config.groupMapping.Lock()
			if val, ok := config.groupMapping.queriedTenants[claims["tid"].(string)]; !ok {
				wp.updateTenantGroups(claims["tid"].(string), config)
			} else {
				if time.Now().Sub(val).Minutes() > config.groupUpdateIntervalMinutes {
					delete(config.groupMapping.queriedTenants, claims["tid"].(string)) // on the next request we will refresh tenant groups
				}
			}
			config.groupMapping.Unlock()

			config.groupMapping.RLock()
			if claims["groups"] != nil {
				for _, g := range claims["groups"].([]interface{}) {
					if val, ok := config.groupMapping.groupMapping[g.(string)]; ok {
						if groupsValue == "" {
							groupsValue = groupsValue + val
						} else {
							groupsValue = groupsValue + "," + val
						}
					}
				}
			}
			config.groupMapping.RUnlock()

		}

		req.Header.Add("x-tenant-id", strings.ReplaceAll(claims["tid"].(string), "-", "_"))

		if groupsValue != "" {
			req.Header.Add("x-auth-user-groups", groupsValue)
		}

		if rolesValue != "" {
			req.Header.Add("x-auth-user-roles", rolesValue)
		}

		var userIdentification string

		if claims["email"] != nil {
			userIdentification = claims["email"].(string)
		} else if claims["verified_primary_email"] != nil {
			userIdentification = claims["verified_primary_email"].(string)
		} else if claims["preferred_username"] != nil {
			userIdentification = claims["preferred_username"].(string)
		} else if claims["oid"] != nil {
			userIdentification = claims["oid"].(string)
		} else {
			userIdentification = "unknown"
		}

		req.Header.Add("from", userIdentification)
	}
	return nil
}

func (wp *WebsocketProxy) updateTenantGroups(tenantId string, config AzureAdConfig) {

	graphClient, err := msgraph.NewGraphClient(tenantId, config.clientId, config.clientSecret)

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: unable to connect to Azure AD (error: %v) tenant: %s \n", err, tenantId)
		return
	}

	groups, err := graphClient.ListGroups()

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: unable to resolve groups (error: %v) for tenant: %s \n", err, tenantId)
		return
	}

	for _, g := range groups {

		config.groupMapping.groupMapping[g.ID] = g.DisplayName
	}

	config.groupMapping.queriedTenants[tenantId] = time.Now()
}
