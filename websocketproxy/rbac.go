package websocketproxy

import (
	"errors"
	"net/http"
	"strings"
)

type RbacConfig struct {
	rbacRoles string
}

func (wp *WebsocketProxy) checkRbacPermissions(writer http.ResponseWriter, request *http.Request) error {

	var user_rbac []string
	var api_rbac []string

	user_groups, ok := request.Header["X-Auth-User-Groups"]
	if ok {
		user_rbac = strings.Split(strings.ToLower(strings.Join(user_groups, " ")), ",")
	}

	user_roles, ok := request.Header["X-Auth-User-Roles"]
	if ok {
		user_rbac = strings.Split(strings.ToLower(strings.Join(user_roles, " ")), ",")
	}

	api_rbac = strings.Split(strings.ToLower(strings.ReplaceAll(wp.rbac.rbacRoles, " ", "")), ",")

	for _, api := range api_rbac {
		for _, user := range user_rbac {
			if api == user {
				return nil
			}
		}
	}
	writer.WriteHeader(http.StatusForbidden)
	writer.Write([]byte("User has no permissions for that operation"))
	return errors.New("User has no permissions for that operation")
}
