package policy

import (
	"encoding/json"
	"fmt"

	"github.com/docker/engine-api/types/swarm"
	"github.com/docker/go-connections/nat"
	"github.com/docker/go-plugins-helpers/authorization"
)

// ServiceCreate called from plugin
func ServiceCreate(req authorization.Request, config *Config) *Result {
	svc := &swarm.Service{}

	b := []byte(req.RequestBody)
	err := json.Unmarshal(b, svc)
	if err != nil {
		return &Result{Allow: false, Error: err.Error()}
	}

	acl := GetACL(config.Username)

	if svc.Spec.EndpointSpec != nil {
		if len(svc.Spec.EndpointSpec.Ports) > 0 {
			for _, port := range svc.Spec.EndpointSpec.Ports {
				pb := nat.PortBinding{HostIP: "", HostPort: string(port.PublishedPort)}
				if !ValidateHostPort(acl, pb) {
					return &Result{Allow: false, Msg: fmt.Sprintf("Port %s is not allowed to be pubished", port.PublishedPort)}
				}
			}
		}
	}

	if len(svc.Spec.TaskTemplate.ContainerSpec.Mounts) > 0 {
		for _, mount := range svc.Spec.TaskTemplate.ContainerSpec.Mounts {
			if mount.Type == "bind" {
				if len(mount.Source) > 0 {
					return &Result{Allow: false, Msg: fmt.Sprintf("Volume %s is not allowed to be mounted", mount.Source)}
				}
			}
		}
	}

	if len(svc.Spec.TaskTemplate.ContainerSpec.User) > 0 {
		if svc.Spec.TaskTemplate.ContainerSpec.User == "root" && ValidateFlag(acl, "container_disallow_root_user") {
			return &Result{Allow: false, Msg: "Running as user \"root\" is not allowed. Please use --user=\"someuser\" param."}
		}
	}

	return &Result{Allow: true}
}
