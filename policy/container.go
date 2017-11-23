package policy

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/CMartinUdden/dpe/utils"
	//	log "github.com/Sirupsen/logrus"
	"github.com/docker/engine-api/types/container"
	"github.com/docker/go-plugins-helpers/authorization"
)

type volumeOptions struct {
	Recursive bool
	NoSuid    bool
}

type containerCreateConfig struct {
	container.Config
	HostConfig container.HostConfig
}

// ContainerCreate called from plugin
func ContainerCreate(req authorization.Request, config *Config) *Result {
	acl := GetACL(config.Username)

	failmsg := "%s Using %s for user \"" + config.Username + "\" from ACL entry " + acl.String()

	cc := &containerCreateConfig{}

	b := []byte(req.RequestBody)
	err := json.Unmarshal(b, cc)

	if err != nil {
		return &Result{Allow: false, Error: err.Error()}
	}

	for _, fi := range []interface{}{validateFlags, validateDevs, validateCaps, validateBinds, validateHostPorts} {
		r := utils.Vcall(fi, []interface{}{cc, acl, failmsg})[0].Interface().(*Result)
		if !r.Allow {
			return r
		}
	}

	return &Result{Allow: true}
}

func validateDevs(cc *containerCreateConfig, acl *ACL, failmsg string) *Result {
	if len(cc.HostConfig.Devices) > 0 {
		for _, dev := range cc.HostConfig.Devices {
			if !ValidateDev(acl, dev.PathOnHost) {
				msg := fmt.Sprintf(failmsg, dev.PathOnHost+" (--device=\""+dev.PathOnHost+"\" run parameter) is not allowed.", "devs")
				return &Result{Allow: false, Msg: msg}
			}
		}
	}

	return &Result{Allow: true}
}

func validateHostPorts(cc *containerCreateConfig, acl *ACL, failmsg string) *Result {
	if len(cc.HostConfig.PortBindings) > 0 {
		for containerport, pbs := range cc.HostConfig.PortBindings {
			for _, pb := range pbs {
				if !ValidateHostPort(acl, pb) {
					s := ""
					if pb.HostIP != "" {
						s = pb.HostIP + ":"
					}
					s += pb.HostPort + ":" + string(containerport)
					re, _ := regexp.Compile("/.*")
					sc := re.ReplaceAllString(s, "")
					pmsg := fmt.Sprintf("Host port publication %s (--publish=%s, -p %s run parameter) is not allowed.", s, sc, sc)
					msg := fmt.Sprintf(failmsg, pmsg, "portbindings")
					return &Result{Allow: false, Msg: msg}
				}
			}
		}
	}

	return &Result{Allow: true}
}

func validateBinds(cc *containerCreateConfig, acl *ACL, failmsg string) *Result {
	if len(cc.HostConfig.Binds) > 0 {
		for _, b := range cc.HostConfig.Binds {
			if !ValidateBind(acl, b) {
				msg := fmt.Sprintf(failmsg, "Host bind "+b+" (-v "+b+" run parameter) is not allowed.", "binds")
				return &Result{Allow: false, Msg: msg}
			}
		}
	}

	return &Result{Allow: true}
}

func validateCaps(cc *containerCreateConfig, acl *ACL, failmsg string) *Result {
	if len(cc.HostConfig.CapAdd) > 0 {
		for _, c := range cc.HostConfig.CapAdd {
			if !ValidateCap(acl, c) {
				msg := fmt.Sprintf(failmsg, c+" (--cap-add=\""+c+"\" run parameter) is not allowed.", "caps")
				return &Result{Allow: false, Msg: msg}
			}
		}
	}
	return &Result{Allow: true}
}

func validateFlags(cc *containerCreateConfig, acl *ACL, failmsg string) *Result {
	type flagt struct {
		p    bool
		name string
		fmsg string
	}

	flags := []flagt{
		flagt{p: cc.HostConfig.Privileged, name: "container_create_privileged", fmsg: "(--privileged run parameter) is not allowed."},
		flagt{p: cc.HostConfig.IpcMode == "host", name: "container_create_ipc_host", fmsg: "(--ipc=\"host\" run parameter) is not allowed."},
		flagt{p: cc.HostConfig.NetworkMode == "host", name: "container_create_net_host", fmsg: "(--net=\"host\" run parameter) is not allowed."},
		flagt{p: cc.HostConfig.PidMode == "host", name: "container_create_pid_host", fmsg: "(--pid=\"host\" run parameter) is not allowed."},
		flagt{p: cc.HostConfig.UsernsMode == "host", name: "container_create_userns_host", fmsg: "(--userns=\"host\" run parameter) is not allowed."},
		flagt{p: cc.HostConfig.UTSMode == "host", name: "container_create_uts_host", fmsg: "(--uts=\"host\" run parameter) is not allowed."},
		flagt{p: cc.HostConfig.PublishAllPorts, name: "container_publish_all", fmsg: "(--publish-all run parameter) is not allowed"}}
	for _, flag := range flags {
		if flag.p {
			if !ValidateFlag(acl, flag.name) {
				msg := fmt.Sprintf(failmsg, flag.name+" "+flag.fmsg, "flags")
				return &Result{Allow: false, Msg: msg}
			}
		}
	}

	return &Result{Allow: true}
}
