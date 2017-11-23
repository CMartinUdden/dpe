package policy

import (
	"fmt"
	"github.com/CMartinUdden/dpe/utils"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-connections/nat"
	"github.com/docker/go-plugins-helpers/authorization"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	// DebugACL Debug the ACL subsystem
	DebugACL bool
	// Directory the policy directory
	Directory string
)

// Config appconfig structure
type Config struct {
	AppPath  string
	Username string
}

// Result the result structure
type Result struct {
	Allow bool
	Msg   string
	Error string
}

// True always true
func True(req authorization.Request, config *Config) *Result {
	return &Result{Allow: true}
}

// SupportedFile check whether path is a supported configuration file
func SupportedFile(path string) bool {
	ext := filepath.Ext(path)
	return utils.StringInSlice(ext, supportedSuffixes)
}

// Init initializes the policy engine
func Init() error {
	if DebugACL {
		log.SetLevel(log.DebugLevel)
	}

	theconfig = &config{}

	if _, err := os.Stat(Directory); err != nil {
		return err
	}

	// Traverse the policy dir ...
	err := filepath.Walk(Directory, wf)
	if err != nil {
		return err
	}

	// When all configuration is merged into the groups structure
	// we calculate the user indexed ACL

	calculateacl()

	return nil
}

// GetACL gets a specific ACL
func GetACL(user string) *ACL {
	user = getUser(user)

	if user == "*" {
		if _, ok := acl[user]; !ok {
			return &ACL{Name: user}
		}
	}
	return acl[user]
}

func getUser(u string) string {
	if _, ok := acl[u]; !ok {
		return "*"
	}
	return u
}

// ValidateDev policy
func ValidateDev(u *ACL, dev string) bool {
	return utils.StringsInSlice([]string{dev, "*"}, u.Devs)
}

// ValidateCap policy
func ValidateCap(u *ACL, cap string) bool {
	return utils.StringsInSlice([]string{cap, "*"}, u.Caps)
}

// ValidateFlag policy
func ValidateFlag(u *ACL, flag string) bool {
	return utils.StringsInSlice([]string{flag, "*"}, u.Flags)
}

// ValidateHostPort policy
func ValidateHostPort(u *ACL, flag nat.PortBinding) bool {
	log.Debugf("ValidateHostPort called, %#v, %#v, %#v, container_publish_all: %t", u, flag.HostIP, flag.HostPort)
	for _, policy := range u.PortBindings {
		if matchPortPolicy(flag, policy) || ValidateFlag(u, "container_publish_all") {
			return true
		}
	}
	return false
}

// ValidateBind the policy
func ValidateBind(u *ACL, flag string) bool {
	log.Debugf("ValidateBind called, %#v, %#v", u, flag)
	return matchBind(flag, u.Binds)
}

func matchPortPolicy(pb nat.PortBinding, policy string) bool {
	msg := fmt.Sprintf("%s:%s, policy %s", pb.HostIP, pb.HostPort, policy)
	failmsg := fmt.Sprintf("No match for policy: %s", msg)
	passmsg := fmt.Sprintf("Passing port binding: %s", msg)
	errmsg := fmt.Sprintf("Error parsing port binding: %s: error: %%s", msg)

	log.Debugf("matchPortPolicy called %s", msg)
	re, err := regexp.Compile(`^((\d+\.\d+\.\d+\.\d+):)?((\d+)-)?(\d+)$`)
	if err != nil {
		log.Errorf(errmsg, err)
	}
	sl := re.FindStringSubmatch(policy)
	pHiPort, err := strconv.Atoi(sl[5])
	if err != nil {
		log.Errorf(errmsg, err)
	}
	pHostPort, err := strconv.Atoi(pb.HostPort)
	if err != nil {
		log.Errorf(errmsg, err)
	}
	if sl[4] != "" {
		pLowPort, err := strconv.Atoi(sl[4])
		if err != nil {
			log.Errorf(errmsg, err)
		}
		if pLowPort > pHiPort {
			log.Debugf("invalid port range in policy %s", policy)
			log.Debug(failmsg)
			return false
		}
		if pLowPort > pHostPort || pHiPort < pHostPort {
			log.Debugf("port out of range in policy %s", policy)
			log.Debug(failmsg)
			return false
		}
	} else {
		if pHiPort != pHostPort {
			log.Debugf("port mismatch in policy %s", policy)
			log.Debug(failmsg)
			return false
		}
	}
	pIP := sl[2]
	if pIP == "0.0.0.0" || pIP == "" {
		log.Debug(passmsg)
		return true
	}
	if pb.HostIP == "0.0.0.0" || pb.HostIP == "" {
		log.Debug("explicit ip policy")
		log.Debug(failmsg)
		return false
	}
	if pIP != pb.HostIP {
		log.Debug("ip mismatch in explicip ip policy")
		log.Debug(failmsg)
		return false
	}
	log.Debug(passmsg)
	return true
}

func matchBind(bindrequest string, policies []bind) bool {
	failmsg := fmt.Sprintf("No match for bind request: %#v", bindrequest)
	for _, policy := range policies {
		sl := strings.Split(bindrequest, ":")
		hostpath := sl[0]
		options := sl[2:]
		roreq := utils.StringInSlice("ro", options)
		msg := fmt.Sprintf("request: %#v, policy path: %#v, policy readonly: %t", bindrequest, policy.Path, policy.ReadOnly)
		passmsg := fmt.Sprintf("Passing host path %#v on request: %#v", hostpath, msg)
		errmsg := fmt.Sprintf("Error parsing bind request: %#v, error: %%s", msg)
		if ok, _ := regexp.MatchString("^/", policy.Path); !ok {
			log.Errorf(errmsg, "Policy path needs to be aboslute")
			continue
		}
		restring := fmt.Sprintf(`^(%s|%s/.*)$`, policy.Path, policy.Path)
		re, err := regexp.Compile(restring)
		if err != nil {
			log.Errorf(errmsg, err)
		}

		if re.MatchString(hostpath) || policy.Path == "/*" {
			log.Debugf("path match")
			if roreq {
				log.Debugf(passmsg, "readonly")
				return true
			}
			if !policy.ReadOnly {
				log.Debugf(passmsg, "readwrite")
				return true
			}
		}
	}
	log.Debug(failmsg)
	return false
}
