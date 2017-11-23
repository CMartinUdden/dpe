package plugin

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/CMartinUdden/dpe/policy"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/authorization"
)

// URI structure
type URI struct {
	Method      string
	Re          *regexp.Regexp
	AllowFunc   func(authorization.Request, *policy.Config) *policy.Result
	Action      string
	CmdName     string
	Description string
}

// URIs structure
type URIs []URI

// Info structure
type Info struct {
	Version string
	Path    string
}

// New function
func NewURI() *URIs {
	return &URIs{}
}

// Register function
func (uris *URIs) Register(method, uri string, af func(authorization.Request, *policy.Config) *policy.Result, action, cmdName, desc string) {
	*uris = append(*uris, URI{Method: method, Re: regexp.MustCompile(uri), AllowFunc: af, Action: action, CmdName: cmdName, Description: desc})
}

// GetURI function
func (uris *URIs) GetURI(method, url string) (URI, error) {
	for _, u := range *uris {
		if u.Method == method {
			if u.Re.MatchString(url) {
				return u, nil
			}
		}
	}

	return URI{}, nil
}

// ActionExists function
func (uris *URIs) ActionExists(action string) bool {
	for _, u := range *uris {
		if u.Action == action {
			return true
		}
	}

	return false
}

// GetURIInfo function
func GetURIInfo(defaultVersion string, req authorization.Request) (Info, error) {
	reURIWithVersion := regexp.MustCompile(`^/(v[0-9]+\.[0-9]+)(/.*)`)
	reURIWithoutVersion := regexp.MustCompile(`^(/.*)`)

	u, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		return Info{}, err
	}

	log.Debugf("Authorization request: User: %s, Method: %s, Endpoint: %s", req.User, req.RequestMethod, u.Path)

	result := reURIWithVersion.FindStringSubmatch(u.Path)

	if len(result) == 0 {
		r := reURIWithoutVersion.FindStringSubmatch(u.Path)
		if len(r) > 0 {
			return Info{Version: defaultVersion, Path: r[1]}, nil
		}
	} else {
		return Info{Version: result[1], Path: result[2]}, nil
	}

	return Info{}, fmt.Errorf("%s is not compatible", u.Path)
}
