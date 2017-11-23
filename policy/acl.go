package policy

import (
	"encoding/json"
	"github.com/CMartinUdden/dpe/utils"
	log "github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"os"
	"reflect"
)

var theconfig *config

var supportedSuffixes = []string{".json"}

type bind struct {
	Path     string
	ReadOnly bool
}

// ACL is the ACL structure
type ACL struct {
	Name         string
	Members      []string
	Binds        []bind
	Caps         []string
	Devs         []string
	Flags        []string
	Groups       []string
	PortBindings []string
}

type res struct {
	Name   string
	Groups []string
}

type user struct {
	Name   string
	Groups []string
}

type bindgroup struct {
	Name     string
	ReadOnly bool
}

type topbind struct {
	Path   string
	Groups []bindgroup
}

type config struct {
	Groups       []ACL
	Users        []user
	Binds        []topbind
	Caps         []res
	Devs         []res
	Flags        []res
	PortBindings []res
}

var thegroups map[string]*ACL
var acl map[string]*ACL

func (e *ACL) String() string {
	//return spew.Sdump(e)
	return utils.Sdump(*e)
}

func (e bind) String() string {
	//return spew.Sdump(e)
	return utils.Sdump(e)
}

func calculateacl() {
	thegroups = make(map[string]*ACL)
	acl = make(map[string]*ACL)
	var allgroups []string
	var groups []string
	var bg []bindgroup

	// We start by builing the global groups var (thegroups)
	// This contains all the policies group indexed
	for _, g := range theconfig.Groups {
		thegroups[g.Name] = &ACL{Name: g.Name, Members: g.Members, Binds: g.Binds,
			Caps: g.Caps, Devs: g.Devs, Flags: g.Flags, PortBindings: g.PortBindings}
		allgroups = append(allgroups, g.Name)
	}

	for _, user := range theconfig.Users {
		if len(user.Groups) > 0 && user.Groups[0] == "*" {
			groups = allgroups
		} else {
			groups = user.Groups
		}
		adduser(user, groups)
	}

	for _, bind := range theconfig.Binds {
		if len(bind.Groups) > 0 && bind.Groups[0].Name == "*" {
			for _, b := range allgroups {
				bg = append(bg, bindgroup{Name: b, ReadOnly: bind.Groups[0].ReadOnly})
			}
		} else {
			bg = bind.Groups
		}
		addbind(bind, bg)
	}

	type rs struct {
		r []res
		s string
	}

	for _, x := range []rs{rs{theconfig.Caps, "Caps"}, rs{theconfig.Devs, "Devs"}, rs{theconfig.Flags, "Flags"}, rs{theconfig.PortBindings, "PortBindings"}} {
		for _, r := range x.r {
			if len(r.Groups) > 0 && r.Groups[0] == "*" {
				groups = allgroups
			} else {
				groups = r.Groups
			}
			addres(r, groups, thegroups, x.s)
		}
	}

	allgroups = []string{}

	for g := range thegroups {
		allgroups = append(allgroups, g)
	}

	// Now we create the ACL var, indexed by user name for easy lookup
	// We treat the users as dummy groups
	for _, g := range thegroups {
		for _, user := range g.Members {
			addgroup(user, g.Name, acl)
			s := []string{user}
			for _, bind := range g.Binds {
				adduserbind(bind, user)
			}
			for _, c := range g.Caps {
				addres(res{Name: c}, s, acl, "Caps")
			}

			for _, d := range g.Devs {
				addres(res{Name: d}, s, acl, "Devs")
			}

			for _, f := range g.Flags {
				addres(res{Name: f}, s, acl, "Flags")
			}

			for _, p := range g.PortBindings {
				addres(res{Name: p}, s, acl, "PortBindings")
			}
		}
	}
	log.Debugf("Calculated group list: %s", spew.Sdump(thegroups))
	log.Debugf("Calculated ACL: %s", spew.Sdump(acl))
}

// Make sure we have a named entry in a acl map
func addentry(g string, themap map[string]*ACL) {
	_, ok := themap[g]
	if !ok {
		themap[g] = &ACL{Name: g}
	}
}

// Add a user to a list of specified groups
func adduser(u user, groups []string) {
	for _, g := range groups {
		addentry(g, thegroups)
		if !utils.StringInSlice(u.Name, thegroups[g].Members) {
			thegroups[g].Members = append(thegroups[g].Members, u.Name)
		}
	}
}

// We want to be able to check for the readonly flag,
// so we have to traverse this struct
func bindExists(b *bind, binds []bind) bool {
	for _, extbind := range binds {
		if b.Path == extbind.Path && b.ReadOnly == extbind.ReadOnly {
			return true
		}
	}
	return false
}

// Adds a bind to the user indexed ACL
func adduserbind(b bind, user string) {
	themap := acl
	addentry(user, themap)
	thebind := &bind{Path: b.Path, ReadOnly: b.ReadOnly}
	if !bindExists(thebind, themap[user].Binds) {
		themap[user].Binds = append(themap[user].Binds, *thebind)
	}
}

// Adds a bind to the group structure using the topbind type
func addbind(b topbind, groups []bindgroup) {
	themap := thegroups
	for _, g := range groups {
		name := g.Name
		path := b.Path
		readonly := g.ReadOnly
		addentry(name, themap)
		thebind := &bind{Path: path, ReadOnly: readonly}
		if !bindExists(thebind, themap[name].Binds) {
			themap[name].Binds = append(themap[name].Binds, *thebind)
		}
	}
}

// Adds a group to the user indexed ACL, for easy lookup
func addgroup(user string, g string, themap map[string]*ACL) {
	addentry(user, themap)
	if !utils.StringInSlice(g, themap[user].Groups) {
		themap[user].Groups = append(themap[user].Groups, g)
	}
}

func addres(r res, items []string, themap map[string]*ACL, field string) {
	for _, g := range items {
		addentry(g, themap)
		rv := utils.GetFieldInStruct(themap[g], field).(reflect.Value)
		slice := rv.Interface().([]string)

		if !utils.StringInSlice(r.Name, slice) {
			slice = append(slice, r.Name)
			utils.SetFieldInStruct(themap[g], field, reflect.ValueOf(slice))
		}
	}
}

// Build the top conf objects
func configmerge(c *config) {
	for _, field := range []string{"Groups", "Users", "Binds", "Caps", "Devs", "Flags", "PortBindings"} {
		utils.MergeSliceField(c, theconfig, field)
	}
}

func wf(path string, info os.FileInfo, err error) error {
	var c config
	// .. looking for files that looks like a supported conf file
	if !info.IsDir() && SupportedFile(path) {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Errorf("Unable to read file %s: %s", path, err)
			return err
		}

		c = config{}

		err = json.Unmarshal(data, &c)

		if err != nil {
			log.Errorf("Unable to parse json file %s: %s", path, err)
			return err
		}

		// and merge the configuration into the global conf var
		configmerge(&c)
		log.Debugf("Read config file %s: %#v", path, c)
	}

	return nil
}
