package impl

import (
	"time"

	"github.com/NetAuth/NetAuth/pkg/client"

	pb "github.com/NetAuth/Protocol"
)

func (o OktaPlugin) groupSyncTimer() {
	ticker := time.NewTicker(cfg.GetDuration("interval"))

	for range ticker.C {
		o.syncGroups()
	}
}

func (o OktaPlugin) syncGroups() {
	c, err := client.New()
	groups, err := c.SearchGroups("*")
	if err != nil {
		appLogger.Warn("Not running syncGroups()", "error", err)
		return
	}

	// Filter on manageable groups
	oktaGroups := make(map[string]pb.Group)
	for _, g := range groups.GetGroups() {
		oktaID := getGroupOktaID(*g)
		if oktaID != "" {
			oktaGroups[oktaID] = *g
		}
	}

	// Compute what we want the groups to look like
	want := make(map[string]map[string]struct{})
	for gid, g := range oktaGroups {
		want[gid] = make(map[string]struct{})

		members, err := c.ListGroupMembers(g.GetName())
		if err != nil {
			appLogger.Warn("Failed to get memberships", "group", g.GetName(), "error", err)
			continue
		}
		for _, e := range members {
			if id := getEntityOktaID(*e); id != "" {
				want[gid][id] = struct{}{}
			}
		}
	}

	// Get existing memberships
	for gid := range oktaGroups {
		users, _, err := o.c.Group.ListGroupUsers(gid, nil)
		if err != nil {
			appLogger.Warn("Not updating membership for group",
				"group", oktaGroups[gid].Name,
				"error", err)
			continue
		}
		for i := range users {
			if _, ok := want[gid][users[i].Id]; ok {
				// User is already there, drop it from
				// the want list
				delete(want[gid], users[i].Id)
			} else {
				// User is there and shouldn't be, get
				// rid of them.
				_, err := o.c.Group.RemoveGroupUser(gid, users[i].Id)
				if err != nil {
					appLogger.Warn("Failed to remove user from group",
						"group", gid,
						"user", users[i].Id,
						"error", err)
				}
				appLogger.Trace("Removing okta user",
					"group", gid,
					"user", users[i].Id)
			}
		}
	}

	// Add the remaining users
	for gid := range oktaGroups {
		for user := range want[gid] {
			if _, err := o.c.Group.AddUserToGroup(gid, user); err != nil {
				appLogger.Warn("Failed to add user to group",
					"group", gid,
					"user", user,
					"error", err)
			}
		}
	}
}
