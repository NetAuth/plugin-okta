package impl

import (
	"github.com/okta/okta-sdk-golang/okta"

	"github.com/netauth/netauth/pkg/plugin/tree"

	pb "github.com/netauth/Protocol"
)

// GroupCreate will create a matched group in Okta.  Assigning
// applications to this group must still be done in Okta directly, but
// the group and its attributes are mapped from netauth.
func (o OktaPlugin) GroupCreate(g pb.Group) (pb.Group, error) {
	og := okta.Group{
		Profile: &okta.GroupProfile{
			Description: g.GetDisplayName(),
			Name:        g.GetName(),
		},
	}

	group, _, err := o.c.Group.CreateGroup(og)
	if err != nil {
		appLogger.Error("Okta group was not created!", "error", err)
		return g, err
	}

	g.UntypedMeta = tree.PatchKeyValueSlice(g.UntypedMeta, "UPSERT", "oktaID", group.Id)

	return g, nil
}

// GroupUpdate is called to manage ongoing changes to a group.  This
// function does not push membership changes.
func (o OktaPlugin) GroupUpdate(g pb.Group) (pb.Group, error) {
	oktaID := getGroupOktaID(g)
	if oktaID == "" {
		return g, nil
	}

	grp, _, err := o.c.Group.GetGroup(oktaID, nil)
	if err != nil {
		appLogger.Warn("No group with OktaID", "name", g.GetName(), "oktaID", oktaID, "error", err)
		return g, nil
	}

	grp.Profile.Description = g.GetDisplayName()

	_, _, err = o.c.Group.UpdateGroup(oktaID, *grp)
	if err != nil {
		appLogger.Warn("Error updating Okta group", "error", err)
		return g, nil
	}

	return g, nil
}

// GroupDestroy pushes the destruction of groups to Okta.  It is
// recommended to never destroy a group, but if this is desired this
// function will ensure the group is removed in Okta as well.
func (o OktaPlugin) GroupDestroy(g pb.Group) (pb.Group, error) {
	appLogger.Info("Attempting to remove group from Okta", "group", g.GetName())
	oktaID := getGroupOktaID(g)
	if oktaID == "" {
		return g, nil
	}

	// Deleting groups in Okta appears to be very racy, and this
	// often leads to groups not actually being deleted.  The fix
	// is to keep trying to get the group until it goes away since
	// that is the only way Okta provides to be sure that a group
	// is really gone.
	var err error
	err = nil
	for err == nil {
		_, err = o.c.Group.DeleteGroup(oktaID)
		if err != nil {
			appLogger.Warn("Failed to delete Okta Group", "group", g.GetName(), "oktaID", oktaID, "error", err)
		}

		_, _, err = o.c.Group.GetGroup(oktaID, nil)
		appLogger.Debug("Error after getting group", "error", err)
	}

	return g, nil
}
