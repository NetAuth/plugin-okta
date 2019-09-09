package impl

import (
	"github.com/okta/okta-sdk-golang/okta"

	"github.com/NetAuth/NetAuth/pkg/plugin/tree"

	pb "github.com/NetAuth/Protocol"
)

// GroupCreate will create a matched group in Okta.  Assigning
// applications to this group must still be done in Okta directly, but
// the group and its attributes are mapped from NetAuth.
func (o OktaPlugin) GroupCreate(g pb.Group) (pb.Group, error) {
	og := okta.Group{
		Profile: &okta.GroupProfile{
			Description: g.GetDisplayName(),
			Name:        g.GetName(),
		},
	}

	group, resp, err := o.c.Group.CreateGroup(og)
	if err != nil {
		appLogger.Error("Okta group was not created!", "error", err)
		return g, err
	}

	appLogger.Debug("Okta Response", "response", resp)

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

	grp, resp, err := o.c.Group.GetGroup(oktaID, nil)
	if err != nil {
		appLogger.Warn("No group with OktaID", "name", g.GetName(), "oktaID", oktaID, "error", err)
		return g, nil
	}

	appLogger.Debug("Okta Response", "response", resp)

	grp.Profile.Description = g.GetDisplayName()

	_, resp, err = o.c.Group.UpdateGroup(oktaID, *grp)
	if err != nil {
		appLogger.Warn("Error updating Okta group", "error", err)
		return g, nil
	}

	appLogger.Debug("Okta Response", "response", resp)

	return g, nil
}

// GroupDestroy pushes the destruction of groups to Okta.  It is
// recommended to never destroy a group, but if this is desired this
// function will ensure the group is removed in Okta as well.
func (o OktaPlugin) GroupDestroy(g pb.Group) error {
	appLogger.Info("Attempting to remove group from Okta", "group", g.GetName())
	oktaID := getGroupOktaID(g)
	if oktaID == "" {
		return nil
	}
	resp, err := o.c.Group.DeleteGroup(oktaID)
	if err != nil {
		appLogger.Warn("Failed to delete Okta Group", "group", g.GetName(), "oktaID", oktaID, "error", err)
	}

	appLogger.Debug("Okta Response", "response", resp)
	return nil
}
