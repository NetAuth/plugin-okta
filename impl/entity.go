package impl

import (
	"strings"

	"github.com/okta/okta-sdk-golang/okta"

	"github.com/NetAuth/NetAuth/pkg/plugin/tree"

	pb "github.com/NetAuth/Protocol"
)

// EntityCreate propogates entity creation events.  This makes certain
// assumptions around how the okta logins are setup, and how usernames
// are provisioned.
func (o OktaPlugin) EntityCreate(e, de pb.Entity) (pb.Entity, error) {
	p := &okta.PasswordCredential{
		Value: de.GetSecret(),
	}
	uc := &okta.UserCredentials{
		Password: p,
	}
	profile := okta.UserProfile{}
	profile["firstName"] = "UNSET"
	profile["lastName"] = "UNSET"
	profile["employeeNumber"] = e.GetNumber()
	profile["email"] = e.GetID() + "@" + cfg.GetString("domain")
	profile["login"] = e.GetID() + "@" + cfg.GetString("domain")
	u := &okta.User{
		Credentials: uc,
		Profile:     &profile,
	}

	user, resp, err := o.c.User.CreateUser(*u, nil)
	if err != nil {
		appLogger.Error("Okta user was not created!", "error", err)
		return e, err
	}

	appLogger.Debug("Okta Response", "response", resp)

	if e.Meta == nil {
		e.Meta = &pb.EntityMeta{}
	}

	e.Meta.UntypedMeta = tree.PatchKeyValueSlice(e.Meta.UntypedMeta, "UPSERT", "oktaID", user.Id)

	return e, nil
}

// EntityUpdate pushes changes to the base entity profile, nothing
// else.  Custom attributes are not supported in this plugin.
func (o OktaPlugin) EntityUpdate(e pb.Entity) (pb.Entity, error) {
	oktaID := getEntityOktaID(e)
	if oktaID == "" {
		return e, nil
	}

	user, resp, err := o.c.User.GetUser(oktaID)
	if err != nil {
		appLogger.Warn("No user with OktaID", "id", oktaID, "error", err)
		return e, nil
	}

	name := e.GetMeta().GetLegalName()
	nameParts := strings.SplitN(name, " ", 2)

	newProfile := *user.Profile
	if len(nameParts) == 2 {
		newProfile["firstName"] = nameParts[0]
		newProfile["lastName"] = nameParts[1]
	}
	newProfile["employeeNumber"] = e.GetNumber()
	newProfile["displayName"] = e.GetMeta().GetDisplayName()

	updatedUser := &okta.User{
		Profile: &newProfile,
	}
	_, resp, err = o.c.User.UpdateUser(oktaID, *updatedUser, nil)
	if err != nil {
		appLogger.Warn("Error updating Okta user", "error", err)
		return e, nil
	}
	appLogger.Debug("Okta Response", "response", resp)
	return e, nil
}

// EntityLock translates to a suspended entity in Okta.
func (o OktaPlugin) EntityLock(e pb.Entity) (pb.Entity, error) {
	oktaID := getEntityOktaID(e)
	if oktaID == "" {
		return e, nil
	}

	_, err := o.c.User.SuspendUser(oktaID)
	if err != nil {
		appLogger.Warn("Failed to lock Okta user", "entity", e.GetID(), "error", err)
	}

	return e, nil
}

// EntityUnlock translates to a force un-suspend in Okta.
func (o OktaPlugin) EntityUnlock(e pb.Entity) (pb.Entity, error) {
	oktaID := getEntityOktaID(e)
	if oktaID == "" {
		return e, nil
	}

	_, err := o.c.User.UnsuspendUser(oktaID)
	if err != nil {
		appLogger.Warn("Failed to lock Okta user", "entity", e.GetID(), "error", err)
	}

	return e, nil
}

// EntityDestroy should never be used, deleting users is generally
// bad, but if you must, then this function will ensure that users in
// Okta have also been wiped.
func (o OktaPlugin) EntityDestroy(e pb.Entity) error {
	oktaID := getEntityOktaID(e)
	if oktaID == "" {
		return nil
	}

	_, err := o.c.User.DeactivateUser(oktaID, nil)
	if err != nil {
		appLogger.Warn("Failed to deactivate Okta user", "enttiy", e.GetID(), "error", err)
	}

	_, err = o.c.User.DeactivateOrDeleteUser(oktaID, nil)
	if err != nil {
		appLogger.Warn("Failed to delete Okta user", "entity", e.GetID(), "error", err)
	}

	return nil
}
