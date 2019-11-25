package impl

import (
	"strings"

	"github.com/netauth/netauth/pkg/plugin/tree"

	pb "github.com/netauth/protocol"
)

func getEntityOktaID(e pb.Entity) string {
	m := e.GetMeta()
	if m == nil {
		return ""
	}
	um := m.GetUntypedMeta()
	res := tree.PatchKeyValueSlice(um, "READ", "oktaID", "")
	if len(res) != 1 || res[0] == "" {
		return ""
	}
	oktaID := strings.SplitN(res[0], ":", 2)[1]
	return oktaID
}

func getGroupOktaID(g pb.Group) string {
	res := tree.PatchKeyValueSlice(g.UntypedMeta, "READ", "oktaID", "")
	if len(res) != 1 || res[0] == "" {
		return ""
	}
	oktaID := strings.SplitN(res[0], ":", 2)[1]
	return oktaID
}
