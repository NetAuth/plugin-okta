package impl

import (
	"strings"

	"github.com/NetAuth/NetAuth/pkg/plugin/tree"

	pb "github.com/NetAuth/Protocol"
)

func getOktaID(e pb.Entity) string {
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
