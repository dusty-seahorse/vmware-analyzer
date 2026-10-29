package topology

import (
	"testing"

	"github.com/np-guard/models/pkg/netset"
	"github.com/stretchr/testify/require"
)

// TestNewRuleIPBlockExternalRangeDefault is a regression test for a nil-pointer panic: RuleIPBlock's
// ExternalRange field is only populated later in the parsing pipeline (nsxConfigParser.getExternalIPs()
// in topology.go), and is left unset entirely when there is no external IP range at all. Before this
// fix, NewRuleIPBlock left ExternalRange as nil, so calling String() (e.g. via debug logging) or
// HasExternal() on a freshly-constructed RuleIPBlock would panic with a nil pointer dereference.
func TestNewRuleIPBlockExternalRangeDefault(t *testing.T) {
	block, err := netset.IPBlockFromCidr("10.0.0.0/24")
	require.NoError(t, err)

	ruleIPBlock := NewRuleIPBlock("10.0.0.0/24", block)

	require.NotNil(t, ruleIPBlock.ExternalRange, "ExternalRange should default to a non-nil empty block")
	require.True(t, ruleIPBlock.ExternalRange.IsEmpty(), "ExternalRange should default to an empty block")

	// must not panic
	require.NotPanics(t, func() {
		_ = ruleIPBlock.String()
	})

	require.False(t, ruleIPBlock.HasExternal(), "HasExternal() should be false before ExternalRange is computed")

	require.NotPanics(t, func() {
		_ = ruleIPBlock.HasInternalIPNotInSegments()
	})
}
