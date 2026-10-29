package runner

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/np-guard/vmware-analyzer/pkg/configuration"
)

// minimalResources returns a minimal, valid ResourcesContainerModel: just enough for
// ConfigAsJSON's direct field accesses (DomainList[0].Resources.SecurityPolicyList) to be safe.
func minimalResources() *collector.ResourcesContainerModel {
	return &collector.ResourcesContainerModel{
		DomainList: []collector.Domain{
			{Resources: collector.DomainResources{SecurityPolicyList: []collector.SecurityPolicy{}}},
		},
	}
}

// TestConfigAsJSONGenerateCommandDoesNotPanic reproduces the operator's actual usage: a Runner
// run with the "generate" command only (never "analyze"), so parsedConfig and analyzedConnectivity
// are left at their zero value (nil). Calling ConfigAsJSON() on the resulting Observations used to
// panic with a nil pointer dereference inside parsedConfig.TopologyToJSON(); it should now return
// successfully with empty Topology/Connectivity sections instead.
func TestConfigAsJSONGenerateCommandDoesNotPanic(t *testing.T) {
	r := newDefaultRunner()
	r.nsxResources = minimalResources()
	// parsedConfig and analyzedConnectivity are intentionally left nil here, mirroring what
	// happens when Run() only executes runSynthesis() (Cmd == "generate") and never runAnalyzer().
	o := &Observations{r: r}

	var res *JSONResults
	var err error
	require.NotPanics(t, func() {
		res, err = o.ConfigAsJSON()
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Empty(t, res.Topology, "topology should be empty, not panic, when the runner didn't run 'analyze'")
	require.Empty(t, res.Connectivity, "connectivity should be empty, not panic, when the runner didn't run 'analyze'")
}

// TestConfigAsJSONPopulatesTopologyWhenParsedConfigIsSet is a sanity check for the opposite case:
// when parsedConfig *is* populated (as it would be after the runner ran "analyze"), its topology
// JSON should actually be returned rather than skipped.
func TestConfigAsJSONPopulatesTopologyWhenParsedConfigIsSet(t *testing.T) {
	r := newDefaultRunner()
	r.nsxResources = minimalResources()
	parsedConfig, err := configuration.ConfigFromResourcesContainer(r.nsxResources, &common.OutputParameters{})
	require.NoError(t, err)
	r.parsedConfig = parsedConfig
	// analyzedConnectivity is still left nil here; it's populated by a separate step
	// (NSXConnectivityFromResourcesContainer) that this test doesn't need to exercise.
	o := &Observations{r: r}

	var res *JSONResults
	require.NotPanics(t, func() {
		res, err = o.ConfigAsJSON()
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Topology, "topology should be populated once parsedConfig is set")
	require.Empty(t, res.Connectivity, "connectivity should still be empty since analyzedConnectivity was not set")
}
