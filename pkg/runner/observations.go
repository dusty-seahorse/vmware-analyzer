package runner

import (
	"github.com/np-guard/vmware-analyzer/internal/common"
)

// Observations holds reference to runner that completed its run without err.
// It captures output/observations produced from a successful run.
type Observations struct {
	r *Runner
}

// JSONResults holds various JSON strings for NSX config/anslysis/synthesis
type JSONResults struct {
	Topology         string
	Segmentation     string
	Connectivity     string
	GeneratedNetpols string
}

// ConfigAsJSON returns JSONResults objects, capruting various NSX config/anslysis/synthesis data in JSON strings format.
// Topology and Connectivity are only populated by the Runner when it ran the "analyze" command
// (see runAnalyzer() in runner.go, which is the sole place that sets parsedConfig/analyzedConnectivity);
// a Runner invoked with "generate" (or "lint"/"collect") never sets those fields. Rather than
// dereferencing nil state and panicking, leave the corresponding JSON section empty in that case,
// so callers (e.g. the operator, which currently only runs "generate") get the sections that are
// actually available instead of crashing.
func (o *Observations) ConfigAsJSON() (res *JSONResults, err error) {
	res = &JSONResults{}

	// topology (only available when the runner ran the "analyze" command)
	if o.r.parsedConfig != nil {
		if res.Topology, err = o.r.parsedConfig.TopologyToJSON(); err != nil {
			return nil, err
		}
	}

	// segmentation
	segmentation := o.r.nsxResources.DomainList[0].Resources.SecurityPolicyList
	if res.Segmentation, err = common.MarshalJSON(segmentation); err != nil {
		return nil, err
	}

	// connectivity (only available when the runner ran the "analyze" command)
	if o.r.analyzedConnectivity != nil {
		if res.Connectivity, err = o.r.analyzedConnectivity.GenConnectivityOutput(
			&common.OutputParameters{Format: common.JSONFormat}); err != nil {
			return nil, err
		}
	}

	// generated netpols
	// TODO: add also admin netpols
	if res.GeneratedNetpols, err = common.MarshalJSON(o.r.generatedK8sPolicies); err != nil {
		return nil, err
	}

	return res, nil
}
