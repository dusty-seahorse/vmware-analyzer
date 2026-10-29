package symbolicexpr

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vmware-analyzer/internal/common"
	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsx "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

// unsupportedIPAddressCondition builds a collector.Condition matching NSX's built-in
// "DefaultMaliciousIpGroup" membership condition: {member_type: IPAddress, key: ALL,
// operator: EQUALS, value: MALICIOUS_IP}. This is not a VM-tag condition, so
// getAtomicsForCondition is expected to treat it as unsupported.
func unsupportedIPAddressCondition() *collector.Condition {
	return &collector.Condition{Condition: nsx.Condition{
		MemberType: common.PointerTo(nsx.ConditionMemberTypeIPAddress),
		Key:        common.PointerTo(nsx.ConditionKeyALL),
		Operator:   common.PointerTo(nsx.ConditionOperatorEQUALS),
		Value:      common.PointerTo("MALICIOUS_IP"),
	}}
}

// TestGetAtomicsForConditionUnsupportedReturnsNil documents the existing, intentional
// behavior: an unsupported condition (e.g. IPAddress/ALL) results in a nil Atomic.
func TestGetAtomicsForConditionUnsupportedReturnsNil(t *testing.T) {
	atom := getAtomicsForCondition(false, unsupportedIPAddressCondition(), "DefaultMaliciousIpGroup")
	require.Nil(t, atom)
}

// TestGetDNFsForOperandsUnsupportedConditionDoesNotLeakNilAtomic is a regression test for a
// nil-pointer panic: getDNFsForOperands used to wrap getAtomicsForCondition's nil result
// directly into a Term (DNF{{nil}}), leaving a nil Atomic interface value inside it. Any later
// call to that Term's String()/contains()/etc. then panicked with a nil pointer dereference -
// observed in production via the unconditional debug print in
// pkg/synthesis/model/model.go's NSXConfigToAbstractModel, triggered by NSX's built-in
// "Default Malicious IP Block Rules" referencing DefaultMaliciousIpGroup.
func TestGetDNFsForOperandsUnsupportedConditionDoesNotLeakNilAtomic(t *testing.T) {
	dnf := getDNFsForOperands(nil, false, "DefaultMaliciousIpGroup", unsupportedIPAddressCondition())
	require.Nil(t, dnf, "an unsupported condition should contribute nothing, not a Term containing a nil Atomic")
}

// TestGetDNFFromExprUnsupportedConditionDoesNotPanic is an end-to-end safety net: a group whose
// expression consists solely of an unsupported condition must produce a DNF whose Terms (if any)
// never panic when stringified.
func TestGetDNFFromExprUnsupportedConditionDoesNotPanic(t *testing.T) {
	expr := collector.Expression{unsupportedIPAddressCondition()}
	var dnf DNF
	require.NotPanics(t, func() {
		dnf = GetDNFFromExpr(nil, false, &expr, "DefaultMaliciousIpGroup")
	})
	for _, term := range dnf {
		require.NotPanics(t, func() {
			_ = term.String()
		})
	}
}
