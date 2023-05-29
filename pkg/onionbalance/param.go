package onionbalance

const (
	// FrontendDescriptorLifetime How long should we keep a frontend descriptor before we expire it (in
	// seconds)?
	FrontendDescriptorLifetime        = 60 * 60
	FrontendDescriptorLifetimeTestnet = 20

	// HsdirNReplicas Number of replicas per descriptor
	HsdirNReplicas = 2

	// HsdirSpreadStore How many uploads per replica
	// [TODO: Get these from the consensus instead of hardcoded]
	HsdirSpreadStore = 4

	// InstanceDescriptorTooOld If we last received a descriptor for this instance more than
	// INSTANCE_DESCRIPTOR_TOO_OLD seconds ago, consider the instance to be down.
	InstanceDescriptorTooOld = 60 * 60

	// NIntrosPerInstance How many intros should we use from each instance in the final frontend
	// descriptor?
	// [TODO: This makes no attempt to hide the use of onionbalance. In the future we
	// should be smarter and sneakier here.]
	NIntrosPerInstance = 2
)
