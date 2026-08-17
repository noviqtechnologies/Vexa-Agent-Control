package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IdentityConfig defines identity parameters
type IdentityConfig struct {
	Provider  string `json:"provider,omitempty"`
	VaultAddr string `json:"vaultAddr,omitempty"`
}

// NetworkPolicyConfig defines network policy configuration (FR-5 §5.5.8).
//
// When Enforced is true, the operator generates a Kubernetes NetworkPolicy that
// restricts egress from pods matching AgentPodSelector so they can ONLY reach
// pods matching GatewayPodSelector on MCPPort. DNS egress (53/tcp+udp) is always
// permitted so agents can still resolve the gateway's service name.
//
// All fields except Enforced are optional and fall back to conventions:
//   AgentPodSelector    -> {agentcontrol.io/agent: "true"}
//   GatewayPodSelector  -> {agentcontrol.io/gateway: "true"}
//   MCPPort             -> 8080
//
// Existing CRs written before these fields were introduced remain valid; the
// defaults produce the behavior described in the PRD.
type NetworkPolicyConfig struct {
	// Enforced enables NetworkPolicy generation for this policy.
	// Defaults to false to preserve backward compatibility with existing CRs.
	Enforced bool `json:"enforced,omitempty"`

	// AgentPodSelector selects the agent pods that will be restricted.
	// If empty, defaults to {"agentcontrol.io/agent": "true"}.
	// +optional
	AgentPodSelector map[string]string `json:"agentPodSelector,omitempty"`

	// GatewayPodSelector selects the gateway pod(s) that agents are allowed
	// to reach. If empty, defaults to {"agentcontrol.io/gateway": "true"}.
	// +optional
	GatewayPodSelector map[string]string `json:"gatewayPodSelector,omitempty"`

	// MCPPort is the TCP port the gateway listens on. Defaults to 8080.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	MCPPort int32 `json:"mcpPort,omitempty"`
}

// AgentControlPolicySpec defines the desired state of AgentControlPolicy
type AgentControlPolicySpec struct {
	// GatewayImage defines the Agent Control image to inject
	GatewayImage string `json:"gatewayImage,omitempty"`

	// Policy contains the inline YAML policy definition
	Policy string `json:"policy,omitempty"`

	// Identity configuration
	Identity IdentityConfig `json:"identity,omitempty"`

	// NetworkPolicy configuration
	NetworkPolicy NetworkPolicyConfig `json:"networkPolicy,omitempty"`
}

// AgentControlPolicyStatus defines the observed state of AgentControlPolicy
type AgentControlPolicyStatus struct {
	// Phase is the current state of the policy
	Phase string `json:"phase,omitempty"`

	// GatewayPodName is the name of the deployed gateway pod
	GatewayPodName string `json:"gatewayPodName,omitempty"`

	// LastReconcileTime is the last time the policy was reconciled
	LastReconcileTime string `json:"lastReconcileTime,omitempty"`

	// NetworkPolicyName is the name of the generated NetworkPolicy, if any.
	// Empty when NetworkPolicy.Enforced is false.
	NetworkPolicyName string `json:"networkPolicyName,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// AgentControlPolicy is the Schema for the agentcontrolpolicies API
type AgentControlPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AgentControlPolicySpec   `json:"spec,omitempty"`
	Status AgentControlPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AgentControlPolicyList contains a list of AgentControlPolicy
type AgentControlPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AgentControlPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AgentControlPolicy{}, &AgentControlPolicyList{})
}
