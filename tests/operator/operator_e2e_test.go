package operator

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	agentcontrolv1alpha1 "github.com/noviqtechnologies/agentcontrol/operator/api/v1alpha1"
	"github.com/noviqtechnologies/agentcontrol/operator/controllers"
)

func TestAgent ControlPolicyReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = agentcontrolv1alpha1.AddToScheme(scheme)

	policy := &agentcontrolv1alpha1.Agent ControlPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: agentcontrolv1alpha1.Agent ControlPolicySpec{
			GatewayImage: "agentcontrol:test",
			Policy:       "default_action: deny\n",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()

	r := &controllers.Agent ControlPolicyReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	ctx := context.TODO()
	req := ctrl.Request{
		NamespacedName: client.ObjectKey{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	_, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var cm corev1.ConfigMap
	err = fakeClient.Get(ctx, client.ObjectKey{Name: "test-policy-policy-config", Namespace: "default"}, &cm)
	if err != nil {
		t.Fatalf("failed to get configmap: %v", err)
	}

	if cm.Data["policy.yaml"] != "default_action: deny\n" {
		t.Errorf("expected policy data, got %v", cm.Data["policy.yaml"])
	}

	err = fakeClient.Get(ctx, client.ObjectKey{Name: "test-policy", Namespace: "default"}, policy)
	if err != nil {
		t.Fatalf("failed to get updated policy: %v", err)
	}

	if policy.Status.Phase != "Active" {
		t.Errorf("expected Active phase, got %v", policy.Status.Phase)
	}
}
