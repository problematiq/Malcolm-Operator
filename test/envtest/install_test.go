package envtest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	sigsyaml "sigs.k8s.io/yaml"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
	"github.com/idaholab/malcolm-operator/internal/controller"
)

const operatorSA = "system:serviceaccount:malcolm-operator-system:malcolm-operator-controller-manager"

// TestInstallManifestsAndRBAC applies the kustomize install bundle, then runs
// the manager as the operator's ServiceAccount, so any permission missing from
// config/rbac surfaces as a failure.
func TestInstallManifestsAndRBAC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kubectl := filepath.Join(os.Getenv("KUBEBUILDER_ASSETS"), "kubectl")
	out, err := exec.Command(kubectl, "kustomize", filepath.Join("..", "..", "config", "default")).Output()
	if err != nil {
		t.Fatalf("kubectl kustomize: %v", err)
	}
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(out)))
	applied := 0
	for {
		doc, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{}
		if err := sigsyaml.Unmarshal(doc, &u.Object); err != nil {
			t.Fatal(err)
		}
		if len(u.Object) == 0 {
			continue
		}
		if err := k8s.Apply(ctx, client.ApplyConfigurationFromUnstructured(u), client.FieldOwner("test"), client.ForceOwnership); err != nil {
			t.Fatalf("applying %s/%s: %v", u.GetKind(), u.GetName(), err)
		}
		applied++
	}
	if applied != 14 {
		t.Fatalf("install bundle has %d objects, want 14", applied)
	}

	ns := "mal-rbac"
	createNamespace(t, ns)
	cfg := rest.CopyConfig(restConfig)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: operatorSA, Groups: []string{"system:serviceaccounts", "system:authenticated"}}

	// Sanity check: impersonation really drops cluster-admin.
	sa, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.List(ctx, &corev1.PodList{}, client.InNamespace(ns)); err == nil {
		t.Fatal("expected the operator ServiceAccount not to be able to list pods")
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress:  "0",
		Controller:              config.Controller{SkipNameValidation: ptr.To(true)},
		LeaderElection:          true,
		LeaderElectionID:        "malcolm-operator.malcolm.idaholab.github.io",
		LeaderElectionNamespace: "malcolm-operator-system",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&controller.MalcolmReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Scheme: scheme}).SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("manager: %v", err)
		}
	}()

	userSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "es", Namespace: ns},
		StringData: map[string]string{"username": "u", "password": "p"}}
	if err := k8s.Create(ctx, userSecret); err != nil {
		t.Fatal(err)
	}
	m := &malcolmv1.Malcolm{ObjectMeta: metav1.ObjectMeta{Name: "malcolm", Namespace: ns}}
	m.Spec.NetworkPolicy.Enabled = true // reads the kubernetes Service and EndpointSlices in "default"
	m.Spec.OpenSearch.Secondary = &malcolmv1.OpenSearchSecondarySpec{URL: "https://os2:9200", CredentialsSecret: "es"}
	m.Spec.Istio = malcolmv1.IstioSpec{Enabled: true, Host: "malcolm.example.org"} // RESTMapper lookup of an absent CRD
	// Jobs, CronJobs and Job listing (GeoIP updates, PostgreSQL bootstrap).
	m.Spec.MaxMind = malcolmv1.MaxMindSpec{AlternateURL: "https://mirror.example.org/geoip", Database: &malcolmv1.GeoIPDatabaseSpec{Enabled: true}}
	m.Spec.Postgres.Mode = malcolmv1.PostgresModeExternal
	m.Spec.Postgres.External = &malcolmv1.PostgresExternalSpec{Host: "pg.example.org",
		Bootstrap: &malcolmv1.PostgresBootstrapSpec{AdminCredentialsSecret: "es"}}
	if err := k8s.Create(ctx, m); err != nil {
		t.Fatal(err)
	}
	eventually(t, "reconcile as the operator ServiceAccount", func() error {
		got := &malcolmv1.Malcolm{}
		if err := k8s.Get(ctx, types.NamespacedName{Namespace: ns, Name: "malcolm"}, got); err != nil {
			return err
		}
		if got.Status.Phase != controller.PhaseProgressing {
			return fmt.Errorf("phase %q conditions %+v", got.Status.Phase, got.Status.Conditions)
		}
		jobs := &batchv1.JobList{}
		if err := k8s.List(ctx, jobs, client.InNamespace(ns)); err != nil {
			return err
		}
		if len(jobs.Items) != 2 {
			return fmt.Errorf("want the GeoIP and PostgreSQL bootstrap Jobs, got %d", len(jobs.Items))
		}
		return k8s.Get(ctx, types.NamespacedName{Namespace: ns, Name: "maxmind-geoip-update"}, &batchv1.CronJob{})
	})
}
