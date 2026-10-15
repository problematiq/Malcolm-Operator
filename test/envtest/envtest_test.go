// Package envtest runs the reconciler against a real kube-apiserver and etcd
// (no kubelet, so pods never start). It verifies that the CRD installs, that
// its CEL rules are enforced, that every rendered object passes API-server
// validation, and that reconciliation is idempotent.
//
// It runs only when KUBEBUILDER_ASSETS points at envtest binaries:
//
//	KUBEBUILDER_ASSETS=$(setup-envtest use 1.37.0 -p path) go test ./test/envtest/ -v
package envtest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
	"github.com/idaholab/malcolm-operator/internal/controller"
	"github.com/idaholab/malcolm-operator/internal/render"
)

var (
	k8s        client.Client
	restConfig *rest.Config
	scheme     = runtime.NewScheme()
)

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// Without envtest binaries there is nothing to run.
		os.Exit(0)
	}
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(malcolmv1.AddToScheme(scheme))
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		panic(err)
	}
	restConfig = cfg
	k8s, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		panic(err)
	}
	code := m.Run()
	_ = env.Stop()
	os.Exit(code)
}

func reconciler() *controller.MalcolmReconciler {
	return &controller.MalcolmReconciler{Client: k8s, APIReader: k8s, Scheme: scheme}
}

func createNamespace(t *testing.T, name string) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
		"pod-security.kubernetes.io/enforce": "privileged",
	}}}
	if err := k8s.Create(context.Background(), ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
}

func reconcile(t *testing.T, ns, name string) {
	t.Helper()
	if _, err := reconciler().Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}); err != nil {
		t.Fatalf("reconcile %s/%s: %v", ns, name, err)
	}
}

func getMalcolm(t *testing.T, ns, name string) *malcolmv1.Malcolm {
	t.Helper()
	m := &malcolmv1.Malcolm{}
	if err := k8s.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, m); err != nil {
		t.Fatal(err)
	}
	return m
}

// workloadVersions captures resourceVersions to detect writes.
func workloadVersions(t *testing.T, ns string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ctx := context.Background()
	lists := []client.ObjectList{&appsv1.DeploymentList{}, &appsv1.StatefulSetList{}, &appsv1.DaemonSetList{},
		&corev1.ConfigMapList{}, &corev1.SecretList{}, &corev1.ServiceList{}, &corev1.PersistentVolumeClaimList{}}
	for _, l := range lists {
		if err := k8s.List(ctx, l, client.InNamespace(ns)); err != nil {
			t.Fatal(err)
		}
		items, _ := meta.ExtractList(l)
		for _, it := range items {
			o := it.(client.Object)
			out[typeName(o)+"/"+o.GetName()] = o.GetResourceVersion()
		}
	}
	return out
}

func typeName(o client.Object) string {
	switch o.(type) {
	case *appsv1.Deployment:
		return "Deployment"
	case *appsv1.StatefulSet:
		return "StatefulSet"
	case *appsv1.DaemonSet:
		return "DaemonSet"
	case *corev1.ConfigMap:
		return "ConfigMap"
	case *corev1.Secret:
		return "Secret"
	case *corev1.Service:
		return "Service"
	case *corev1.PersistentVolumeClaim:
		return "PVC"
	}
	return "?"
}

type scenario struct {
	name  string
	spec  func(*malcolmv1.MalcolmSpec)
	setup []client.Object
}

func secret(name string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name}, StringData: data}
	return s
}

func configMap(name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name}, Data: data}
}

var scenarios = []scenario{
	{name: "default"},
	{name: "production-everything", spec: func(s *malcolmv1.MalcolmSpec) {
		s.Profile = malcolmv1.ProfileProduction
		s.Capture.PCAP.Enabled = ptr.To(true)
		s.Arkime.Parliament.Enabled = true
		s.Arkime.Cont3xt.Enabled = true
		s.IndexLifecycle = &malcolmv1.IndexLifecycleSpec{}
		s.Coverage = &malcolmv1.CoverageSpec{Enabled: true}
		s.NetworkPolicy.Enabled = true
		s.Istio = malcolmv1.IstioSpec{Enabled: true, Host: "malcolm.example.org"}
		s.Ingress.ClassName = ptr.To("nginx")
		s.Ingress.Host = "malcolm.example.org"
		s.Ingress.TLSSecretName = "malcolm-tls"
		s.Nginx.ServiceType = corev1.ServiceTypeLoadBalancer
		s.Components = map[string]malcolmv1.ComponentSpec{
			"suricata-live": {Sidecars: []runtime.RawExtension{{Raw: []byte(`{"name":"probe","image":"busybox:1.37"}`)}}},
			"logstash": {
				Resources:   &corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resourceQty("2")}},
				Tolerations: []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "ingest", Effect: corev1.TaintEffectNoSchedule}},
			},
		}
	}},
	{name: "keycloak", spec: func(s *malcolmv1.MalcolmSpec) {
		s.Auth.Mode = malcolmv1.AuthModeKeycloak
		s.Keycloak.ClientSecret = &malcolmv1.SecretKeyRef{Name: "kc-client", Key: "secret"}
	}, setup: []client.Object{secret("kc-client", map[string]string{"secret": "s3cr3t"})}},
	{name: "remote-elasticsearch", spec: func(s *malcolmv1.MalcolmSpec) {
		s.OpenSearch = malcolmv1.OpenSearchSpec{
			Mode: malcolmv1.OpenSearchModeElasticsearchRemote, URL: "https://es.example.org:9200",
			CredentialsSecret: "es-creds", DashboardsURL: "http://kibana:5601", ExternalDashboardsURL: "https://kibana.example.org",
			CACertificate: &malcolmv1.CrossNamespaceSecretKeyRef{Name: "es-ca"},
		}
		s.NetBox.Mode = malcolmv1.NetBoxModeDisabled
		s.Postgres.Enabled = ptr.To(false)
	}, setup: []client.Object{
		secret("es-creds", map[string]string{"username": "elastic", "password": "p@ss:w\"rd"}),
		secret("es-ca", map[string]string{"ca.crt": "-----BEGIN CERTIFICATE-----\n"}),
	}},
	{name: "external-postgres-geoip-placement", spec: func(s *malcolmv1.MalcolmSpec) {
		s.Postgres.Mode = malcolmv1.PostgresModeExternal
		s.Postgres.External = &malcolmv1.PostgresExternalSpec{
			Host: "pg.example.org", SSLMode: "require",
			NetBox:    malcolmv1.PostgresDatabaseSpec{CredentialsSecret: "nb-creds"},
			Bootstrap: &malcolmv1.PostgresBootstrapSpec{AdminCredentialsSecret: "pg-admin"},
		}
		s.Auth.Mode = malcolmv1.AuthModeKeycloak
		s.OpenSearch = malcolmv1.OpenSearchSpec{Mode: malcolmv1.OpenSearchModeRemote, URL: "https://os.example.org:9200",
			CredentialsSecret: "os-creds", SSLCertificateVerification: true,
			CACertificate: &malcolmv1.CrossNamespaceSecretKeyRef{Name: "os-ca"}}
		s.MaxMind = malcolmv1.MaxMindSpec{CredentialsSecret: "mm", Database: &malcolmv1.GeoIPDatabaseSpec{Enabled: true}}
		s.Placement.Server = malcolmv1.ServerPlacementSpec{
			NodeSelector:      map[string]string{"cnaps.io/node-type": "Tier-1"},
			AvoidCaptureNodes: true,
			Tolerations:       []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}},
		}
	}, setup: []client.Object{
		secret("nb-creds", map[string]string{"username": "nbuser", "password": "nbpw"}),
		secret("pg-admin", map[string]string{"username": "postgres", "password": "admin"}),
		secret("os-creds", map[string]string{"username": "malcolm", "password": "pw"}),
		secret("os-ca", map[string]string{"ca.crt": "-----BEGIN CERTIFICATE-----\n"}),
		secret("mm", map[string]string{"accountID": "1", "licenseKey": "k"}),
	}},
	{name: "custom-everything", spec: func(s *malcolmv1.MalcolmSpec) {
		s.Auth.HashedCredentials = &malcolmv1.HashedCredentialsSpec{SecretName: "malcolm-auth"}
		s.CATrustConfigMap = "my-ca"
		s.Zeek.CustomConfigMap = "my-zeek"
		s.Suricata.RulesConfigMap = "my-rules"
		s.Storage.PCAP.ExistingClaim = "nfs-pcap"
		s.OpenSearch.Local.Replicas = ptr.To[int32](3)
		s.OpenSearch.Local.TransportCASecret = "os-ca"
		s.Logstash.Replicas = ptr.To[int32](2)
	}, setup: []client.Object{
		secret("malcolm-auth", map[string]string{"username": "u", "openssl_password": "x", "htpass_cred": "u:y"}),
		configMap("my-ca", nil), configMap("my-zeek", map[string]string{"__load__.zeek": ""}), configMap("my-rules", nil),
	}},
}

func TestScenariosAreAcceptedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			ns := "mal-" + sc.name
			createNamespace(t, ns)
			for _, o := range sc.setup {
				o = o.DeepCopyObject().(client.Object)
				o.SetNamespace(ns)
				if err := k8s.Create(ctx, o); err != nil {
					t.Fatal(err)
				}
			}
			m := &malcolmv1.Malcolm{ObjectMeta: metav1.ObjectMeta{Name: "malcolm", Namespace: ns}}
			if sc.spec != nil {
				sc.spec(&m.Spec)
			}
			if err := k8s.Create(ctx, m); err != nil {
				t.Fatalf("creating Malcolm: %v", err)
			}

			reconcile(t, ns, "malcolm")
			got := getMalcolm(t, ns, "malcolm")
			if got.Status.Phase != controller.PhaseProgressing {
				t.Fatalf("phase = %q, conditions: %+v", got.Status.Phase, got.Status.Conditions)
			}
			if c := meta.FindStatusCondition(got.Status.Conditions, controller.ConditionDegraded); c == nil || c.Status != metav1.ConditionFalse {
				t.Fatalf("Degraded condition: %+v", c)
			}
			// Spec defaults are applied by the API server.
			if got.Spec.Profile == "" || got.Spec.Image.Repository != "ghcr.io/idaholab/malcolm" {
				t.Errorf("CRD defaults not applied: profile=%q repo=%q", got.Spec.Profile, got.Spec.Image.Repository)
			}

			// Once settled, a reconcile must be a no-op for every object. (The API
			// server rewrites a PVC once on its first re-apply after creation.)
			reconcile(t, ns, "malcolm")
			before := workloadVersions(t, ns)
			reconcile(t, ns, "malcolm")
			after := workloadVersions(t, ns)
			for k, v := range before {
				if after[k] != v {
					t.Errorf("%s was rewritten by an unchanged reconcile (%s -> %s)", k, v, after[k])
				}
			}
			if len(before) < 40 {
				t.Errorf("only %d objects found; expected a full deployment", len(before))
			}
		})
	}
}

func TestCELRulesEnforcedByAPIServer(t *testing.T) {
	createNamespace(t, "mal-invalid")
	m := &malcolmv1.Malcolm{ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "mal-invalid"}}
	m.Spec.Capture.Netsniff = ptr.To(true)
	m.Spec.Config = map[string]map[string]string{"zeeek": {"A": "b"}}
	err := k8s.Create(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "cannot both be enabled") || !strings.Contains(err.Error(), "unknown config group") {
		t.Fatalf("expected CEL validation errors, got %v", err)
	}
}

func TestSpecChangesUpdateAndPrune(t *testing.T) {
	ctx := context.Background()
	ns := "mal-update"
	createNamespace(t, ns)
	m := &malcolmv1.Malcolm{ObjectMeta: metav1.ObjectMeta{Name: "malcolm", Namespace: ns}}
	m.Spec.Auth.Mode = malcolmv1.AuthModeKeycloak
	if err := k8s.Create(ctx, m); err != nil {
		t.Fatal(err)
	}
	reconcile(t, ns, "malcolm")

	dep := func(name string) (*appsv1.Deployment, error) {
		d := &appsv1.Deployment{}
		return d, k8s.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, d)
	}
	if _, err := dep("keycloak-deployment"); err != nil {
		t.Fatal(err)
	}
	ls, _ := dep("logstash-deployment")
	hashBefore := ls.Spec.Template.Annotations[render.AnnotationConfigHash]
	freq, _ := dep("freq-deployment")
	freqHash := freq.Spec.Template.Annotations[render.AnnotationConfigHash]

	cur := getMalcolm(t, ns, "malcolm")
	cur.Spec.Auth.Mode = malcolmv1.AuthModeBasic
	cur.Spec.Logstash.Workers = ptr.To[int32](8)
	cur.Spec.Storage.PCAP.Size = ptr.To(resourceQty("40Gi"))
	if err := k8s.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	reconcile(t, ns, "malcolm")

	if _, err := dep("keycloak-deployment"); !apierrors.IsNotFound(err) {
		t.Errorf("keycloak-deployment should be pruned, err=%v", err)
	}
	ls, _ = dep("logstash-deployment")
	if ls.Spec.Template.Annotations[render.AnnotationConfigHash] == hashBefore {
		t.Error("logstash should roll after its configuration changed")
	}
	freq, _ = dep("freq-deployment")
	if freq.Spec.Template.Annotations[render.AnnotationConfigHash] != freqHash {
		t.Error("freq does not consume the changed configuration and should not roll")
	}
	cm := &corev1.ConfigMap{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: ns, Name: "logstash-env"}, cm); err != nil || cm.Data["pipeline.workers"] != "8" {
		t.Errorf("logstash-env not updated: %v %v", err, cm.Data["pipeline.workers"])
	}
	// envtest has no volume provisioner, so the claim is unbound and must not be
	// resized; the instance reports a warning instead of failing.
	pvc := &corev1.PersistentVolumeClaim{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: ns, Name: render.ClaimPCAP}, pvc); err != nil {
		t.Fatal(err)
	}
	if q := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; q.String() != "25Gi" {
		t.Errorf("unbound pcap claim should keep its size, got %s", q.String())
	}
	status := getMalcolm(t, ns, "malcolm").Status
	if w := meta.FindStatusCondition(status.Conditions, controller.ConditionWarning); w == nil || !strings.Contains(w.Message, "pcap-claim cannot grow to 40Gi: the claim is not bound yet") {
		t.Errorf("expected a resize warning, got %+v", w)
	}
	if c := meta.FindStatusCondition(status.Conditions, controller.ConditionDegraded); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("a blocked resize must not degrade the instance: %+v", c)
	}

	// StatefulSet claim templates are immutable; size changes must not break reconciliation.
	cur = getMalcolm(t, ns, "malcolm")
	cur.Spec.Storage.OpenSearch.Size = ptr.To(resourceQty("100Gi"))
	if err := k8s.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	reconcile(t, ns, "malcolm")
	status = getMalcolm(t, ns, "malcolm").Status
	if c := meta.FindStatusCondition(status.Conditions, controller.ConditionDegraded); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("changing a claim template size degraded the instance: %+v", c)
	}
	if w := meta.FindStatusCondition(status.Conditions, controller.ConditionWarning); w == nil || !strings.Contains(w.Message, "StatefulSet opensearch volume claim templates are immutable") {
		t.Errorf("expected a claim template warning, got %+v", w)
	}
}

func TestTakesOverHelmStyleObjects(t *testing.T) {
	ctx := context.Background()
	ns := "mal-takeover"
	createNamespace(t, ns)
	// Objects shaped like the chart's: same names and selectors, no owner.
	helmDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "freq-deployment", Namespace: ns,
			Labels:      map[string]string{"app.kubernetes.io/managed-by": "Helm"},
			Annotations: map[string]string{"meta.helm.sh/release-name": "malcolm"}},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": "freq-deployment"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"name": "freq-deployment"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "freq-container", Image: "ghcr.io/idaholab/malcolm/freq:26.09.0"}}},
			},
		},
	}
	helmValkey := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.SecretValkeyEnv, Namespace: ns},
		StringData: map[string]string{"VALKEY_PASSWORD": "kept"}}
	for _, o := range []client.Object{helmDeployment, helmValkey} {
		if err := k8s.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	if err := k8s.Create(ctx, &malcolmv1.Malcolm{ObjectMeta: metav1.ObjectMeta{Name: "malcolm", Namespace: ns}}); err != nil {
		t.Fatal(err)
	}
	reconcile(t, ns, "malcolm")

	d := &appsv1.Deployment{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: ns, Name: "freq-deployment"}, d); err != nil {
		t.Fatal(err)
	}
	if metav1.GetControllerOf(d) == nil || d.Labels[render.LabelManagedBy] != render.ManagedByValue {
		t.Errorf("deployment not taken over: owner=%v labels=%v", metav1.GetControllerOf(d), d.Labels)
	}
	if d.Spec.Template.Spec.Containers[0].LivenessProbe == nil {
		t.Error("deployment spec not updated to the operator's desired state")
	}
	vk := &corev1.Secret{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: ns, Name: render.SecretValkeyEnv}, vk); err != nil {
		t.Fatal(err)
	}
	if string(vk.Data["VALKEY_PASSWORD"]) != "kept" {
		t.Errorf("valkey password not preserved: %q", vk.Data["VALKEY_PASSWORD"])
	}
}

func resourceQty(s string) resource.Quantity { return resource.MustParse(s) }
