package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
	"github.com/idaholab/malcolm-operator/internal/credentials"
	"github.com/idaholab/malcolm-operator/internal/render"
)

const ns = "malcolm"

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(malcolmv1.AddToScheme(s))
	return s
}

func newReconciler(t *testing.T, objs ...client.Object) (*MalcolmReconciler, client.Client) {
	t.Helper()
	s := newScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&malcolmv1.Malcolm{}).
		Build()
	return &MalcolmReconciler{Client: c, Scheme: s}, c
}

func malcolm(name string, mut func(*malcolmv1.MalcolmSpec)) *malcolmv1.Malcolm {
	m := &malcolmv1.Malcolm{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID("uid-" + name)}}
	if mut != nil {
		mut(&m.Spec)
	}
	return m
}

func reconcileOnce(t *testing.T, r *MalcolmReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return res
}

func get[T client.Object](t *testing.T, c client.Client, name string, obj T) T {
	t.Helper()
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, obj); err != nil {
		t.Fatalf("get %T %s: %v", obj, name, err)
	}
	return obj
}

func TestReconcileCreatesDeployment(t *testing.T) {
	r, c := newReconciler(t, malcolm("malcolm", nil))
	res := reconcileOnce(t, r, "malcolm")
	if res.RequeueAfter == 0 {
		t.Error("expected a requeue while components are not ready")
	}

	// Generated credentials and admin login exist and are retained (no owner).
	gen := get(t, c, "malcolm-generated", &corev1.Secret{})
	if len(gen.OwnerReferences) != 0 || gen.Annotations[render.AnnotationRetain] != "true" {
		t.Errorf("generated secret should be retained: %+v", gen.ObjectMeta)
	}
	if len(gen.Data[keyPostgresPassword]) != 32 || len(gen.Data[keyNetBoxSecretKey]) != 50 {
		t.Errorf("unexpected generated lengths")
	}
	admin := get(t, c, "malcolm-admin-credentials", &corev1.Secret{})
	user, pw := string(admin.Data["username"]), string(admin.Data["password"])
	if user != "malcolm" || len(pw) != 24 {
		t.Errorf("unexpected admin credentials %q/%d", user, len(pw))
	}
	authEnv := get(t, c, render.SecretAuthEnv, &corev1.Secret{})
	nginxAuth := get(t, c, render.SecretNginxAuth, &corev1.Secret{})
	if !credentials.VerifyHtpasswd(string(nginxAuth.Data["htpasswd"]), user, pw) {
		t.Error("htpasswd does not match the generated admin password")
	}
	if string(authEnv.Data["MALCOLM_USERNAME"]) != user {
		t.Error("auth-env username mismatch")
	}

	// Workloads exist with a controller reference to the Malcolm resource.
	d := get(t, c, "logstash-deployment", &appsv1.Deployment{})
	if ref := metav1.GetControllerOf(d); ref == nil || ref.Name != "malcolm" {
		t.Errorf("logstash-deployment owner = %+v", ref)
	}
	if *d.Spec.Replicas != 1 {
		t.Errorf("logstash replicas = %d, want 1 with no labeled nodes", *d.Spec.Replicas)
	}
	get(t, c, "opensearch", &appsv1.StatefulSet{})
	get(t, c, "zeek-live-daemonset-remotesensor", &appsv1.DaemonSet{})
	pvc := get(t, c, render.ClaimPCAP, &corev1.PersistentVolumeClaim{})
	if len(pvc.OwnerReferences) != 0 {
		t.Error("PVCs are retained by default and must not have an owner")
	}

	m := get(t, c, "malcolm", &malcolmv1.Malcolm{})
	if m.Status.Phase != PhaseProgressing || m.Status.AdminCredentialsSecret != "malcolm-admin-credentials" ||
		m.Status.Version != render.DefaultVersion || m.Status.ReadyComponents != "0/27" {
		t.Errorf("unexpected status %+v", m.Status)
	}

	// A second reconcile must not change passwords, hashes, or pod templates.
	hashBefore := d.Spec.Template.Annotations[render.AnnotationConfigHash]
	htBefore := string(nginxAuth.Data["htpasswd"])
	reconcileOnce(t, r, "malcolm")
	d2 := get(t, c, "logstash-deployment", &appsv1.Deployment{})
	if d2.Spec.Template.Annotations[render.AnnotationConfigHash] != hashBefore {
		t.Error("config hash changed without a spec change")
	}
	if string(get(t, c, render.SecretNginxAuth, &corev1.Secret{}).Data["htpasswd"]) != htBefore {
		t.Error("htpasswd was regenerated without a credential change")
	}
	gen2 := get(t, c, "malcolm-generated", &corev1.Secret{})
	if string(gen2.Data[keyPostgresPassword]) != string(gen.Data[keyPostgresPassword]) {
		t.Error("postgres password changed between reconciles")
	}
}

func TestAdoptsHelmGeneratedSecrets(t *testing.T) {
	helmValkey := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: render.SecretValkeyEnv, Namespace: ns},
		Data:       map[string][]byte{"VALKEY_PASSWORD": []byte("from-helm")},
	}
	helmPostgres := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: render.SecretPostgresEnv, Namespace: ns},
		Data:       map[string][]byte{"POSTGRES_PASSWORD": []byte("pg-from-helm")},
	}
	r, c := newReconciler(t, malcolm("malcolm", nil), helmValkey, helmPostgres)
	reconcileOnce(t, r, "malcolm")
	gen := get(t, c, "malcolm-generated", &corev1.Secret{})
	if string(gen.Data[keyValkeyPassword]) != "from-helm" || string(gen.Data[keyPostgresPassword]) != "pg-from-helm" {
		t.Errorf("did not adopt Helm passwords: %q %q", gen.Data[keyValkeyPassword], gen.Data[keyPostgresPassword])
	}
	nb := get(t, c, render.SecretNetBoxEnv, &corev1.Secret{})
	if string(nb.Data["VALKEY_PASSWORD"]) != "from-helm" {
		t.Error("netbox-secret-env should share the adopted valkey password")
	}
	// The adopted secret is now applied (and owned) by the operator.
	vk := get(t, c, render.SecretValkeyEnv, &corev1.Secret{})
	if metav1.GetControllerOf(vk) == nil || string(vk.Data["VALKEY_HOST"]) != "valkey" {
		t.Errorf("valkey-env not taken over: %+v", vk)
	}
}

func TestUserProvidedAdminCredentials(t *testing.T) {
	adminSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-admin", Namespace: ns},
		Data:       map[string][]byte{"username": []byte("analyst"), "password": []byte("correct horse")},
	}
	r, c := newReconciler(t, malcolm("malcolm", func(s *malcolmv1.MalcolmSpec) { s.Auth.AdminSecret = "my-admin" }), adminSecret)
	reconcileOnce(t, r, "malcolm")
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "malcolm-admin-credentials"}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Error("no admin secret should be generated when adminSecret is set")
	}
	auth := get(t, c, render.SecretNginxAuth, &corev1.Secret{})
	if !credentials.VerifyHtpasswd(string(auth.Data["htpasswd"]), "analyst", "correct horse") {
		t.Error("htpasswd does not match user-provided credentials")
	}
	gen := get(t, c, "malcolm-generated", &corev1.Secret{})
	if !credentials.VerifyMD5Crypt(string(gen.Data[keyAdminOpensslHash]), "correct horse") {
		t.Error("MD5-crypt hash does not match user-provided credentials")
	}

	// Changing the password re-hashes.
	adminSecret.Data["password"] = []byte("new password")
	if err := c.Update(context.Background(), adminSecret); err != nil {
		t.Fatal(err)
	}
	reconcileOnce(t, r, "malcolm")
	auth = get(t, c, render.SecretNginxAuth, &corev1.Secret{})
	if !credentials.VerifyHtpasswd(string(auth.Data["htpasswd"]), "analyst", "new password") {
		t.Error("htpasswd not updated after password change")
	}
}

func TestMissingSecretReportsError(t *testing.T) {
	r, c := newReconciler(t, malcolm("malcolm", func(s *malcolmv1.MalcolmSpec) {
		s.OpenSearch = malcolmv1.OpenSearchSpec{Mode: malcolmv1.OpenSearchModeElasticsearchRemote, URL: "https://es:9200", CredentialsSecret: "nope"}
	}))
	res := reconcileOnce(t, r, "malcolm")
	m := get(t, c, "malcolm", &malcolmv1.Malcolm{})
	if m.Status.Phase != PhaseError || res.RequeueAfter == 0 {
		t.Errorf("expected Error phase with requeue, got %q %v", m.Status.Phase, res)
	}
	if cond := findCondition(m, ConditionReady); cond == nil || cond.Reason != "MissingInput" {
		t.Errorf("unexpected Ready condition %+v", cond)
	}
}

func TestOnlyOneInstancePerNamespace(t *testing.T) {
	first := malcolm("first", nil)
	first.CreationTimestamp = metav1.NewTime(metav1.Now().Add(-3600e9))
	second := malcolm("second", nil)
	second.CreationTimestamp = metav1.Now()
	r, c := newReconciler(t, first, second)
	reconcileOnce(t, r, "second")
	m := get(t, c, "second", &malcolmv1.Malcolm{})
	if cond := findCondition(m, ConditionReady); cond == nil || cond.Reason != "DuplicateInstance" {
		t.Errorf("expected DuplicateInstance, got %+v", m.Status)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "logstash-deployment"}, &appsv1.Deployment{}); !apierrors.IsNotFound(err) {
		t.Error("the duplicate instance must not deploy anything")
	}
}

func TestPrunesDisabledComponents(t *testing.T) {
	m := malcolm("malcolm", func(s *malcolmv1.MalcolmSpec) { s.Auth.Mode = malcolmv1.AuthModeKeycloak })
	r, c := newReconciler(t, m)
	reconcileOnce(t, r, "malcolm")
	get(t, c, "keycloak-deployment", &appsv1.Deployment{})
	get(t, c, render.SecretKeycloakEnv, &corev1.Secret{})

	cur := get(t, c, "malcolm", &malcolmv1.Malcolm{})
	cur.Spec.Auth.Mode = malcolmv1.AuthModeBasic
	cur.Spec.Components = map[string]malcolmv1.ComponentSpec{"freq": {Enabled: ptr.To(false)}}
	if err := c.Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	reconcileOnce(t, r, "malcolm")
	for _, gone := range []client.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "keycloak-deployment"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "keycloak"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.SecretKeycloakEnv}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "freq-deployment"}},
	} {
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: gone.GetName()}, gone); !apierrors.IsNotFound(err) {
			t.Errorf("%T %s should have been pruned (err=%v)", gone, gone.GetName(), err)
		}
	}
	// Retained objects survive pruning.
	get(t, c, "malcolm-generated", &corev1.Secret{})
	get(t, c, render.ClaimPCAP, &corev1.PersistentVolumeClaim{})
}

func TestLogstashReplicasFollowNodeLabels(t *testing.T) {
	var objs []client.Object
	for i, label := range []string{"Tier-1", "Tier-1", "Tier-1", "Tier-1", "Tier-2"} {
		objs = append(objs, &corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: "node-" + string(rune('a'+i)), Labels: map[string]string{"cnaps.io/node-type": label},
		}})
	}
	r, c := newReconciler(t, append(objs, malcolm("malcolm", nil))...)
	reconcileOnce(t, r, "malcolm")
	if got := *get(t, c, "logstash-deployment", &appsv1.Deployment{}).Spec.Replicas; got != 2 {
		t.Errorf("logstash replicas = %d, want 2 for 4 Tier-1 nodes", got)
	}
}

func TestPVCImmutableFieldsPreserved(t *testing.T) {
	existing := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: render.ClaimPCAP, Namespace: ns},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: ptr.To("legacy"),
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
			Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: mustQty("500Gi")}},
		},
	}
	r, c := newReconciler(t, existing, malcolm("malcolm", func(s *malcolmv1.MalcolmSpec) {
		s.Storage.StorageClassName = ptr.To("new-class")
	}))
	reconcileOnce(t, r, "malcolm")
	pvc := get(t, c, render.ClaimPCAP, &corev1.PersistentVolumeClaim{})
	if *pvc.Spec.StorageClassName != "legacy" {
		t.Errorf("storage class changed to %q", *pvc.Spec.StorageClassName)
	}
	if q := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; q.String() != "500Gi" {
		t.Errorf("claim shrank to %s", q.String())
	}
}

func findCondition(m *malcolmv1.Malcolm, t string) *metav1.Condition {
	for i := range m.Status.Conditions {
		if m.Status.Conditions[i].Type == t {
			return &m.Status.Conditions[i]
		}
	}
	return nil
}

func mustQty(s string) resource.Quantity { return resource.MustParse(s) }

func TestBoundClaimGrowsOnlyWhenExpandable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expandable bool
		wantSize   string
		wantWarn   string
	}{
		{"expandable", true, "40Gi", ""},
		{"not expandable", false, "25Gi", "StorageClass standard does not allow volume expansion"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "standard"}, Provisioner: "x", AllowVolumeExpansion: ptr.To(tc.expandable)}
			pvc := &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{Name: render.ClaimPCAP, Namespace: ns},
				Spec: corev1.PersistentVolumeClaimSpec{
					StorageClassName: ptr.To("standard"),
					AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
					Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: mustQty("25Gi")}},
				},
				Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
			}
			r, c := newReconciler(t, sc, pvc, malcolm("malcolm", func(s *malcolmv1.MalcolmSpec) {
				s.Storage.PCAP.Size = ptr.To(mustQty("40Gi"))
			}))
			reconcileOnce(t, r, "malcolm")
			got := get(t, c, render.ClaimPCAP, &corev1.PersistentVolumeClaim{})
			if q := got.Spec.Resources.Requests[corev1.ResourceStorage]; q.String() != tc.wantSize {
				t.Errorf("size = %s, want %s", q.String(), tc.wantSize)
			}
			w := findCondition(get(t, c, "malcolm", &malcolmv1.Malcolm{}), ConditionWarning)
			switch {
			case tc.wantWarn == "" && w != nil && strings.Contains(w.Message, "pcap-claim"):
				t.Errorf("unexpected warning %q", w.Message)
			case tc.wantWarn != "" && (w == nil || !strings.Contains(w.Message, tc.wantWarn)):
				t.Errorf("expected warning containing %q, got %+v", tc.wantWarn, w)
			}
		})
	}
}

func TestRetentionFollowsSpec(t *testing.T) {
	r, c := newReconciler(t, malcolm("malcolm", nil))
	reconcileOnce(t, r, "malcolm")
	for _, n := range []string{"malcolm-generated", "malcolm-admin-credentials"} {
		if s := get(t, c, n, &corev1.Secret{}); metav1.GetControllerOf(s) != nil {
			t.Fatalf("%s should be retained by default", n)
		}
	}
	cur := get(t, c, "malcolm", &malcolmv1.Malcolm{})
	cur.Spec.Storage.RetainOnDelete = ptr.To(false)
	if err := c.Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	reconcileOnce(t, r, "malcolm")
	for _, n := range []string{"malcolm-generated", "malcolm-admin-credentials"} {
		s := get(t, c, n, &corev1.Secret{})
		if metav1.GetControllerOf(s) == nil || s.Annotations[render.AnnotationRetain] != "" {
			t.Errorf("%s should be owned once retainOnDelete is false: %+v", n, s.ObjectMeta)
		}
	}
	if p := get(t, c, render.ClaimPCAP, &corev1.PersistentVolumeClaim{}); metav1.GetControllerOf(p) == nil {
		t.Error("pcap-claim should be owned once retainOnDelete is false")
	}
	cur = get(t, c, "malcolm", &malcolmv1.Malcolm{})
	cur.Spec.Storage.RetainOnDelete = ptr.To(true)
	if err := c.Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	reconcileOnce(t, r, "malcolm")
	if s := get(t, c, "malcolm-generated", &corev1.Secret{}); metav1.GetControllerOf(s) != nil {
		t.Error("generated secret should be retained again")
	}
}

func externalPG(bootstrap bool, netboxCreds string) func(*malcolmv1.MalcolmSpec) {
	return func(s *malcolmv1.MalcolmSpec) {
		s.Postgres.Mode = malcolmv1.PostgresModeExternal
		s.Postgres.External = &malcolmv1.PostgresExternalSpec{Host: "pg.example.org",
			NetBox: malcolmv1.PostgresDatabaseSpec{CredentialsSecret: netboxCreds}}
		if bootstrap {
			s.Postgres.External.Bootstrap = &malcolmv1.PostgresBootstrapSpec{AdminCredentialsSecret: "pg-admin"}
		}
	}
}

func TestExternalPostgresInputs(t *testing.T) {
	nbCreds := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "nb", Namespace: ns},
		Data: map[string][]byte{"username": []byte("nbuser"), "password": []byte("nbpw")}}
	admin := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pg-admin", Namespace: ns},
		Data: map[string][]byte{"username": []byte("postgres"), "password": []byte("x")}}

	cases := []struct {
		name    string
		spec    func(*malcolmv1.MalcolmSpec)
		objs    []client.Object
		wantErr string
	}{
		{"no credentials and no bootstrap", externalPG(false, ""), nil, "postgres.external.netbox.credentialsSecret is required"},
		{"bootstrap secret missing", externalPG(true, ""), nil, "secret malcolm/pg-admin not found"},
		{"credentials only", externalPG(false, "nb"), []client.Object{nbCreds}, ""},
		{"bootstrap generates logins", externalPG(true, ""), []client.Object{admin}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, c := newReconciler(t, append(tc.objs, malcolm("malcolm", tc.spec))...)
			reconcileOnce(t, r, "malcolm")
			m := get(t, c, "malcolm", &malcolmv1.Malcolm{})
			cond := findCondition(m, ConditionReady)
			if tc.wantErr != "" {
				if m.Status.Phase != PhaseError || cond == nil || !strings.Contains(cond.Message, tc.wantErr) {
					t.Fatalf("expected error %q, got %q %+v", tc.wantErr, m.Status.Phase, cond)
				}
				return
			}
			if m.Status.Phase != PhaseProgressing {
				t.Fatalf("phase %q %+v", m.Status.Phase, cond)
			}
			env := get(t, c, render.SecretPostgresEnv, &corev1.Secret{}).Data
			if tc.name == "credentials only" && (string(env["POSTGRES_NETBOX_USER"]) != "nbuser" || string(env["POSTGRES_NETBOX_PASSWORD"]) != "nbpw") {
				t.Errorf("netbox login not taken from its Secret: %s/%s", env["POSTGRES_NETBOX_USER"], env["POSTGRES_NETBOX_PASSWORD"])
			}
			if tc.name == "bootstrap generates logins" && (string(env["POSTGRES_NETBOX_USER"]) != "netbox" || len(env["POSTGRES_NETBOX_PASSWORD"]) != 32) {
				t.Errorf("expected a generated netbox login, got %s", env["POSTGRES_NETBOX_USER"])
			}
		})
	}
}

func TestGeoIPUpdateRollsArkime(t *testing.T) {
	spec := func(s *malcolmv1.MalcolmSpec) {
		s.MaxMind = malcolmv1.MaxMindSpec{CredentialsSecret: "mm", Database: &malcolmv1.GeoIPDatabaseSpec{Enabled: true}}
	}
	mm := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "mm", Namespace: ns},
		Data: map[string][]byte{"accountID": []byte("1"), "licenseKey": []byte("k")}}
	r, c := newReconciler(t, mm, malcolm("malcolm", spec))
	reconcileOnce(t, r, "malcolm")
	ds := get(t, c, "arkime-live-daemonset", &appsv1.DaemonSet{})
	if a := ds.Spec.Template.Annotations[render.AnnotationGeoIPUpdated]; a != "" {
		t.Fatalf("no update has completed yet, got annotation %q", a)
	}

	// A Job started by the CronJob completes.
	done := metav1.NewTime(metav1.Now().Add(-time.Minute).Truncate(time.Second))
	labels := render.SelectorLabels("malcolm")
	labels[render.LabelComponent] = render.ComponentGeoIP
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "maxmind-geoip-update-123", Namespace: ns, Labels: labels},
		Status: batchv1.JobStatus{CompletionTime: &done, Conditions: []batchv1.JobCondition{
			{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
		}},
	}
	if err := c.Create(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	reconcileOnce(t, r, "malcolm")
	want := done.UTC().Format(time.RFC3339)
	for _, name := range []string{"arkime-live-daemonset", "arkime-deployment"} {
		var tmpl corev1.PodTemplateSpec
		if name == "arkime-deployment" {
			tmpl = get(t, c, name, &appsv1.Deployment{}).Spec.Template
		} else {
			tmpl = get(t, c, name, &appsv1.DaemonSet{}).Spec.Template
		}
		if got := tmpl.Annotations[render.AnnotationGeoIPUpdated]; got != want {
			t.Errorf("%s annotation = %q, want %q", name, got, want)
		}
	}
	if m := get(t, c, "malcolm", &malcolmv1.Malcolm{}); m.Status.GeoIPUpdated == nil || !m.Status.GeoIPUpdated.Equal(&done) {
		t.Errorf("status.geoIPUpdated = %v", m.Status.GeoIPUpdated)
	}
}
