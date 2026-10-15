package envtest

import (
	"context"
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
	"github.com/idaholab/malcolm-operator/internal/controller"
	"github.com/idaholab/malcolm-operator/internal/credentials"
	"github.com/idaholab/malcolm-operator/internal/render"
)

// eventually polls cond until it returns nil or the timeout expires.
func eventually(t *testing.T, what string, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = cond(); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", what, err)
}

// TestManagerEndToEnd runs the operator's real manager (caches, watches and
// predicates) and drives it only through API changes.
func TestManagerEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ns := "mal-e2e"
	createNamespace(t, ns)

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// Several managers run in this test binary; controller names are process-global.
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
		Cache:      cache.Options{DefaultNamespaces: map[string]cache.Config{ns: {}}},
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

	key := func(name string) types.NamespacedName { return types.NamespacedName{Namespace: ns, Name: name} }
	deployment := func(name string) (*appsv1.Deployment, error) {
		d := &appsv1.Deployment{}
		return d, k8s.Get(ctx, key(name), d)
	}

	// 1. Creating the resource deploys Malcolm and reports progress.
	if err := k8s.Create(ctx, &malcolmv1.Malcolm{ObjectMeta: metav1.ObjectMeta{Name: "malcolm", Namespace: ns}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "initial rollout", func() error {
		m := &malcolmv1.Malcolm{}
		if err := k8s.Get(ctx, key("malcolm"), m); err != nil {
			return err
		}
		if m.Status.Phase != controller.PhaseProgressing || m.Status.ReadyComponents != "0/27" {
			return fmt.Errorf("status %q %q", m.Status.Phase, m.Status.ReadyComponents)
		}
		_, err := deployment("nginx-proxy-deployment")
		return err
	})

	// 2. Labeling nodes rescales Logstash through the Node watch.
	for i := 0; i < 4; i++ {
		n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("e2e-node-%d", i), Labels: map[string]string{"cnaps.io/node-type": "Tier-1"}}}
		if err := k8s.Create(ctx, n); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = k8s.Delete(context.Background(), n) }()
	}
	eventually(t, "logstash to scale to 2", func() error {
		d, err := deployment("logstash-deployment")
		if err != nil {
			return err
		}
		if *d.Spec.Replicas != 2 {
			return fmt.Errorf("replicas %d", *d.Spec.Replicas)
		}
		return nil
	})

	// 3. Pointing at a user Secret, then editing it, re-hashes the login
	//    through the Malcolm and Secret watches.
	admin := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: ns},
		StringData: map[string]string{"username": "analyst", "password": "first"}}
	if err := k8s.Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	m := &malcolmv1.Malcolm{}
	if err := k8s.Get(ctx, key("malcolm"), m); err != nil {
		t.Fatal(err)
	}
	m.Spec.Auth.AdminSecret = "admin"
	if err := k8s.Update(ctx, m); err != nil {
		t.Fatal(err)
	}
	htpasswdMatches := func(user, pw string) func() error {
		return func() error {
			s := &corev1.Secret{}
			if err := k8s.Get(ctx, key(render.SecretNginxAuth), s); err != nil {
				return err
			}
			if !credentials.VerifyHtpasswd(string(s.Data["htpasswd"]), user, pw) {
				return fmt.Errorf("htpasswd does not match %s", user)
			}
			return nil
		}
	}
	eventually(t, "login from adminSecret", htpasswdMatches("analyst", "first"))
	ngx, _ := deployment("nginx-proxy-deployment")
	nginxHash := ngx.Spec.Template.Annotations[render.AnnotationConfigHash]
	if err := k8s.Get(ctx, key("admin"), admin); err != nil {
		t.Fatal(err)
	}
	admin.Data["password"] = []byte("second")
	if err := k8s.Update(ctx, admin); err != nil {
		t.Fatal(err)
	}
	eventually(t, "login re-hashed after password edit", htpasswdMatches("analyst", "second"))
	eventually(t, "nginx to roll", func() error {
		d, err := deployment("nginx-proxy-deployment")
		if err != nil {
			return err
		}
		if d.Spec.Template.Annotations[render.AnnotationConfigHash] == nginxHash {
			return fmt.Errorf("config hash unchanged")
		}
		return nil
	})

	// 4. Drift is corrected: a deleted ConfigMap and an edited image come back.
	if err := k8s.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "zeek-env", Namespace: ns}}); err != nil {
		t.Fatal(err)
	}
	d, _ := deployment("freq-deployment")
	want := d.Spec.Template.Spec.Containers[0].Image
	d.Spec.Template.Spec.Containers[0].Image = "example.org/tampered:1"
	if err := k8s.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	eventually(t, "drift correction", func() error {
		if err := k8s.Get(ctx, key("zeek-env"), &corev1.ConfigMap{}); err != nil {
			return err
		}
		d, err := deployment("freq-deployment")
		if err != nil {
			return err
		}
		if got := d.Spec.Template.Spec.Containers[0].Image; got != want {
			return fmt.Errorf("image %s", got)
		}
		return nil
	})

	// 5. Once every workload reports available, the instance becomes Ready.
	markAllAvailable(t, ctx, ns)
	eventually(t, "Ready phase", func() error {
		m := &malcolmv1.Malcolm{}
		if err := k8s.Get(ctx, key("malcolm"), m); err != nil {
			return err
		}
		c := meta.FindStatusCondition(m.Status.Conditions, controller.ConditionReady)
		if m.Status.Phase != controller.PhaseReady || c == nil || c.Status != metav1.ConditionTrue {
			// Status updates race with spec rollouts; keep workloads marked available.
			markAllAvailable(t, ctx, ns)
			return fmt.Errorf("phase %q ready %s", m.Status.Phase, m.Status.ReadyComponents)
		}
		return nil
	})
}

// markAllAvailable stands in for the kube-controller-manager, which envtest
// does not run, by reporting every workload as fully available.
func markAllAvailable(t *testing.T, ctx context.Context, ns string) {
	t.Helper()
	deps := &appsv1.DeploymentList{}
	stss := &appsv1.StatefulSetList{}
	dss := &appsv1.DaemonSetList{}
	for _, l := range []client.ObjectList{deps, stss, dss} {
		if err := k8s.List(ctx, l, client.InNamespace(ns)); err != nil {
			t.Fatal(err)
		}
	}
	update := func(o client.Object) {
		if err := k8s.Status().Update(ctx, o); err != nil && !apierrors.IsConflict(err) {
			t.Fatal(err)
		}
	}
	for i := range deps.Items {
		d := &deps.Items[i]
		n := *d.Spec.Replicas
		d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: n, UpdatedReplicas: n, ReadyReplicas: n, AvailableReplicas: n}
		update(d)
	}
	for i := range stss.Items {
		s := &stss.Items[i]
		n := *s.Spec.Replicas
		s.Status = appsv1.StatefulSetStatus{ObservedGeneration: s.Generation, Replicas: n, UpdatedReplicas: n, ReadyReplicas: n, AvailableReplicas: n, CurrentReplicas: n}
		update(s)
	}
	for i := range dss.Items {
		d := &dss.Items[i]
		d.Status = appsv1.DaemonSetStatus{ObservedGeneration: d.Generation, DesiredNumberScheduled: 1, CurrentNumberScheduled: 1,
			UpdatedNumberScheduled: 1, NumberReady: 1, NumberAvailable: 1}
		update(d)
	}
}
