// Package controller implements the Malcolm reconciler.
package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
	"github.com/idaholab/malcolm-operator/internal/render"
)

// Condition types reported on Malcolm resources.
const (
	ConditionReady       = "Ready"
	ConditionProgressing = "Progressing"
	ConditionDegraded    = "Degraded"
	ConditionWarning     = "ConfigurationWarning"
)

// Phases reported in status.phase.
const (
	PhaseProgressing = "Progressing"
	PhaseReady       = "Ready"
	PhaseDegraded    = "Degraded"
	PhaseError       = "Error"
)

const (
	requeueNotReady = 30 * time.Second
	requeueResync   = 10 * time.Minute
)

// MalcolmReconciler reconciles Malcolm resources.
type MalcolmReconciler struct {
	client.Client
	// APIReader reads directly from the API server, for objects outside the
	// watched namespaces (the kubernetes Service, cross-namespace CA Secrets).
	APIReader client.Reader
	Scheme    *runtime.Scheme
}

func (r *MalcolmReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// +kubebuilder:rbac:groups=malcolm.idaholab.github.io,resources=malcolms,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=malcolm.idaholab.github.io,resources=malcolms/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=malcolm.idaholab.github.io,resources=malcolms/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps;secrets;services;persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:groups=storage.k8s.io,resources=storageclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=batch,resources=jobs;cronjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses;networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.istio.io,resources=virtualservices,verbs=get;list;watch;create;update;patch;delete

// Reconcile drives a Malcolm deployment towards its desired state.
func (r *MalcolmReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	m := &malcolmv1.Malcolm{}
	if err := r.Get(ctx, req.NamespacedName, m); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !m.DeletionTimestamp.IsZero() {
		// Owned objects are garbage collected; retained ones are kept on purpose.
		return ctrl.Result{}, nil
	}
	orig := m.Status.DeepCopy()

	if other, err := r.olderInstance(ctx, m); err != nil {
		return ctrl.Result{}, err
	} else if other != "" {
		r.setFailure(m, "DuplicateInstance", fmt.Sprintf(
			"Malcolm %q already manages namespace %s; only one Malcolm resource per namespace is supported", other, m.Namespace))
		return ctrl.Result{}, r.updateStatus(ctx, m, orig)
	}

	in, adminSecret, err := r.resolveInputs(ctx, m)
	if err != nil {
		if isMissingInput(err) {
			log.Info("waiting for referenced input", "reason", err.Error())
			r.setFailure(m, "MissingInput", err.Error())
			return ctrl.Result{RequeueAfter: requeueNotReady}, r.updateStatus(ctx, m, orig)
		}
		return ctrl.Result{}, err
	}

	// Render twice: first to discover user-provided objects consumed by pods,
	// then with their content hashes so edits to them roll the pods.
	res, err := render.Render(*in)
	if err != nil {
		r.setFailure(m, "RenderFailed", err.Error())
		return ctrl.Result{}, r.updateStatus(ctx, m, orig)
	}
	in.ExternalHashes = r.externalHashes(ctx, m.Namespace, res)
	if res, err = render.Render(*in); err != nil {
		r.setFailure(m, "RenderFailed", err.Error())
		return ctrl.Result{}, r.updateStatus(ctx, m, orig)
	}

	var applyErrs []string
	for _, obj := range res.Objects {
		warning, err := r.apply(ctx, m, obj)
		if err != nil {
			kind := obj.GetObjectKind().GroupVersionKind().Kind
			applyErrs = append(applyErrs, fmt.Sprintf("%s/%s: %v", kind, obj.GetName(), err))
		}
		if warning != "" {
			res.Warnings = append(res.Warnings, warning)
		}
	}
	if len(applyErrs) == 0 {
		keep := map[string]bool{GeneratedSecretName(m): true, AdminSecretName(m): true}
		if err := r.prune(ctx, m, res.Objects, keep); err != nil {
			applyErrs = append(applyErrs, err.Error())
		}
	}

	allReady, err := r.computeStatus(ctx, m, in, res, adminSecret)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(applyErrs) > 0 {
		msg := strings.Join(applyErrs, "; ")
		log.Error(errors.New(msg), "failed to apply some resources")
		m.Status.Phase = PhaseDegraded
		setCondition(m, ConditionDegraded, metav1.ConditionTrue, "ApplyFailed", msg)
		if err := r.updateStatus(ctx, m, orig); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, fmt.Errorf("applying resources: %s", msg)
	}
	setCondition(m, ConditionDegraded, metav1.ConditionFalse, "Applied", "all resources applied")
	if err := r.updateStatus(ctx, m, orig); err != nil {
		return ctrl.Result{}, err
	}
	if !allReady {
		return ctrl.Result{RequeueAfter: requeueNotReady}, nil
	}
	return ctrl.Result{RequeueAfter: requeueResync}, nil
}

// olderInstance returns the name of another Malcolm in the same namespace that
// takes precedence over m, if any.
func (r *MalcolmReconciler) olderInstance(ctx context.Context, m *malcolmv1.Malcolm) (string, error) {
	list := &malcolmv1.MalcolmList{}
	if err := r.List(ctx, list, client.InNamespace(m.Namespace)); err != nil {
		return "", err
	}
	for _, o := range list.Items {
		if o.UID == m.UID || !o.DeletionTimestamp.IsZero() {
			continue
		}
		if o.CreationTimestamp.Before(&m.CreationTimestamp) ||
			(o.CreationTimestamp.Equal(&m.CreationTimestamp) && o.Name < m.Name) {
			return o.Name, nil
		}
	}
	return "", nil
}

func setCondition(m *malcolmv1.Malcolm, t string, s metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&m.Status.Conditions, metav1.Condition{
		Type: t, Status: s, Reason: reason, Message: msg, ObservedGeneration: m.Generation,
	})
}

func (r *MalcolmReconciler) setFailure(m *malcolmv1.Malcolm, reason, msg string) {
	m.Status.Phase = PhaseError
	m.Status.ObservedGeneration = m.Generation
	setCondition(m, ConditionReady, metav1.ConditionFalse, reason, msg)
	setCondition(m, ConditionDegraded, metav1.ConditionTrue, reason, msg)
}

func (r *MalcolmReconciler) updateStatus(ctx context.Context, m *malcolmv1.Malcolm, orig *malcolmv1.MalcolmStatus) error {
	if apiequality.Semantic.DeepEqual(&m.Status, orig) {
		return nil
	}
	if err := r.Status().Update(ctx, m); err != nil {
		if apierrors.IsConflict(err) {
			return nil // a newer version will be reconciled
		}
		return err
	}
	return nil
}

// computeStatus fills status from the rendered workloads' current state.
func (r *MalcolmReconciler) computeStatus(ctx context.Context, m *malcolmv1.Malcolm, in *render.Inputs, res *render.Result, adminSecret string) (bool, error) {
	st := &m.Status
	st.ObservedGeneration = m.Generation
	st.Version = m.Spec.Version
	if st.Version == "" {
		st.Version = render.DefaultVersion
	}
	st.URL = res.URL
	st.AdminCredentialsSecret = adminSecret
	st.LogstashReplicas = 0
	st.GeoIPUpdated = nil
	if in.GeoIPUpdated != "" {
		if t, err := time.Parse(time.RFC3339, in.GeoIPUpdated); err == nil {
			st.GeoIPUpdated = &metav1.Time{Time: t}
		}
	}

	var comps []malcolmv1.ComponentStatus
	ready := 0
	for _, w := range res.Workloads {
		cs := malcolmv1.ComponentStatus{Name: w.Component, Kind: w.Kind}
		key := types.NamespacedName{Namespace: m.Namespace, Name: w.Name}
		switch w.Kind {
		case "Deployment":
			d := &appsv1.Deployment{}
			if err := r.Get(ctx, key, d); err != nil && !apierrors.IsNotFound(err) {
				return false, err
			}
			if d.Spec.Replicas != nil {
				cs.Desired = *d.Spec.Replicas
			}
			cs.Available = d.Status.AvailableReplicas
			cs.Ready = d.Status.ObservedGeneration >= d.Generation && d.Generation > 0 &&
				d.Status.UpdatedReplicas >= cs.Desired && cs.Available >= cs.Desired
			if w.Component == "logstash" {
				st.LogstashReplicas = cs.Desired
			}
		case "StatefulSet":
			s := &appsv1.StatefulSet{}
			if err := r.Get(ctx, key, s); err != nil && !apierrors.IsNotFound(err) {
				return false, err
			}
			if s.Spec.Replicas != nil {
				cs.Desired = *s.Spec.Replicas
			}
			cs.Available = s.Status.AvailableReplicas
			cs.Ready = s.Status.ObservedGeneration >= s.Generation && s.Generation > 0 &&
				s.Status.UpdatedReplicas >= cs.Desired && cs.Available >= cs.Desired
		case "DaemonSet":
			d := &appsv1.DaemonSet{}
			if err := r.Get(ctx, key, d); err != nil && !apierrors.IsNotFound(err) {
				return false, err
			}
			cs.Desired = d.Status.DesiredNumberScheduled
			cs.Available = d.Status.NumberAvailable
			cs.Ready = d.Status.ObservedGeneration >= d.Generation && d.Generation > 0 &&
				d.Status.UpdatedNumberScheduled >= cs.Desired && cs.Available >= cs.Desired
		}
		if cs.Ready {
			ready++
		}
		comps = append(comps, cs)
	}
	st.Components = comps
	st.ReadyComponents = fmt.Sprintf("%d/%d", ready, len(comps))

	allReady := ready == len(comps)
	if allReady {
		st.Phase = PhaseReady
		setCondition(m, ConditionReady, metav1.ConditionTrue, "AllComponentsReady", "all Malcolm components are available")
		setCondition(m, ConditionProgressing, metav1.ConditionFalse, "Stable", "deployment is up to date")
	} else {
		var waiting []string
		for _, c := range comps {
			if !c.Ready {
				waiting = append(waiting, c.Name)
			}
		}
		st.Phase = PhaseProgressing
		msg := "waiting for: " + strings.Join(waiting, ", ")
		setCondition(m, ConditionReady, metav1.ConditionFalse, "ComponentsNotReady", msg)
		setCondition(m, ConditionProgressing, metav1.ConditionTrue, "RollingOut", msg)
	}
	if len(res.Warnings) > 0 {
		setCondition(m, ConditionWarning, metav1.ConditionTrue, "Warnings", strings.Join(res.Warnings, "; "))
	} else {
		meta.RemoveStatusCondition(&m.Status.Conditions, ConditionWarning)
	}
	return allReady, nil
}

// SetupWithManager registers the controller and its watches.
func (r *MalcolmReconciler) SetupWithManager(mgr ctrl.Manager) error {
	inNamespace := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		return r.requestsFor(ctx, client.InNamespace(obj.GetNamespace()))
	})
	allInstances := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		return r.requestsFor(ctx)
	})
	return ctrl.NewControllerManagedBy(mgr).
		For(&malcolmv1.Malcolm{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&networkingv1.Ingress{}).
		Owns(&networkingv1.NetworkPolicy{}).
		// GeoIP updates: the CronJob's status changes when one of its Jobs succeeds.
		Owns(&batchv1.Job{}).
		Owns(&batchv1.CronJob{}).
		// Secrets/ConfigMaps referenced by name (credentials, custom rules, ...).
		Watches(&corev1.Secret{}, inNamespace).
		Watches(&corev1.ConfigMap{}, inNamespace, builder.WithPredicates(predicate.Funcs{
			// Owned ConfigMaps are handled by Owns(); avoid double work on our own writes.
			UpdateFunc: func(e event.UpdateEvent) bool { return metav1.GetControllerOf(e.ObjectNew) == nil },
		})).
		// Logstash sizing follows node labels.
		Watches(&corev1.Node{}, allInstances, builder.WithPredicates(predicate.Or(
			predicate.LabelChangedPredicate{},
			predicate.Funcs{
				CreateFunc: func(event.CreateEvent) bool { return true },
				DeleteFunc: func(event.DeleteEvent) bool { return true },
				UpdateFunc: func(event.UpdateEvent) bool { return false },
			},
		))).
		Named("malcolm").
		Complete(r)
}

func (r *MalcolmReconciler) requestsFor(ctx context.Context, opts ...client.ListOption) []reconcile.Request {
	list := &malcolmv1.MalcolmList{}
	if err := r.List(ctx, list, opts...); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for _, m := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: m.Namespace, Name: m.Name}})
	}
	return reqs
}
