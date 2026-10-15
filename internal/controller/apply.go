package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
	"github.com/idaholab/malcolm-operator/internal/render"
)

// FieldOwner is the server-side apply field manager used by the operator.
const FieldOwner = "malcolm-operator"

// toApplyUnstructured converts a typed object into an unstructured apply
// configuration, dropping fields that must not be part of an apply request.
func (r *MalcolmReconciler) toApplyUnstructured(obj client.Object) (*unstructured.Unstructured, error) {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u.DeepCopy(), nil
	}
	gvk, err := r.gvkFor(obj)
	if err != nil {
		return nil, err
	}
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	delete(m, "status")
	pruneNullTimestamps(m)
	u := &unstructured.Unstructured{Object: m}
	u.SetGroupVersionKind(gvk)
	return u, nil
}

func (r *MalcolmReconciler) gvkFor(obj client.Object) (schema.GroupVersionKind, error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	if !gvk.Empty() {
		return gvk, nil
	}
	gvks, _, err := r.Scheme.ObjectKinds(obj)
	if err != nil || len(gvks) == 0 {
		return schema.GroupVersionKind{}, fmt.Errorf("unknown kind for %T: %w", obj, err)
	}
	return gvks[0], nil
}

// pruneNullTimestamps removes "creationTimestamp": null entries that typed
// objects serialize, which would otherwise claim ownership of the field.
func pruneNullTimestamps(v any) {
	switch t := v.(type) {
	case map[string]any:
		if ts, ok := t["creationTimestamp"]; ok && ts == nil {
			delete(t, "creationTimestamp")
		}
		for _, child := range t {
			pruneNullTimestamps(child)
		}
	case []any:
		for _, child := range t {
			pruneNullTimestamps(child)
		}
	}
}

// prepare adjusts a desired object before apply: owner reference, and
// preservation of immutable fields of existing objects. It returns a warning
// when part of the desired state cannot be applied.
func (r *MalcolmReconciler) prepare(ctx context.Context, m *malcolmv1.Malcolm, obj client.Object) (string, error) {
	retained := obj.GetAnnotations()[render.AnnotationRetain] == "true"
	if !retained {
		if err := controllerutil.SetControllerReference(m, obj, r.Scheme); err != nil {
			return "", err
		}
	}
	switch desired := obj.(type) {
	case *corev1.PersistentVolumeClaim:
		existing := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing); err != nil {
			if apierrors.IsNotFound(err) {
				return "", nil
			}
			return "", err
		}
		// Only the requested size can change after creation, and only upwards.
		desired.Spec.StorageClassName = existing.Spec.StorageClassName
		desired.Spec.AccessModes = existing.Spec.AccessModes
		desired.Spec.VolumeMode = existing.Spec.VolumeMode
		desired.Spec.Selector = existing.Spec.Selector
		desired.Spec.VolumeName = existing.Spec.VolumeName
		want := desired.Spec.Resources.Requests[corev1.ResourceStorage]
		have := existing.Spec.Resources.Requests[corev1.ResourceStorage]
		switch want.Cmp(have) {
		case -1:
			desired.Spec.Resources.Requests[corev1.ResourceStorage] = have
			return fmt.Sprintf("PersistentVolumeClaim %s cannot shrink from %s to %s", desired.Name, have.String(), want.String()), nil
		case 1:
			reason, err := r.expansionBlocker(ctx, existing)
			if err != nil {
				return "", err
			}
			if reason != "" {
				desired.Spec.Resources.Requests[corev1.ResourceStorage] = have
				return fmt.Sprintf("PersistentVolumeClaim %s cannot grow to %s: %s", desired.Name, want.String(), reason), nil
			}
		}
	case *appsv1.StatefulSet:
		existing := &appsv1.StatefulSet{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing); err != nil {
			if apierrors.IsNotFound(err) {
				return "", nil
			}
			return "", err
		}
		// volumeClaimTemplates (and the selector/serviceName) are immutable.
		warning := ""
		if changed := claimTemplatesDiffer(desired.Spec.VolumeClaimTemplates, existing.Spec.VolumeClaimTemplates); changed != "" {
			warning = fmt.Sprintf("StatefulSet %s volume claim templates are immutable (%s changed); resize its PersistentVolumeClaims directly", desired.Name, changed)
		}
		desired.Spec.VolumeClaimTemplates = existing.Spec.VolumeClaimTemplates
		desired.Spec.Selector = existing.Spec.Selector
		desired.Spec.ServiceName = existing.Spec.ServiceName
		return warning, nil
	}
	return "", nil
}

// expansionBlocker explains why an existing claim cannot be expanded, or
// returns "" when it can.
func (r *MalcolmReconciler) expansionBlocker(ctx context.Context, pvc *corev1.PersistentVolumeClaim) (string, error) {
	if pvc.Status.Phase != corev1.ClaimBound {
		return "the claim is not bound yet", nil
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName == "" {
		return "it has no StorageClass", nil
	}
	sc := &storagev1.StorageClass{}
	if err := r.Get(ctx, client.ObjectKey{Name: *pvc.Spec.StorageClassName}, sc); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Sprintf("StorageClass %s not found", *pvc.Spec.StorageClassName), nil
		}
		return "", err
	}
	if sc.AllowVolumeExpansion == nil || !*sc.AllowVolumeExpansion {
		return fmt.Sprintf("StorageClass %s does not allow volume expansion", sc.Name), nil
	}
	return "", nil
}

func claimTemplatesDiffer(desired, existing []corev1.PersistentVolumeClaim) string {
	have := map[string]corev1.PersistentVolumeClaim{}
	for _, c := range existing {
		have[c.Name] = c
	}
	for _, d := range desired {
		e, ok := have[d.Name]
		if !ok {
			return d.Name
		}
		dq, eq := d.Spec.Resources.Requests[corev1.ResourceStorage], e.Spec.Resources.Requests[corev1.ResourceStorage]
		if dq.Cmp(eq) != 0 || !apiequality.Semantic.DeepEqual(d.Spec.StorageClassName, e.Spec.StorageClassName) {
			return d.Name
		}
	}
	return ""
}

func (r *MalcolmReconciler) apply(ctx context.Context, m *malcolmv1.Malcolm, obj client.Object) (string, error) {
	warning, err := r.prepare(ctx, m, obj)
	if err != nil {
		return "", err
	}
	u, err := r.toApplyUnstructured(obj)
	if err != nil {
		return "", err
	}
	if _, isUnstructured := obj.(*unstructured.Unstructured); isUnstructured && obj.GetAnnotations()[render.AnnotationRetain] != "true" {
		if err := controllerutil.SetControllerReference(m, u, r.Scheme); err != nil {
			return "", err
		}
	}
	return warning, r.Apply(ctx, client.ApplyConfigurationFromUnstructured(u), client.FieldOwner(FieldOwner), client.ForceOwnership)
}

// prunableKinds are the kinds the operator deletes when they are no longer desired.
func (r *MalcolmReconciler) prunableKinds(istio bool) []client.ObjectList {
	lists := []client.ObjectList{
		&corev1.ConfigMapList{},
		&corev1.SecretList{},
		&corev1.ServiceList{},
		&appsv1.DeploymentList{},
		&appsv1.StatefulSetList{},
		&appsv1.DaemonSetList{},
		&networkingv1.IngressList{},
		&networkingv1.NetworkPolicyList{},
		&batchv1.JobList{},
		&batchv1.CronJobList{},
	}
	if istio {
		vs := &unstructured.UnstructuredList{}
		vs.SetGroupVersionKind(schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1beta1", Kind: "VirtualServiceList"})
		lists = append(lists, vs)
	}
	return lists
}

// prune deletes objects owned by this Malcolm instance that are no longer desired.
func (r *MalcolmReconciler) prune(ctx context.Context, m *malcolmv1.Malcolm, desired []client.Object, keep map[string]bool) error {
	want := map[string]bool{}
	for _, o := range desired {
		gvk, err := r.gvkFor(o)
		if err != nil {
			return err
		}
		want[gvk.Kind+"/"+o.GetName()] = true
	}
	istio := r.hasKind(schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1beta1", Kind: "VirtualService"})
	var errs []string
	for _, list := range r.prunableKinds(istio) {
		if err := r.List(ctx, list, client.InNamespace(m.Namespace), client.MatchingLabels(render.SelectorLabels(m.Name))); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			errs = append(errs, err.Error())
			continue
		}
		items, err := listItems(list)
		if err != nil {
			return err
		}
		for _, obj := range items {
			gvk, err := r.gvkFor(obj)
			if err != nil {
				return err
			}
			if want[gvk.Kind+"/"+obj.GetName()] || keep[obj.GetName()] || !isControlledBy(obj, m.UID) {
				continue
			}
			if err := r.Delete(ctx, obj, client.PropagationPolicy("Background")); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("pruning: %s", strings.Join(errs, "; "))
	}
	return nil
}

func listItems(list client.ObjectList) ([]client.Object, error) {
	objs, err := meta.ExtractList(list)
	if err != nil {
		return nil, err
	}
	out := make([]client.Object, 0, len(objs))
	for _, o := range objs {
		co, ok := o.(client.Object)
		if !ok {
			return nil, fmt.Errorf("unexpected list item type %T", o)
		}
		out = append(out, co)
	}
	return out, nil
}

func isControlledBy(obj client.Object, uid types.UID) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller && ref.UID == uid {
			return true
		}
	}
	return false
}

func podSpecOf(o client.Object) *corev1.PodSpec {
	switch w := o.(type) {
	case *appsv1.Deployment:
		return &w.Spec.Template.Spec
	case *appsv1.StatefulSet:
		return &w.Spec.Template.Spec
	case *appsv1.DaemonSet:
		return &w.Spec.Template.Spec
	}
	return nil
}

func cutString(s, sep string) (string, string, bool) { return strings.Cut(s, sep) }

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedByteKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
