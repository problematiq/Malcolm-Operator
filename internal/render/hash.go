package render

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// applyConfigHashes stamps every workload's pod template with a hash of the
// ConfigMaps and Secrets it consumes, so pods restart when their configuration
// changes (envFrom-sourced variables are otherwise only read at start-up).
func (r *renderer) applyConfigHashes() {
	data := map[string]string{}
	for _, o := range r.objects {
		switch obj := o.(type) {
		case *corev1.ConfigMap:
			data["configmap/"+obj.Name] = hashStringMap(obj.Data)
		case *corev1.Secret:
			m := make(map[string]string, len(obj.Data))
			for k, v := range obj.Data {
				m[k] = string(v)
			}
			data["secret/"+obj.Name] = hashStringMap(m)
		}
	}
	for k, v := range r.in.ExternalHashes {
		if _, ok := data[k]; !ok {
			data[k] = v
		}
	}

	for _, o := range r.objects {
		var tmpl *corev1.PodTemplateSpec
		switch w := o.(type) {
		case *appsv1.Deployment:
			tmpl = &w.Spec.Template
		case *appsv1.StatefulSet:
			tmpl = &w.Spec.Template
		case *appsv1.DaemonSet:
			tmpl = &w.Spec.Template
		default:
			continue
		}
		refs := PodConfigReferences(&tmpl.Spec)
		h := sha256.New()
		for _, ref := range refs {
			h.Write([]byte(ref))
			h.Write([]byte{0})
			h.Write([]byte(data[ref]))
			h.Write([]byte{0})
		}
		if tmpl.Annotations == nil {
			tmpl.Annotations = map[string]string{}
		}
		tmpl.Annotations[AnnotationConfigHash] = hex.EncodeToString(h.Sum(nil))[:16]
	}
}

// PodConfigReferences lists the "configmap/<name>" and "secret/<name>" objects a
// pod spec consumes through envFrom, env valueFrom, and volumes, sorted.
func PodConfigReferences(ps *corev1.PodSpec) []string {
	set := map[string]struct{}{}
	add := func(kind, name string) {
		if name != "" {
			set[kind+"/"+name] = struct{}{}
		}
	}
	containers := append(append([]corev1.Container{}, ps.InitContainers...), ps.Containers...)
	for _, c := range containers {
		for _, ef := range c.EnvFrom {
			if ef.ConfigMapRef != nil {
				add("configmap", ef.ConfigMapRef.Name)
			}
			if ef.SecretRef != nil {
				add("secret", ef.SecretRef.Name)
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom == nil {
				continue
			}
			if e.ValueFrom.ConfigMapKeyRef != nil {
				add("configmap", e.ValueFrom.ConfigMapKeyRef.Name)
			}
			if e.ValueFrom.SecretKeyRef != nil {
				add("secret", e.ValueFrom.SecretKeyRef.Name)
			}
		}
	}
	for _, v := range ps.Volumes {
		if v.ConfigMap != nil {
			add("configmap", v.ConfigMap.Name)
		}
		if v.Secret != nil {
			add("secret", v.Secret.SecretName)
		}
		if v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.ConfigMap != nil {
					add("configmap", s.ConfigMap.Name)
				}
				if s.Secret != nil {
					add("secret", s.Secret.Name)
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hashStringMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(m[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
