package render

import (
	"sort"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// maxExclusionTerms bounds the node-affinity expansion for capture-node
// avoidance (only reachable with many multi-label capture selectors).
const maxExclusionTerms = 64

// serverPlacement applies spec.placement.server to the pod spec of a central
// service (Deployment, StatefulSet or Job). Component settings are applied
// afterwards and take precedence.
func (r *renderer) serverPlacement(ps *corev1.PodSpec) {
	p := r.spec.Placement.Server
	if len(p.NodeSelector) > 0 {
		if ps.NodeSelector == nil {
			ps.NodeSelector = map[string]string{}
		}
		for k, v := range p.NodeSelector {
			ps.NodeSelector[k] = v
		}
	}
	ps.Tolerations = append(ps.Tolerations, p.Tolerations...)
	if p.AvoidCaptureNodes && ps.Affinity == nil {
		if terms := r.captureExclusionTerms(); len(terms) > 0 {
			ps.Affinity = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: terms},
			}}
		}
	}
}

// captureSelectors returns the node selectors of every enabled capture DaemonSet.
func (r *renderer) captureSelectors() []map[string]string {
	var out []map[string]string
	if r.zeekLiveEnabled() {
		out = append(out, r.zeekSelector())
	}
	if r.zeekRemoteEnabled() {
		out = append(out, r.zeekRemoteSelector())
	}
	if r.suricataLiveEnabled() {
		out = append(out, r.suricataSelector())
	}
	if r.arkimeLiveEnabled() {
		out = append(out, selectorOrDefault(r.spec.Capture.Arkime.NodeSelector, defaultArkimeSelector))
	}
	if r.pcapCaptureEnabled() {
		out = append(out, selectorOrDefault(r.spec.Capture.PCAP.NodeSelector, defaultPCAPSelector))
	}
	return out
}

// captureExclusionTerms builds node-selector terms matching nodes that no
// capture selector matches. A node matches selector S when it carries every
// label of S, so "matches none" is AND over S of (OR over S's labels of
// "label differs"), expanded into the OR-of-ANDs form node affinity needs.
// NotIn also matches nodes that lack the label entirely.
func (r *renderer) captureExclusionTerms() []corev1.NodeSelectorTerm {
	terms := [][]corev1.NodeSelectorRequirement{{}}
	for _, sel := range r.captureSelectors() {
		if len(sel) == 0 {
			continue
		}
		var next [][]corev1.NodeSelectorRequirement
		for _, t := range terms {
			for _, k := range sortedKeys(sel) {
				req := corev1.NodeSelectorRequirement{Key: k, Operator: corev1.NodeSelectorOpNotIn, Values: []string{sel[k]}}
				next = append(next, append(append([]corev1.NodeSelectorRequirement{}, t...), req))
			}
		}
		if len(next) > maxExclusionTerms {
			r.warn("placement.server.avoidCaptureNodes: capture node selectors are too complex to exclude; use taints on capture nodes instead")
			return nil
		}
		terms = next
	}
	var out []corev1.NodeSelectorTerm
	seen := map[string]bool{}
	for _, t := range terms {
		merged := mergeNotIn(t)
		if len(merged) == 0 {
			continue
		}
		key := ""
		for _, req := range merged {
			key += req.Key + "=" + joinValues(req.Values) + ";"
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, corev1.NodeSelectorTerm{MatchExpressions: merged})
		}
	}
	return out
}

// mergeNotIn combines NotIn requirements on the same key, sorted by key.
func mergeNotIn(reqs []corev1.NodeSelectorRequirement) []corev1.NodeSelectorRequirement {
	values := map[string]map[string]bool{}
	for _, req := range reqs {
		if values[req.Key] == nil {
			values[req.Key] = map[string]bool{}
		}
		for _, v := range req.Values {
			values[req.Key][v] = true
		}
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]corev1.NodeSelectorRequirement, 0, len(keys))
	for _, k := range keys {
		vals := make([]string, 0, len(values[k]))
		for v := range values[k] {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		out = append(out, corev1.NodeSelectorRequirement{Key: k, Operator: corev1.NodeSelectorOpNotIn, Values: vals})
	}
	return out
}

func joinValues(v []string) string {
	s := ""
	for i, x := range v {
		if i > 0 {
			s += ","
		}
		s += x
	}
	return s
}

// job renders a run-to-completion Job. Job pod templates are immutable, so the
// name carries a digest of the inputs: a changed configuration creates a new
// Job and the old one is pruned.
func (r *renderer) job(component, baseName, digest string, spec corev1.PodSpec) *batchv1.Job {
	spec.RestartPolicy = corev1.RestartPolicyOnFailure
	r.serverPlacement(&spec)
	j := &batchv1.Job{
		TypeMeta:   metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{Name: baseName + "-" + digest, Namespace: r.ns, Labels: r.labels(component)},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr.To[int32](10),
			Template:     r.podTemplate(component, baseName, spec),
		},
	}
	r.add(j)
	return j
}

// cronJob renders a scheduled Job.
func (r *renderer) cronJob(component, name, schedule string, spec corev1.PodSpec) *batchv1.CronJob {
	spec.RestartPolicy = corev1.RestartPolicyOnFailure
	r.serverPlacement(&spec)
	c := &batchv1.CronJob{
		TypeMeta:   metav1.TypeMeta{APIVersion: "batch/v1", Kind: "CronJob"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.ns, Labels: r.labels(component)},
		Spec: batchv1.CronJobSpec{
			Schedule:                   schedule,
			ConcurrencyPolicy:          batchv1.ForbidConcurrent,
			SuccessfulJobsHistoryLimit: ptr.To[int32](3),
			FailedJobsHistoryLimit:     ptr.To[int32](3),
			JobTemplate: batchv1.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: r.labels(component)},
				Spec: batchv1.JobSpec{
					BackoffLimit: ptr.To[int32](4),
					Template:     r.podTemplate(component, name, spec),
				},
			},
		},
	}
	r.add(c)
	return c
}
