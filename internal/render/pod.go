package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

// --- containers -----------------------------------------------------------

// rootSecurityContext: Malcolm entrypoints initialize as root and then drop
// privileges to PUID/PGID.
func rootSecurityContext(caps ...corev1.Capability) *corev1.SecurityContext {
	sc := &corev1.SecurityContext{RunAsUser: ptr.To[int64](0), RunAsGroup: ptr.To[int64](0)}
	if len(caps) > 0 {
		sc.Capabilities = &corev1.Capabilities{Add: caps}
	}
	return sc
}

func (r *renderer) container(name, image string, caps ...corev1.Capability) corev1.Container {
	return corev1.Container{
		Name:            name,
		Image:           r.image(image),
		ImagePullPolicy: r.pullPolicy(),
		Stdin:           false,
		TTY:             true,
		SecurityContext: rootSecurityContext(caps...),
	}
}

func healthProbe(initialDelay, period, timeout, failure int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{Command: []string{"/usr/local/bin/container_health.sh"}},
		},
		InitialDelaySeconds: initialDelay,
		PeriodSeconds:       period,
		TimeoutSeconds:      timeout,
		SuccessThreshold:    1,
		FailureThreshold:    failure,
	}
}

func tcpPort(name string, port int32) corev1.ContainerPort {
	return corev1.ContainerPort{Name: name, ContainerPort: port, Protocol: corev1.ProtocolTCP}
}

func cmEnv(name string) corev1.EnvFromSource {
	return corev1.EnvFromSource{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: name}}}
}

func secretEnv(name string) corev1.EnvFromSource {
	return corev1.EnvFromSource{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: name}}}
}

// envFrom builds an envFrom list. Names prefixed with "secret:" are Secrets.
// opensearch-env and dashboards-env are followed by the credential-bearing URL
// Secret when remote credentials are embedded in URLs (later sources win).
func (r *renderer) envFrom(names ...string) []corev1.EnvFromSource {
	var out []corev1.EnvFromSource
	needsURLSecret := false
	for _, n := range names {
		if name, ok := strings.CutPrefix(n, "secret:"); ok {
			out = append(out, secretEnv(name))
			continue
		}
		out = append(out, cmEnv(n))
		if n == "opensearch-env" || n == "dashboards-env" {
			needsURLSecret = needsURLSecret || r.embedCredentials()
		}
	}
	if needsURLSecret {
		out = append(out, secretEnv(SecretOpenSearchURLEnv))
	}
	return out
}

func envVal(name, value string) corev1.EnvVar { return corev1.EnvVar{Name: name, Value: value} }

func envField(name, path string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: path}}}
}

func envSecretKey(name, secret, key string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: secret}, Key: key,
	}}}
}

func nodeNameEnv() corev1.EnvVar { return envField("PCAP_NODE_NAME", "spec.nodeName") }

// adminUsernameEnv references the administrator username.
func (r *renderer) adminUsernameEnv() corev1.EnvVar {
	if r.usesGeneratedAdmin() {
		return envSecretKey("MALCOLM_USERNAME", SecretAuthEnv, "MALCOLM_USERNAME")
	}
	h := r.spec.Auth.HashedCredentials
	return envSecretKey("MALCOLM_USERNAME", h.SecretName, strDefault(h.UsernameKey, "username"))
}

func (r *renderer) adminPasswordEnv() corev1.EnvVar {
	if r.usesGeneratedAdmin() {
		return envSecretKey("MALCOLM_PASSWORD", SecretAuthEnv, "MALCOLM_PASSWORD")
	}
	h := r.spec.Auth.HashedCredentials
	return envSecretKey("MALCOLM_PASSWORD", h.SecretName, strDefault(h.OpensslPasswordKey, "openssl_password"))
}

// dirinit returns the init container that creates/chowns directories on volumes.
func (r *renderer) dirinit(name string, env []corev1.EnvVar, mounts ...corev1.VolumeMount) corev1.Container {
	c := r.container(name, "dirinit")
	c.EnvFrom = []corev1.EnvFromSource{cmEnv("process-env")}
	c.Env = env
	c.VolumeMounts = mounts
	return c
}

func mkdir(spec string) corev1.EnvVar { return envVal("PUSER_MKDIR", spec) }
func chown(spec string) corev1.EnvVar { return envVal("PUSER_CHOWN", spec) }
func pcopy(spec string) corev1.EnvVar { return envVal("PUSER_COPY", spec) }

// --- volumes ----------------------------------------------------------------

func mount(name, path string) corev1.VolumeMount {
	return corev1.VolumeMount{Name: name, MountPath: path}
}

func mountSub(name, path, sub string) corev1.VolumeMount {
	return corev1.VolumeMount{Name: name, MountPath: path, SubPath: sub}
}

func mountRO(m corev1.VolumeMount) corev1.VolumeMount { m.ReadOnly = true; return m }

func catrustMount() corev1.VolumeMount {
	return mount("var-local-catrust-volume", "/var/local/ca-trust/configmap")
}

func curlrcMount(volume string) corev1.VolumeMount {
	return mount(volume, "/var/local/curlrc/secretmap")
}

// catrustVolume holds the CA certificates every Malcolm container imports into
// its trust store. An imported data-store CA (opensearch.caCertificate) is
// added to it, so TLS verification works for all components, not just Arkime.
func (r *renderer) catrustVolume() corev1.Volume {
	if len(r.in.CACertificate) == 0 {
		return cmVolume("var-local-catrust-volume", r.caTrustConfigMap())
	}
	return corev1.Volume{Name: "var-local-catrust-volume", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
		Sources: []corev1.VolumeProjection{
			{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: r.caTrustConfigMap()}}},
			{Secret: &corev1.SecretProjection{
				LocalObjectReference: corev1.LocalObjectReference{Name: SecretRemoteCA},
				Items:                []corev1.KeyToPath{{Key: "elastic_ca.crt", Path: "opensearch-remote-ca.crt"}},
			}},
		},
	}}}
}

func cmVolume(name, cm string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
		LocalObjectReference: corev1.LocalObjectReference{Name: cm},
	}}}
}

func secretVolume(name, secret string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret}}}
}

func (r *renderer) pvcVolume(name, claim string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
		ClaimName: r.claimName(claim),
	}}}
}

func hostPathVolume(name, path string) corev1.Volume {
	t := corev1.HostPathDirectoryOrCreate
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path, Type: &t}}}
}

func emptyDirVolume(name, sizeLimit string) corev1.Volume {
	v := corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}
	if sizeLimit != "" {
		q := resource.MustParse(sizeLimit)
		v.EmptyDir.SizeLimit = &q
	}
	return v
}

func (r *renderer) curlrcVolume(name string) corev1.Volume { return secretVolume(name, SecretCurlrc) }

// --- workloads ----------------------------------------------------------------

// podTemplate builds a pod template for a workload with the given pod label.
func (r *renderer) podTemplate(component, podName string, spec corev1.PodSpec) corev1.PodTemplateSpec {
	labels := r.labels(component)
	labels[LabelPodName] = podName
	if len(r.spec.Image.PullSecrets) > 0 {
		spec.ImagePullSecrets = append(append([]corev1.LocalObjectReference{}, r.spec.Image.PullSecrets...), spec.ImagePullSecrets...)
	}
	t := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: spec}
	r.customizePod(component, &t)
	return t
}

func (r *renderer) deployment(component, name string, replicas int32, spec corev1.PodSpec) *appsv1.Deployment {
	if c := r.component(component); c.Replicas != nil {
		replicas = *c.Replicas
	}
	r.serverPlacement(&spec)
	d := &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.ns, Labels: r.labels(component)},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{LabelPodName: name}},
			Template: r.podTemplate(component, name, spec),
		},
	}
	r.add(d)
	r.workloads = append(r.workloads, Workload{Component: component, Kind: "Deployment", Name: name})
	return d
}

func (r *renderer) daemonSet(component, name string, spec corev1.PodSpec) *appsv1.DaemonSet {
	d := &appsv1.DaemonSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "DaemonSet"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.ns, Labels: r.labels(component)},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{LabelPodName: name}},
			Template: r.podTemplate(component, name, spec),
		},
	}
	r.add(d)
	r.workloads = append(r.workloads, Workload{Component: component, Kind: "DaemonSet", Name: name})
	return d
}

func (r *renderer) statefulSet(component, name, serviceName string, replicas int32, claims []corev1.PersistentVolumeClaim, spec corev1.PodSpec) *appsv1.StatefulSet {
	r.serverPlacement(&spec)
	s := &appsv1.StatefulSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "StatefulSet"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.ns, Labels: r.labels(component)},
		Spec: appsv1.StatefulSetSpec{
			Replicas:             ptr.To(replicas),
			ServiceName:          serviceName,
			Selector:             &metav1.LabelSelector{MatchLabels: map[string]string{LabelPodName: name}},
			Template:             r.podTemplate(component, name, spec),
			VolumeClaimTemplates: claims,
		},
	}
	if !r.retainOnDelete() {
		// Remove the per-replica claims along with the StatefulSet (scale-down keeps them).
		s.Spec.PersistentVolumeClaimRetentionPolicy = &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{
			WhenDeleted: appsv1.DeletePersistentVolumeClaimRetentionPolicyType,
			WhenScaled:  appsv1.RetainPersistentVolumeClaimRetentionPolicyType,
		}
	}
	r.add(s)
	r.workloads = append(r.workloads, Workload{Component: component, Kind: "StatefulSet", Name: name})
	return s
}

type svcPort struct {
	name       string
	port       int32
	targetPort int32
}

func (r *renderer) service(component, name, selector string, ports ...svcPort) *corev1.Service {
	s := &corev1.Service{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.ns, Labels: r.labels(component)},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{LabelPodName: selector},
		},
	}
	for _, p := range ports {
		sp := corev1.ServicePort{Name: p.name, Port: p.port, Protocol: corev1.ProtocolTCP}
		if p.targetPort != 0 {
			sp.TargetPort = intstr.FromInt32(p.targetPort)
		}
		s.Spec.Ports = append(s.Spec.Ports, sp)
	}
	r.add(s)
	return s
}

// --- per-component customization ------------------------------------------

// customizePod applies spec.components[component] to a pod template. The first
// container is the component's main container.
func (r *renderer) customizePod(component string, t *corev1.PodTemplateSpec) {
	c, ok := r.spec.Components[component]
	if !ok {
		return
	}
	ps := &t.Spec
	r.customizeImages(component, c, ps)
	if len(ps.Containers) > 0 {
		main := &ps.Containers[0]
		if c.Resources != nil {
			main.Resources = *c.Resources
		}
		main.Env = append(main.Env, c.ExtraEnv...)
		if len(c.ExtraEnvFrom) > 0 {
			main.EnvFrom = append(append([]corev1.EnvFromSource{}, c.ExtraEnvFrom...), main.EnvFrom...)
		}
		main.VolumeMounts = append(main.VolumeMounts, c.ExtraVolumeMounts...)
	}
	for i := range ps.Containers {
		if res, ok := c.ContainerResources[ps.Containers[i].Name]; ok {
			ps.Containers[i].Resources = res
		}
	}
	for i := range ps.InitContainers {
		if res, ok := c.ContainerResources[ps.InitContainers[i].Name]; ok {
			ps.InitContainers[i].Resources = res
		}
	}
	if len(c.NodeSelector) > 0 {
		if ps.NodeSelector == nil {
			ps.NodeSelector = map[string]string{}
		}
		for k, v := range c.NodeSelector {
			ps.NodeSelector[k] = v
		}
	}
	ps.Tolerations = append(ps.Tolerations, c.Tolerations...)
	if c.Affinity != nil {
		ps.Affinity = c.Affinity
	}
	if c.PriorityClassName != "" {
		ps.PriorityClassName = c.PriorityClassName
	}
	if c.ServiceAccountName != "" {
		ps.ServiceAccountName = c.ServiceAccountName
	}
	volumes, err := decodeRaw[corev1.Volume](c.ExtraVolumes)
	if err != nil {
		r.fail("components[%s].extraVolumes: %v", component, err)
	}
	ps.Volumes = append(ps.Volumes, volumes...)
	sidecars, err := decodeRaw[corev1.Container](c.Sidecars)
	if err != nil {
		r.fail("components[%s].sidecars: %v", component, err)
	}
	ps.Containers = append(ps.Containers, sidecars...)
	inits, err := decodeRaw[corev1.Container](c.InitContainers)
	if err != nil {
		r.fail("components[%s].initContainers: %v", component, err)
	}
	if len(inits) > 0 {
		ps.InitContainers = append(inits, ps.InitContainers...)
	}
	for k, v := range c.PodLabels {
		if k == LabelPodName {
			continue // the selector label cannot be changed
		}
		if t.Labels == nil {
			t.Labels = map[string]string{}
		}
		t.Labels[k] = v
	}
	if len(c.PodAnnotations) > 0 {
		if t.Annotations == nil {
			t.Annotations = map[string]string{}
		}
		for k, v := range c.PodAnnotations {
			t.Annotations[k] = v
		}
	}
}

// customizeImages applies a component's image settings to the containers the
// operator renders (before user sidecars and init containers are added):
// containerImages[container] > image (main container) > spec.image.overrides.
func (r *renderer) customizeImages(component string, c malcolmv1.ComponentSpec, ps *corev1.PodSpec) {
	if len(ps.Containers) > 0 && c.Image != "" {
		ps.Containers[0].Image = string(c.Image)
	}
	known := map[string]bool{}
	for _, list := range [][]corev1.Container{ps.Containers, ps.InitContainers} {
		for i := range list {
			ctr := &list[i]
			known[ctr.Name] = true
			if img, ok := c.ContainerImages[ctr.Name]; ok {
				ctr.Image = string(img)
			}
			if c.ImagePullPolicy != "" {
				ctr.ImagePullPolicy = c.ImagePullPolicy
			}
		}
	}
	for _, name := range sortedImageKeys(c.ContainerImages) {
		if !known[name] {
			r.warn("components[%s].containerImages: no container named %q (containers: %s)",
				component, name, strings.Join(sortedBoolKeys(known), ", "))
		}
	}
}

func sortedImageKeys(m map[string]malcolmv1.ImageReference) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedBoolKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// decodeRaw strictly decodes user-supplied raw objects (sidecars, init
// containers, volumes), rejecting unknown fields since the CRD schema does not
// validate them.
func decodeRaw[T any](raw []runtime.RawExtension) ([]T, error) {
	out := make([]T, 0, len(raw))
	for i, r := range raw {
		var v T
		dec := json.NewDecoder(bytes.NewReader(r.Raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// instrumentCoverage adds coverage env/mounts to sidecars (all containers after
// the first) of components that the Helm chart instrumented.
func (r *renderer) instrumentCoverage(ps *corev1.PodSpec, userSidecars int) {
	if !r.coverageEnabled() || userSidecars == 0 {
		return
	}
	start := len(ps.Containers) - userSidecars
	for i := start; i < len(ps.Containers); i++ {
		c := &ps.Containers[i]
		c.Env = append(c.Env, envVal("COVERAGE_PROCESS_START", "/etc/coverage/.coveragerc"))
		c.VolumeMounts = append(c.VolumeMounts, mount("coverage-config-volume", "/etc/coverage"))
	}
	ps.Volumes = append(ps.Volumes, cmVolume("coverage-config-volume", r.coverageConfigMapName()))
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
