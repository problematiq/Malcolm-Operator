// Package render turns a Malcolm custom resource (plus a few values resolved
// from the cluster) into the complete set of Kubernetes objects that make up a
// Malcolm deployment. It is pure: it performs no API calls, which keeps it
// deterministic and easy to unit test.
package render

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

// Label and annotation keys applied by the operator.
const (
	LabelName      = "app.kubernetes.io/name"
	LabelInstance  = "app.kubernetes.io/instance"
	LabelComponent = "app.kubernetes.io/component"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelPartOf    = "app.kubernetes.io/part-of"
	LabelVersion   = "app.kubernetes.io/version"

	// LabelPodName is the pod selector label used by the Malcolm Helm chart and
	// manifests. Keeping it allows the operator to adopt Helm-created workloads.
	LabelPodName = "name"

	ManagedByValue = "malcolm-operator"

	AnnotationConfigHash = "malcolm.idaholab.github.io/config-hash"
	// AnnotationRetain marks objects that survive deletion of the Malcolm
	// resource (no owner reference is set on them).
	AnnotationRetain = "malcolm.idaholab.github.io/retain"
)

// Credentials is a username/password pair.
type Credentials struct {
	Username string
	Password string
}

// Secrets carries every secret value the rendered objects need, already
// resolved by the controller from user-supplied Secrets or generated values.
type Secrets struct {
	// Administrator credentials (only used when auth.hashedCredentials is unset).
	AdminUsername    string
	AdminOpensslHash string // $1$... (MD5-crypt)
	AdminHtpasswd    string // username:$2y$...

	ValkeyPassword          string
	ValkeyRemotePassword    string
	NetBoxSecretKey         string
	NetBoxAPIToken          string
	NetBoxSuperuserPassword string
	NetBoxRemoteToken       string
	FilescanKey             string
	PostgresPassword        string
	// Application logins for an external PostgreSQL server (default: the
	// users "netbox"/"keycloak" with PostgresPassword).
	PostgresNetBoxUser       string
	PostgresNetBoxPassword   string
	PostgresKeycloakUser     string
	PostgresKeycloakPassword string
	ArkimePassword           string
	ArkimeWisePIN            string
	OTKBToken                string
	KeycloakClientSecret     string
	KeycloakAdminUsername    string
	KeycloakAdminPassword    string
	MaxMindAccountID         string
	MaxMindLicenseKey        string
	LDAPConfig               string
}

// Inputs is everything Render needs.
type Inputs struct {
	Malcolm *malcolmv1.Malcolm
	Secrets Secrets

	// PrimaryCredentials/SecondaryCredentials for remote data stores.
	PrimaryCredentials   *Credentials
	SecondaryCredentials *Credentials
	// CACertificate is the PEM data copied from opensearch.caCertificate.
	CACertificate []byte

	// LogstashReplicas is the replica count to use when spec.logstash.replicas is unset.
	LogstashReplicas int32
	// KubernetesAPIAddresses are the IPs of the kubernetes API service and endpoints
	// (used by the network policy that lets Malcolm reach the API server).
	KubernetesAPIAddresses []string
	// IstioAvailable reports whether the VirtualService CRD exists.
	IstioAvailable bool
	// GeoIPUpdated is when the shared GeoIP database was last updated
	// successfully (RFC 3339), used to roll Arkime pods after updates.
	GeoIPUpdated string
	// ExternalHashes maps "configmap/<name>" or "secret/<name>" of user-provided
	// objects consumed by pods to a hash of their content, so that changes to
	// them roll the consuming pods.
	ExternalHashes map[string]string
}

// Workload identifies a rendered workload for status reporting.
type Workload struct {
	Component string
	Kind      string
	Name      string
}

// Result is the output of Render.
type Result struct {
	Objects   []client.Object
	Workloads []Workload
	URL       string
	Warnings  []string
}

// Render produces the desired objects for a Malcolm resource.
func Render(in Inputs) (*Result, error) {
	if in.Malcolm == nil {
		return nil, fmt.Errorf("no Malcolm resource given")
	}
	r := newRenderer(in)
	if err := r.run(); err != nil {
		return nil, err
	}
	return r.result(), nil
}

type renderer struct {
	in        Inputs
	m         *malcolmv1.Malcolm
	spec      *malcolmv1.MalcolmSpec
	ns        string
	profile   malcolmv1.Profile
	tun       profileTunables
	version   string
	env       map[string]map[string]string // stem -> final env
	objects   []client.Object
	workloads []Workload
	warnings  []string
	errs      []string
	url       string
}

func newRenderer(in Inputs) *renderer {
	m := in.Malcolm
	profile := m.Spec.Profile
	if profile == "" {
		profile = malcolmv1.ProfileDevelopment
	}
	version := m.Spec.Version
	if version == "" {
		version = DefaultVersion
	}
	return &renderer{
		in:      in,
		m:       m,
		spec:    &m.Spec,
		ns:      m.Namespace,
		profile: profile,
		tun:     tunables[profile],
		version: version,
	}
}

func (r *renderer) run() error {
	r.computeEnv()
	r.renderConfigMaps()
	r.renderSecrets()
	r.renderStorage()
	r.renderGeoIP()
	r.renderCoreWorkloads()
	r.renderArkimeApps()
	r.renderPostgresBootstrap()
	r.renderCaptureWorkloads()
	r.renderNetworking()
	r.applyConfigHashes()
	if len(r.errs) > 0 {
		return fmt.Errorf("invalid spec: %s", strings.Join(r.errs, "; "))
	}
	return nil
}

func (r *renderer) result() *Result {
	sort.SliceStable(r.workloads, func(i, j int) bool { return r.workloads[i].Name < r.workloads[j].Name })
	return &Result{Objects: r.objects, Workloads: r.workloads, URL: r.url, Warnings: r.warnings}
}

func (r *renderer) add(objs ...client.Object) {
	r.objects = append(r.objects, objs...)
}

func (r *renderer) fail(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func (r *renderer) warn(format string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
}

// Labels returns the common labels for an object of the given component.
func (r *renderer) labels(component string) map[string]string {
	return Labels(r.m.Name, component, r.version)
}

// Labels returns the common labels for an object of the given component.
func Labels(instance, component, version string) map[string]string {
	l := map[string]string{
		LabelName:      "malcolm",
		LabelInstance:  instance,
		LabelManagedBy: ManagedByValue,
		LabelPartOf:    "malcolm",
	}
	if component != "" {
		l[LabelComponent] = component
	}
	if version != "" {
		l[LabelVersion] = sanitizeLabelValue(version)
	}
	return l
}

// SelectorLabels selects every object of an instance (used for pruning).
func SelectorLabels(instance string) map[string]string {
	return map[string]string{LabelInstance: instance, LabelManagedBy: ManagedByValue}
}

func sanitizeLabelValue(v string) string {
	if len(v) > 63 {
		v = v[:63]
	}
	return v
}

// --- small helpers -------------------------------------------------------

func boolDefault(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

func int32Default(v *int32, def int32) int32 {
	if v == nil {
		return def
	}
	return *v
}

func strDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func listDefault(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

func btoa(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func (r *renderer) component(name string) malcolmv1.ComponentSpec {
	if r.spec.Components == nil {
		return malcolmv1.ComponentSpec{}
	}
	return r.spec.Components[name]
}

// componentEnabled reports whether a component was not switched off via
// spec.components[name].enabled.
func (r *renderer) componentEnabled(name string) bool {
	return boolDefault(r.component(name).Enabled, true)
}

func (r *renderer) pullPolicy() corev1.PullPolicy {
	if r.spec.Image.PullPolicy == "" {
		return corev1.PullIfNotPresent
	}
	return r.spec.Image.PullPolicy
}

// image returns the reference for a Malcolm image name (e.g. "zeek").
func (r *renderer) image(name string) string {
	if o, ok := r.spec.Image.Overrides[name]; ok && o != "" {
		return o
	}
	return fmt.Sprintf("%s/%s:%s", strDefault(r.spec.Image.Repository, DefaultImageRepository), name, r.version)
}

// --- feature switches ----------------------------------------------------

func (r *renderer) openSearchMode() malcolmv1.OpenSearchMode {
	return malcolmv1.OpenSearchMode(strDefault(string(r.spec.OpenSearch.Mode), string(malcolmv1.OpenSearchModeLocal)))
}

func (r *renderer) openSearchLocal() bool {
	return r.openSearchMode() == malcolmv1.OpenSearchModeLocal
}

func (r *renderer) openSearchReplicas() int32 {
	n := int32Default(r.spec.OpenSearch.Local.Replicas, 1)
	if n < 1 {
		n = 1
	}
	return n
}

func (r *renderer) authMode() malcolmv1.AuthMode {
	return malcolmv1.AuthMode(strDefault(string(r.spec.Auth.Mode), string(malcolmv1.AuthModeBasic)))
}

func (r *renderer) netboxMode() malcolmv1.NetBoxMode {
	return malcolmv1.NetBoxMode(strDefault(string(r.spec.NetBox.Mode), string(malcolmv1.NetBoxModeLocal)))
}

func (r *renderer) keycloakLocal() bool { return r.authMode() == malcolmv1.AuthModeKeycloak }
func (r *renderer) keycloakAny() bool {
	return r.authMode() == malcolmv1.AuthModeKeycloak || r.authMode() == malcolmv1.AuthModeKeycloakRemote
}

func (r *renderer) zeekLiveEnabled() bool {
	return boolDefault(r.spec.Capture.Zeek.Enabled, true) && r.componentEnabled("zeek-live")
}

func (r *renderer) zeekRemoteEnabled() bool {
	return boolDefault(r.spec.Capture.Zeek.RemoteSensor.Enabled, true) && r.componentEnabled("zeek-live-remotesensor")
}

func (r *renderer) suricataLiveEnabled() bool {
	return boolDefault(r.spec.Capture.Suricata.Enabled, true) && r.componentEnabled("suricata-live")
}

func (r *renderer) arkimeLiveEnabled() bool {
	return boolDefault(r.spec.Capture.Arkime.Enabled, true) && r.componentEnabled("arkime-live")
}

func (r *renderer) pcapCaptureEnabled() bool {
	return boolDefault(r.spec.Capture.PCAP.Enabled, false) && r.componentEnabled("pcap-capture")
}

// usesGeneratedAdmin reports whether auth-env/etc-nginx-auth are rendered by
// the operator (as opposed to referencing a user's pre-hashed Secret).
func (r *renderer) usesGeneratedAdmin() bool {
	return r.spec.Auth.HashedCredentials == nil || r.spec.Auth.HashedCredentials.SecretName == ""
}

func (r *renderer) caTrustConfigMap() string {
	return strDefault(r.spec.CATrustConfigMap, "var-local-catrust")
}

func (r *renderer) retainOnDelete() bool {
	return boolDefault(r.spec.Storage.RetainOnDelete, true)
}
