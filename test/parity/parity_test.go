// Package parity compares the operator's rendered objects with the output of
// `helm template` for the Malcolm Helm chart, across a set of equivalent
// configurations, so drift between the two is caught when either is updated.
//
// It runs only when HELM_BIN and HELM_CHART are set:
//
//	HELM_BIN=$(command -v helm) HELM_CHART=../Malcolm-Helm/chart go test ./test/parity/ -v
package parity

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	sigsyaml "sigs.k8s.io/yaml"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
	"github.com/idaholab/malcolm-operator/internal/render"
)

// knownConfigDifferences are intentional deviations from the chart's ConfigMaps.
var knownConfigDifferences = map[string]string{
	// The chart always lists 3 seed hosts (from opensearch.replicas) with a
	// trailing comma, even in single-node mode; the operator lists the actual nodes.
	"opensearch-env/discovery.seed_hosts": "seed hosts follow the actual replica count",
	// The chart passes the literal "false"; Malcolm expects "" or a mode name.
	"opensearch-env/OPENSEARCH_SECONDARY": "empty when no secondary store is configured",
	// The chart's default is a placeholder domain; the operator uses the
	// ingress/Istio host when known, otherwise accepts any origin.
	"netbox-env/CSRF_TRUSTED_ORIGINS": "derived from the ingress/Istio host",
	// Chart bug: the unquoted production value 1048576 is rendered by Go
	// templates as the float "1.048576e+06".
	"suricata-live-env/SURICATA_AF_PACKET_BLOCK_SIZE": "chart renders 1048576 in float notation",
	// The chart renders an empty value as YAML null, which becomes "".
	"filescan-env/FILESCAN_VERBOSITY": "null vs empty string",
}

type scenario struct {
	name     string
	helmArgs []string
	spec     func(*malcolmv1.MalcolmSpec)
	// known lists additional intentional differences ("<object>/<key>").
	known map[string]string
}

var scenarios = []scenario{
	{name: "default"},
	{name: "production", helmArgs: []string{"--set", "is_production=true"},
		spec: func(s *malcolmv1.MalcolmSpec) { s.Profile = malcolmv1.ProfileProduction }},
	{name: "keycloak", helmArgs: []string{"--set", "auth.mode=keycloak"},
		spec: func(s *malcolmv1.MalcolmSpec) { s.Auth.Mode = malcolmv1.AuthModeKeycloak }},
	{name: "keycloak-remote",
		helmArgs: []string{"--set", "auth.mode=keycloak_remote", "--set", "keycloak.keycloak_auth_url=https://kc.example.org"},
		spec: func(s *malcolmv1.MalcolmSpec) {
			s.Auth.Mode = malcolmv1.AuthModeKeycloakRemote
			s.Keycloak.AuthURL = "https://kc.example.org"
		}},
	{name: "pre-hashed-credentials", helmArgs: []string{"--set", "auth.existingSecret=malcolm-auth"},
		spec: func(s *malcolmv1.MalcolmSpec) {
			s.Auth.HashedCredentials = &malcolmv1.HashedCredentialsSpec{SecretName: "malcolm-auth",
				UsernameKey: "username", OpensslPasswordKey: "openssl_password", HtpasswdKey: "htpass_cred"}
		}},
	{name: "index-lifecycle", helmArgs: []string{"--set", "siem_env.logstash_override.enabled=true"},
		spec: func(s *malcolmv1.MalcolmSpec) { s.IndexLifecycle = &malcolmv1.IndexLifecycleSpec{} }},
	{name: "pcap-capture", helmArgs: []string{"--set", "pcap_live.enabled=true"},
		spec: func(s *malcolmv1.MalcolmSpec) { s.Capture.PCAP.Enabled = ptr.To(true) }},
	{name: "no-arkime-live", helmArgs: []string{"--set", "arkime_live.enabled=false"},
		spec: func(s *malcolmv1.MalcolmSpec) { s.Capture.Arkime.Enabled = ptr.To(false) }},
	{name: "netbox-disabled",
		helmArgs: []string{"--set", "netbox.mode=disabled", "--set", "postgres.enabled=false"},
		spec: func(s *malcolmv1.MalcolmSpec) {
			s.NetBox.Mode = malcolmv1.NetBoxModeDisabled
			s.Postgres.Enabled = ptr.To(false)
		}},
	{name: "istio",
		helmArgs: []string{"--set", "istio.enabled=true", "--set", "ingress.enabled=false"},
		spec: func(s *malcolmv1.MalcolmSpec) {
			s.Istio = malcolmv1.IstioSpec{Enabled: true, Host: "malcolm.vp.bigbang.dev"}
			s.Ingress.Enabled = ptr.To(false)
		},
		known: map[string]string{"dashboards-helper-env/MALCOLM_URL": "same URL, derived from the Istio host"}},
	{name: "multi-node-opensearch",
		helmArgs: []string{"--set", "opensearch.singleNode=false", "--set", "opensearch.existingCASecretName=os-ca"},
		spec: func(s *malcolmv1.MalcolmSpec) {
			s.OpenSearch.Local.Replicas = ptr.To[int32](3)
			s.OpenSearch.Local.TransportCASecret = "os-ca"
		},
		known: map[string]string{
			"opensearch-env/cluster.initial_cluster_manager_nodes": "no trailing comma",
		}},
	{name: "coverage-and-sidecars",
		helmArgs: []string{"--set", "enable_coverage=true",
			"--set", "suricata_chart_overrides.sideCars[0].name=probe",
			"--set", "suricata_chart_overrides.sideCars[0].image=busybox:1.37",
			"--set", "zeek_chart_overrides.sideCars[0].name=probe",
			"--set", "zeek_chart_overrides.sideCars[0].image=busybox:1.37"},
		spec: func(s *malcolmv1.MalcolmSpec) {
			sidecar := []runtime.RawExtension{{Raw: []byte(`{"name":"probe","image":"busybox:1.37"}`)}}
			s.Coverage = &malcolmv1.CoverageSpec{Enabled: true}
			s.Components = map[string]malcolmv1.ComponentSpec{
				"suricata-offline":       {Sidecars: sidecar},
				"suricata-live":          {Sidecars: sidecar},
				"zeek-offline":           {Sidecars: sidecar},
				"zeek-live-remotesensor": {Sidecars: sidecar},
			}
		}},
}

func TestHelmParity(t *testing.T) {
	helm, chart := os.Getenv("HELM_BIN"), os.Getenv("HELM_CHART")
	if helm == "" || chart == "" {
		t.Skip("set HELM_BIN and HELM_CHART to run the Helm parity test")
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			args := append([]string{"template", "malcolm", chart, "-n", "malcolm"}, sc.helmArgs...)
			out, err := exec.Command(helm, args...).Output()
			if err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					t.Fatalf("helm template: %v\n%s", err, ee.Stderr)
				}
				t.Fatalf("helm template: %v", err)
			}
			compare(t, out, sc)
		})
	}
}

func compare(t *testing.T, helmOutput []byte, sc scenario) {
	helmObjs := loadHelm(t, helmOutput)
	m := &malcolmv1.Malcolm{ObjectMeta: metav1.ObjectMeta{Name: "malcolm", Namespace: "malcolm"}}
	if sc.spec != nil {
		sc.spec(&m.Spec)
	}
	res, err := render.Render(render.Inputs{
		IstioAvailable: true,
		Malcolm:        m,
		Secrets:        render.Secrets{AdminUsername: "malcolm", AdminOpensslHash: "$1$x$y", AdminHtpasswd: "malcolm:$2y$"},
		// `helm template` cannot look up nodes, so the chart renders 1 replica.
		LogstashReplicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ours := map[string]client.Object{}
	for _, o := range res.Objects {
		ours[key(o)] = o
	}

	var missing []string
	for k, h := range helmObjs {
		o, ok := ours[k]
		if !ok {
			missing = append(missing, k)
			continue
		}
		switch hv := h.(type) {
		case *corev1.ConfigMap:
			compareConfigMap(t, hv, o.(*corev1.ConfigMap), sc.known)
		case *corev1.Secret:
			compareSecretKeys(t, hv, o.(*corev1.Secret))
		case *corev1.Service:
			compareService(t, hv, o.(*corev1.Service))
		case *corev1.PersistentVolumeClaim:
			comparePVC(t, hv, o.(*corev1.PersistentVolumeClaim))
		case *appsv1.Deployment:
			od := o.(*appsv1.Deployment)
			if *hv.Spec.Replicas != *od.Spec.Replicas {
				t.Errorf("%s: replicas helm=%d operator=%d", k, *hv.Spec.Replicas, *od.Spec.Replicas)
			}
			comparePod(t, k, &hv.Spec.Template.Spec, &od.Spec.Template.Spec)
		case *appsv1.StatefulSet:
			os := o.(*appsv1.StatefulSet)
			if hv.Spec.ServiceName != os.Spec.ServiceName || *hv.Spec.Replicas != *os.Spec.Replicas {
				t.Errorf("%s: serviceName/replicas differ", k)
			}
			for i := range hv.Spec.VolumeClaimTemplates {
				comparePVC(t, &hv.Spec.VolumeClaimTemplates[i], &os.Spec.VolumeClaimTemplates[i])
			}
			comparePod(t, k, &hv.Spec.Template.Spec, &os.Spec.Template.Spec)
		case *appsv1.DaemonSet:
			comparePod(t, k, &hv.Spec.Template.Spec, &o.(*appsv1.DaemonSet).Spec.Template.Spec)
		case *unstructured.Unstructured:
			hj, _ := json.Marshal(hv.Object["spec"])
			oj, _ := json.Marshal(o.(*unstructured.Unstructured).Object["spec"])
			if !sameJSON(string(hj), string(oj)) {
				t.Errorf("%s spec differs:\n helm:     %s\n operator: %s", k, hj, oj)
			}
		case *networkingv1.Ingress:
			oi := o.(*networkingv1.Ingress)
			diff(t, k+" annotations", hv.Annotations, filterAnnotations(oi.Annotations))
			diff(t, k+" spec", hv.Spec, oi.Spec)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		t.Errorf("rendered by Helm but not by the operator: %s", k)
	}
	for k := range ours {
		if _, ok := helmObjs[k]; !ok {
			t.Logf("rendered only by the operator: %s", k)
		}
	}
}

// helmOnly are chart objects the operator intentionally replaces.
var helmOnly = map[string]bool{
	"Job/malcolm-secret-init":            true, // replaced by in-operator secret generation
	"ServiceAccount/malcolm-secret-init": true,
	"Role/malcolm-secret-init":           true,
	"RoleBinding/malcolm-secret-init":    true,
}

func loadHelm(t *testing.T, data []byte) map[string]client.Object {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	decoder := serializer.NewCodecFactory(scheme).UniversalDeserializer()
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	out := map[string]client.Object{}
	for {
		doc, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(bytes.TrimSpace(doc)) == 0 || isCommentOnly(doc) {
			continue
		}
		var co client.Object
		obj, _, err := decoder.Decode(doc, nil, nil)
		switch {
		case runtime.IsNotRegisteredError(err):
			u := &unstructured.Unstructured{}
			if err := sigsyaml.Unmarshal(doc, &u.Object); err != nil {
				t.Fatalf("decoding helm output: %v", err)
			}
			co = u
		case err != nil:
			t.Fatalf("decoding helm output: %v\n%s", err, doc)
		default:
			co = obj.(client.Object)
		}
		k := key(co)
		if helmOnly[k] {
			continue
		}
		out[k] = co
	}
	return out
}

func isCommentOnly(doc []byte) bool {
	for _, line := range strings.Split(string(doc), "\n") {
		l := strings.TrimSpace(line)
		if l != "" && !strings.HasPrefix(l, "#") {
			return false
		}
	}
	return true
}

func key(o client.Object) string {
	kind := o.GetObjectKind().GroupVersionKind().Kind
	if kind == "" {
		kind = reflect.TypeOf(o).Elem().Name()
	}
	return kind + "/" + o.GetName()
}

func compareConfigMap(t *testing.T, h, o *corev1.ConfigMap, known map[string]string) {
	keys := map[string]bool{}
	for k := range h.Data {
		keys[k] = true
	}
	for k := range o.Data {
		keys[k] = true
	}
	for k := range keys {
		hv, hok := h.Data[k]
		ov, ook := o.Data[k]
		if hv == ov && hok == ook {
			continue
		}
		id := h.Name + "/" + k
		if strings.HasSuffix(k, ".json") && sameJSON(hv, ov) {
			continue
		}
		reason, ok := knownConfigDifferences[id]
		if !ok {
			reason, ok = known[id]
		}
		if ok {
			t.Logf("known difference %s (%s): helm=%q operator=%q", id, reason, hv, ov)
			continue
		}
		switch {
		case !hok:
			t.Errorf("ConfigMap %s: key %s only in operator (%q)", h.Name, k, ov)
		case !ook:
			t.Errorf("ConfigMap %s: key %s only in helm (%q)", h.Name, k, hv)
		default:
			t.Errorf("ConfigMap %s: key %s helm=%q operator=%q", h.Name, k, hv, ov)
		}
	}
}

func compareSecretKeys(t *testing.T, h, o *corev1.Secret) {
	helmData := map[string][]byte{}
	for k, v := range h.Data {
		helmData[k] = v
	}
	for k, v := range h.StringData {
		helmData[k] = []byte(v)
	}
	diff(t, "Secret/"+h.Name+" keys", sortedSecretKeys(helmData), sortedSecretKeys(o.Data))
}

func sortedSecretKeys(m map[string][]byte) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func compareService(t *testing.T, h, o *corev1.Service) {
	if h.Spec.Type == "" {
		h.Spec.Type = corev1.ServiceTypeClusterIP
	}
	if o.Spec.Type == "" {
		o.Spec.Type = corev1.ServiceTypeClusterIP
	}
	diff(t, "Service/"+h.Name, h.Spec, o.Spec)
}

func comparePVC(t *testing.T, h, o *corev1.PersistentVolumeClaim) {
	diff(t, "PVC/"+h.Name, h.Spec, o.Spec)
}

func filterAnnotations(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if k != render.AnnotationConfigHash && k != render.AnnotationRetain {
			out[k] = v
		}
	}
	return out
}

// comparePod compares pod specs, ignoring ordering where Kubernetes does.
func comparePod(t *testing.T, id string, h, o *corev1.PodSpec) {
	normalizePod(h)
	normalizePod(o)
	if len(h.Containers) != len(o.Containers) {
		t.Errorf("%s: helm has %d containers, operator %d", id, len(h.Containers), len(o.Containers))
	}
	compareContainers(t, id, h.Containers, o.Containers)
	compareContainers(t, id+" init", h.InitContainers, o.InitContainers)
	h.Containers, o.Containers, h.InitContainers, o.InitContainers = nil, nil, nil, nil
	diff(t, id+" pod spec", *h, *o)
}

func compareContainers(t *testing.T, id string, h, o []corev1.Container) {
	byName := map[string]corev1.Container{}
	for _, c := range o {
		byName[c.Name] = c
	}
	for _, hc := range h {
		oc, ok := byName[hc.Name]
		if !ok {
			t.Errorf("%s: container %s missing from operator", id, hc.Name)
			continue
		}
		diff(t, fmt.Sprintf("%s container %s", id, hc.Name), hc, oc)
	}
}

func normalizePod(ps *corev1.PodSpec) {
	if ps.ServiceAccountName == "default" {
		ps.ServiceAccountName = ""
	}
	sort.Slice(ps.Volumes, func(i, j int) bool { return ps.Volumes[i].Name < ps.Volumes[j].Name })
	for _, list := range [][]corev1.Container{ps.Containers, ps.InitContainers} {
		for i := range list {
			c := &list[i]
			sort.Slice(c.VolumeMounts, func(a, b int) bool {
				return c.VolumeMounts[a].MountPath+c.VolumeMounts[a].Name < c.VolumeMounts[b].MountPath+c.VolumeMounts[b].Name
			})
			// Duplicate envFrom entries are redundant (the chart lists arkime-env twice for nginx).
			seen := map[string]bool{}
			var ef []corev1.EnvFromSource
			for _, e := range c.EnvFrom {
				k := fmt.Sprintf("%v%v", e.ConfigMapRef, e.SecretRef)
				if e.ConfigMapRef != nil {
					k = "cm/" + e.ConfigMapRef.Name
				} else if e.SecretRef != nil {
					k = "secret/" + e.SecretRef.Name
				}
				if !seen[k] {
					seen[k] = true
					ef = append(ef, e)
				}
			}
			c.EnvFrom = ef
			if len(c.Env) == 0 {
				c.Env = nil
			}
		}
	}
	if len(ps.Tolerations) == 0 {
		ps.Tolerations = nil
	}
}

func diff(t *testing.T, id string, h, o any) {
	t.Helper()
	if reflect.DeepEqual(h, o) {
		return
	}
	hy, _ := yamlOf(h)
	oy, _ := yamlOf(o)
	t.Errorf("%s differs:\n%s", id, lineDiff(hy, oy))
}

func yamlOf(v any) (string, error) {
	b, err := jsonYAML(v)
	return string(b), err
}

func lineDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	inB := map[string]int{}
	for _, l := range bl {
		inB[l]++
	}
	inA := map[string]int{}
	for _, l := range al {
		inA[l]++
	}
	var out []string
	for _, l := range al {
		if inB[l] == 0 {
			out = append(out, "  - helm:     "+l)
		} else {
			inB[l]--
		}
	}
	for _, l := range bl {
		if inA[l] == 0 {
			out = append(out, "  + operator: "+l)
		} else {
			inA[l]--
		}
	}
	return strings.Join(out, "\n")
}

func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
