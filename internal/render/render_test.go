package render

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

func testSecrets() Secrets {
	return Secrets{
		AdminUsername: "malcolm", AdminOpensslHash: "$1$xhZ5v90R$qQmoPuMUb1XAKitK0FoqO.", AdminHtpasswd: "malcolm:$2y$05$x",
		ValkeyPassword: "vk", ValkeyRemotePassword: "vkr", NetBoxSecretKey: "nbk", NetBoxAPIToken: "nbt",
		NetBoxSuperuserPassword: "nbs", FilescanKey: "fk", PostgresPassword: "pg", ArkimePassword: "ak",
		KeycloakAdminUsername: "admin", KeycloakAdminPassword: "kc",
	}
}

func newMalcolm(mut func(*malcolmv1.MalcolmSpec)) *malcolmv1.Malcolm {
	m := &malcolmv1.Malcolm{
		ObjectMeta: metav1.ObjectMeta{Name: "malcolm", Namespace: "malcolm", UID: "uid-1"},
	}
	if mut != nil {
		mut(&m.Spec)
	}
	return m
}

func mustRender(t *testing.T, m *malcolmv1.Malcolm, mods ...func(*Inputs)) *Result {
	t.Helper()
	in := Inputs{Malcolm: m, Secrets: testSecrets(), LogstashReplicas: 1}
	for _, f := range mods {
		f(&in)
	}
	res, err := Render(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return res
}

func find[T client.Object](res *Result, name string) T {
	var zero T
	for _, o := range res.Objects {
		if t, ok := o.(T); ok && o.GetName() == name {
			return t
		}
	}
	return zero
}

func workloadNames(res *Result) []string {
	var out []string
	for _, w := range res.Workloads {
		out = append(out, w.Kind+"/"+w.Name)
	}
	sort.Strings(out)
	return out
}

// TestDefaultWorkloadsMatchHelm checks that an empty spec yields the same set
// of workloads as the Helm chart with its default values.yaml.
func TestDefaultWorkloadsMatchHelm(t *testing.T) {
	res := mustRender(t, newMalcolm(nil))
	want := []string{
		"DaemonSet/arkime-live-daemonset",
		"DaemonSet/filebeat-daemonset",
		"DaemonSet/suricata-live-daemonset",
		"DaemonSet/zeek-live-daemonset",
		"DaemonSet/zeek-live-daemonset-remotesensor",
		"Deployment/api-deployment",
		"Deployment/arkime-deployment",
		"Deployment/dashboards-deployment",
		"Deployment/dashboards-helper-deployment",
		"Deployment/filebeat-offline-deployment",
		"Deployment/filescan-deployment",
		"Deployment/freq-deployment",
		"Deployment/htadmin-deployment",
		"Deployment/logstash-deployment",
		"Deployment/netbox-deployment",
		"Deployment/nginx-proxy-deployment",
		"Deployment/pcap-monitor-deployment",
		"Deployment/strelka-backend-deployment",
		"Deployment/strelka-frontend-deployment",
		"Deployment/strelka-manager-deployment",
		"Deployment/suricata-offline-deployment",
		"Deployment/upload-deployment",
		"Deployment/valkey-cache-deployment",
		"Deployment/valkey-deployment",
		"Deployment/zeek-offline-deployment",
		"StatefulSet/opensearch",
		"StatefulSet/postgres-statefulset",
	}
	if got := workloadNames(res); !reflect.DeepEqual(got, want) {
		t.Errorf("workloads mismatch\n got: %v\nwant: %v", got, want)
	}
	for _, pvc := range []string{ClaimPCAP, ClaimZeek, ClaimSuricata, ClaimConfig, ClaimRuntimeLogs} {
		p := find[*corev1.PersistentVolumeClaim](res, pvc)
		if p == nil {
			t.Fatalf("missing PVC %s", pvc)
		}
		if got := p.Spec.Resources.Requests[corev1.ResourceStorage]; got.String() != "25Gi" {
			t.Errorf("PVC %s size %s, want 25Gi", pvc, got.String())
		}
		if p.Annotations[AnnotationRetain] != "true" {
			t.Errorf("PVC %s should be retained by default", pvc)
		}
	}
	if find[*networkingv1.Ingress](res, "traefik-ingress") == nil {
		t.Error("expected default traefik ingress")
	}
}

func TestEnvMatchesHelmDefaults(t *testing.T) {
	res := mustRender(t, newMalcolm(nil))
	cm := func(n string) map[string]string {
		c := find[*corev1.ConfigMap](res, n)
		if c == nil {
			t.Fatalf("missing ConfigMap %s", n)
		}
		return c.Data
	}
	checks := []struct{ cm, key, want string }{
		{"opensearch-env", "OPENSEARCH_JAVA_OPTS", "-server -Xmx10g -Xms10g -Xss256k -XX:-HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom -Dlog4j.formatMsgNoLookups=true"},
		{"opensearch-env", "OPENSEARCH_PRIMARY", "opensearch-local"},
		{"opensearch-env", "OPENSEARCH_URL", "https://opensearch:9200"},
		{"opensearch-env", "discovery.type", "single-node"},
		{"opensearch-env", "OPENSEARCH_DEFAULT_REPLICA_COUNT", "0"},
		{"opensearch-env", "MALCOLM_NETWORK_INDEX_ALIAS", "malcolm_network"},
		{"opensearch-env", "CLUSTER_MAX_SHARDS_PER_NODE", "1000"},
		{"opensearch-env", "ARKIME_INIT_SHARDS", "1"},
		{"logstash-env", "LS_JAVA_OPTS", "-server -Xmx3g -Xms3g -Xss2048k -XX:-HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom -Dlog4j.formatMsgNoLookups=true"},
		{"logstash-env", "pipeline.workers", "2"},
		{"logstash-env", "LOGSTASH_NETBOX_ENRICHMENT_DATASETS", "default"},
		{"suricata-env", "SURICATA_HOME_NET", "'[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]'"},
		{"suricata-env", "SURICATA_UPDATE_ENABLE_SOURCES", "et/open"},
		{"zeek-env", "ZEEK_LOCAL_NETS", "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"},
		{"zeek-env", "ZEEK_EXTRACTOR_MODE", "interesting"},
		{"pcap-capture-env", "PCAP_IFACE", "ens192"},
		{"pcap-capture-env", "PCAP_ROTATE_SECONDS", "600"},
		{"pcap-capture-env", "PCAP_ENABLE_TCPDUMP", "true"},
		{"arkime-env", "ARKIME_QUERY_ALL_INDICES", "false"},
		{"arkime-env", "OPENSEARCH_MAX_SHARDS_PER_NODE", "1000"},
		{"netbox-env", "CSRF_TRUSTED_ORIGINS", "http://* https://*"},
		{"netbox-env", "REMOTE_AUTH_DEFAULT_GROUPS", "netbox_read_access"},
		{"netbox-common-env", "NETBOX_MODE", "local"},
		{"netbox-common-env", "NETBOX_URL", ""},
		{"auth-common-env", "NGINX_AUTH_MODE", "basic"},
		{"lookup-common-env", "SENSITIVE_COUNTRY_CODES", strings.Join(defaultSensitiveCountryCodes, ",")},
		{"process-env", "PUID", "1000"},
		{"process-env", "MALCOLM_PROFILE", "malcolm"},
		{"kafka-config", "ZEEK_KAFKA_BROKERS", "kafka.local:9091"},
		{"pipeline-env", "STRELKA_SCANNERS", "default"},
		{"pipeline-env", "STRELKA_BACKEND_PROCS", "1"},
		{"zeek-live-env", "ZEEK_LB_PROCS", "1"},
		{"suricata-live-env", "SURICATA_AF_PACKET_RING_SIZE", "2048"},
		{"zeek-offline-env", "ZEEK_DISABLE_STATS", "true"},
		{"dashboards-env", "DASHBOARDS_URL", "http://dashboards:5601/dashboards"},
		{"upload-common-env", "PCAP_UPLOAD_MAX_FILE_GB", "50"},
	}
	for _, c := range checks {
		if got := cm(c.cm)[c.key]; got != c.want {
			t.Errorf("%s[%s] = %q, want %q", c.cm, c.key, got, c.want)
		}
	}
	if find[*corev1.ConfigMap](res, "arkime-live-env") == nil {
		t.Error("arkime-live-env should exist when arkime live capture is enabled")
	}
}

func TestProductionProfile(t *testing.T) {
	res := mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) { s.Profile = malcolmv1.ProfileProduction }))
	checks := []struct{ cm, key, want string }{
		{"opensearch-env", "CLUSTER_MAX_SHARDS_PER_NODE", "2500"},
		{"opensearch-env", "ARKIME_INIT_SHARDS", "2"},
		{"logstash-env", "pipeline.workers", "18"},
		{"suricata-env", "SURICATA_STREAM_MEMCAP", "16gb"},
		{"suricata-env", "SURICATA_HOST_MEMCAP", "32mb"},
		{"zeek-live-env", "ZEEK_LB_PROCS", "32"},
		{"zeek-offline-env", "ZEEK_AUTO_ANALYZE_PCAP_THREADS", "3"},
		{"suricata-offline-env", "SURICATA_AUTO_ANALYZE_PCAP_PROCESSES", "10"},
		{"arkime-env", "ARKIME_SPI_DATA_MAX_INDICES", "-1"},
		{"arkime-live-env", "ARKIME_PACKET_THREADS", "6"},
		{"pipeline-env", "STRELKA_BACKEND_PROCS", "4"},
	}
	for _, c := range checks {
		if got := find[*corev1.ConfigMap](res, c.cm).Data[c.key]; got != c.want {
			t.Errorf("%s[%s] = %q, want %q", c.cm, c.key, got, c.want)
		}
	}
	if got := find[*corev1.PersistentVolumeClaim](res, ClaimPCAP).Spec.Resources.Requests[corev1.ResourceStorage]; got.String() != "100Gi" {
		t.Errorf("production pcap claim = %s, want 100Gi", got.String())
	}
}

func TestConfigOverridesTakePrecedence(t *testing.T) {
	res := mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		s.Logstash.Workers = ptr.To[int32](7)
		s.Config = map[string]map[string]string{
			"logstash":    {"pipeline.workers": "9"},
			"zeek":        {"ZEEK_DISABLE_ICS_BACNET": "true"},
			"opensearch":  {"MALCOLM_NETWORK_INDEX_PATTERN": "custom-*"},
			"auth-common": {"ROLE_NETBOX_READ_ACCESS": "nb_ro"},
		}
	}))
	ls := find[*corev1.ConfigMap](res, "logstash-env").Data
	if ls["pipeline.workers"] != "9" {
		t.Errorf("config override should beat typed field, got %q", ls["pipeline.workers"])
	}
	if got := find[*corev1.ConfigMap](res, "zeek-env").Data["ZEEK_DISABLE_ICS_BACNET"]; got != "true" {
		t.Errorf("zeek override not applied: %q", got)
	}
	// Derived values follow overridden inputs.
	if got := find[*corev1.ConfigMap](res, "arkime-env").Data["ARKIME_QUERY_ALL_INDICES"]; got != "true" {
		t.Errorf("ARKIME_QUERY_ALL_INDICES should be true for a custom index pattern, got %q", got)
	}
	if got := find[*corev1.ConfigMap](res, "netbox-env").Data["REMOTE_AUTH_DEFAULT_GROUPS"]; got != "nb_ro" {
		t.Errorf("REMOTE_AUTH_DEFAULT_GROUPS should follow ROLE_NETBOX_READ_ACCESS, got %q", got)
	}
}

func TestFilebeatAffinityMatchesHelmDefault(t *testing.T) {
	res := mustRender(t, newMalcolm(nil))
	ds := find[*appsv1.DaemonSet](res, "filebeat-daemonset")
	got := ds.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	in := func(k string) corev1.NodeSelectorRequirement {
		return corev1.NodeSelectorRequirement{Key: k, Operator: corev1.NodeSelectorOpIn, Values: []string{"true"}}
	}
	remoteMissing := corev1.NodeSelectorRequirement{Key: "cnaps.io/zeek-remote-capture", Operator: corev1.NodeSelectorOpDoesNotExist}
	remoteNotTrue := corev1.NodeSelectorRequirement{Key: "cnaps.io/zeek-remote-capture", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"true"}}
	want := []corev1.NodeSelectorTerm{
		{MatchExpressions: []corev1.NodeSelectorRequirement{in("cnaps.io/suricata-capture"), remoteMissing}},
		{MatchExpressions: []corev1.NodeSelectorRequirement{in("cnaps.io/suricata-capture"), remoteNotTrue}},
		{MatchExpressions: []corev1.NodeSelectorRequirement{in("cnaps.io/zeek-capture"), remoteMissing}},
		{MatchExpressions: []corev1.NodeSelectorRequirement{in("cnaps.io/zeek-capture"), remoteNotTrue}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filebeat affinity mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

// configurations exercises many feature combinations for the integrity checks.
var configurations = map[string]func(*malcolmv1.MalcolmSpec){
	"default": nil,
	"production-everything": func(s *malcolmv1.MalcolmSpec) {
		s.Profile = malcolmv1.ProfileProduction
		s.Capture.PCAP.Enabled = ptr.To(true)
		s.Arkime.Parliament.Enabled = true
		s.Arkime.Cont3xt.Enabled = true
		s.IndexLifecycle = &malcolmv1.IndexLifecycleSpec{}
		s.Coverage = &malcolmv1.CoverageSpec{Enabled: true}
		s.NetworkPolicy.Enabled = true
		s.Istio = malcolmv1.IstioSpec{Enabled: true, Host: "malcolm.example.org"}
		s.Components = map[string]malcolmv1.ComponentSpec{
			"suricata-live": {Sidecars: raw(corev1.Container{Name: "sidecar", Image: "busybox:1.37"})},
			"zeek-offline":  {Sidecars: raw(corev1.Container{Name: "sidecar", Image: "busybox:1.37"})},
		}
	},
	"keycloak": func(s *malcolmv1.MalcolmSpec) { s.Auth.Mode = malcolmv1.AuthModeKeycloak },
	"keycloak-remote": func(s *malcolmv1.MalcolmSpec) {
		s.Auth.Mode = malcolmv1.AuthModeKeycloakRemote
		s.Keycloak.AuthURL = "https://kc.example.org"
	},
	"remote-elasticsearch": func(s *malcolmv1.MalcolmSpec) {
		s.OpenSearch = malcolmv1.OpenSearchSpec{
			Mode: malcolmv1.OpenSearchModeElasticsearchRemote, URL: "https://es.example.org:9200",
			CredentialsSecret: "es-creds", DashboardsURL: "http://kibana:5601", ExternalDashboardsURL: "https://kibana.example.org",
			CACertificate: &malcolmv1.CrossNamespaceSecretKeyRef{Name: "es-ca", Namespace: "elastic"},
			Secondary:     &malcolmv1.OpenSearchSecondarySpec{URL: "https://os2:9200", CredentialsSecret: "os2"},
		}
		s.NetBox.Mode = malcolmv1.NetBoxModeDisabled
		s.Postgres.Enabled = ptr.To(false)
	},
	"hashed-credentials-and-custom-configmaps": func(s *malcolmv1.MalcolmSpec) {
		s.Auth.HashedCredentials = &malcolmv1.HashedCredentialsSpec{SecretName: "malcolm-auth"}
		s.CATrustConfigMap = "my-ca"
		s.Zeek.CustomConfigMap = "my-zeek"
		s.Zeek.IntelPreseedConfigMap = "my-intel"
		s.Suricata.RulesConfigMap = "my-rules"
		s.Suricata.ConfigsConfigMap = "my-suricata-configs"
		s.Arkime.LuaConfigMap = "my-lua"
		s.Arkime.WiseConfigMap = "my-wise"
		s.FileScan.YaraRulesConfigMap = "my-yara"
		s.NetBox.CustomPluginsConfigMap = "my-plugins"
		s.Storage.PCAP.ExistingClaim = "nfs-pcap"
	},
	"multi-node-opensearch": func(s *malcolmv1.MalcolmSpec) {
		s.OpenSearch.Local.Replicas = ptr.To[int32](3)
		s.OpenSearch.Local.TransportCASecret = "os-ca"
	},
	"external-postgres-geoip-placement": func(s *malcolmv1.MalcolmSpec) {
		externalPostgres(true)(s)
		s.MaxMind = malcolmv1.MaxMindSpec{CredentialsSecret: "mm", Database: &malcolmv1.GeoIPDatabaseSpec{Enabled: true}}
		s.Placement.Server = malcolmv1.ServerPlacementSpec{NodeSelector: map[string]string{"tier": "server"}, AvoidCaptureNodes: true}
		s.OpenSearch = malcolmv1.OpenSearchSpec{Mode: malcolmv1.OpenSearchModeRemote, URL: "https://os:9200",
			CACertificate: &malcolmv1.CrossNamespaceSecretKeyRef{Name: "os-ca"}}
	},
	"no-capture": func(s *malcolmv1.MalcolmSpec) {
		s.Capture.Zeek.Enabled = ptr.To(false)
		s.Capture.Zeek.RemoteSensor.Enabled = ptr.To(false)
		s.Capture.Suricata.Enabled = ptr.To(false)
		s.Capture.Arkime.Enabled = ptr.To(false)
	},
}

// userObjects are user-provided objects the configurations reference.
var userObjects = map[string]bool{
	"secret/malcolm-auth": true, "configmap/my-ca": true, "configmap/my-zeek": true, "configmap/my-intel": true,
	"configmap/my-rules": true, "configmap/my-suricata-configs": true, "configmap/my-lua": true, "configmap/my-wise": true,
	"configmap/my-yara": true, "configmap/my-plugins": true, "secret/os-ca": true, "secret/pg-admin": true,
}

// TestRenderedObjectsAreConsistent checks, for every configuration, that each
// pod's volume mounts resolve to volumes, that every ConfigMap/Secret a pod
// consumes is either rendered or user-provided, and that each Service selects
// a rendered workload.
func TestRenderedObjectsAreConsistent(t *testing.T) {
	for name, mut := range configurations {
		t.Run(name, func(t *testing.T) {
			res := mustRender(t, newMalcolm(mut), func(in *Inputs) {
				in.IstioAvailable = true
				in.KubernetesAPIAddresses = []string{"10.43.0.1", "192.168.1.10"}
				if name == "external-postgres-geoip-placement" {
					in.CACertificate = []byte("-----BEGIN CERTIFICATE-----\n")
				}
				if name == "remote-elasticsearch" {
					in.PrimaryCredentials = &Credentials{Username: "elastic", Password: "p@ss"}
					in.SecondaryCredentials = &Credentials{Username: "os", Password: "pw"}
					in.CACertificate = []byte("-----BEGIN CERTIFICATE-----\n")
				}
			})
			rendered := map[string]bool{}
			names := map[string]bool{}
			podLabels := map[string]bool{}
			for _, o := range res.Objects {
				switch o.(type) {
				case *corev1.ConfigMap:
					rendered["configmap/"+o.GetName()] = true
				case *corev1.Secret:
					rendered["secret/"+o.GetName()] = true
				}
				gvk := o.GetObjectKind().GroupVersionKind()
				if gvk.Kind == "" {
					t.Errorf("%T %s has no kind set", o, o.GetName())
				}
				key := gvk.Kind + "/" + o.GetName()
				if names[key] {
					t.Errorf("duplicate object %s", key)
				}
				names[key] = true
				if o.GetNamespace() != "malcolm" {
					t.Errorf("%s has namespace %q", key, o.GetNamespace())
				}
				if o.GetLabels()[LabelInstance] != "malcolm" {
					t.Errorf("%s missing instance label", key)
				}
			}
			for _, o := range res.Objects {
				ps := podSpec(o)
				if ps == nil {
					continue
				}
				tmplLabels := podTemplateLabels(o)
				podLabels[tmplLabels[LabelPodName]] = true
				if tmplLabels[LabelPodName] != o.GetName() {
					t.Errorf("%s pod label name=%q", o.GetName(), tmplLabels[LabelPodName])
				}
				vols := map[string]bool{}
				for _, v := range ps.Volumes {
					if vols[v.Name] {
						t.Errorf("%s: duplicate volume %s", o.GetName(), v.Name)
					}
					vols[v.Name] = true
				}
				if sts, ok := o.(*appsv1.StatefulSet); ok {
					for _, c := range sts.Spec.VolumeClaimTemplates {
						vols[c.Name] = true
					}
				}
				for _, c := range append(append([]corev1.Container{}, ps.InitContainers...), ps.Containers...) {
					for _, vm := range c.VolumeMounts {
						if !vols[vm.Name] {
							t.Errorf("%s/%s mounts undefined volume %s", o.GetName(), c.Name, vm.Name)
						}
					}
					if c.Image == "" || !strings.Contains(c.Image, ":") {
						t.Errorf("%s/%s has bad image %q", o.GetName(), c.Name, c.Image)
					}
				}
				for _, ref := range PodConfigReferences(ps) {
					if !rendered[ref] && !userObjects[ref] {
						t.Errorf("%s references %s which is neither rendered nor user-provided", o.GetName(), ref)
					}
				}
				_, isJob := o.(*batchv1.Job)
				_, isCron := o.(*batchv1.CronJob)
				if !isJob && !isCron && podTemplateAnnotations(o)[AnnotationConfigHash] == "" {
					t.Errorf("%s has no config hash", o.GetName())
				}
			}
			for _, o := range res.Objects {
				if svc, ok := o.(*corev1.Service); ok {
					if sel := svc.Spec.Selector[LabelPodName]; !podLabels[sel] {
						t.Errorf("service %s selects %q which no workload provides", svc.Name, sel)
					}
				}
			}
		})
	}
}

func podSpec(o client.Object) *corev1.PodSpec {
	switch w := o.(type) {
	case *batchv1.Job:
		return &w.Spec.Template.Spec
	case *batchv1.CronJob:
		return &w.Spec.JobTemplate.Spec.Template.Spec
	case *appsv1.Deployment:
		return &w.Spec.Template.Spec
	case *appsv1.StatefulSet:
		return &w.Spec.Template.Spec
	case *appsv1.DaemonSet:
		return &w.Spec.Template.Spec
	}
	return nil
}

func podTemplateLabels(o client.Object) map[string]string {
	switch w := o.(type) {
	case *batchv1.Job:
		return map[string]string{LabelPodName: w.Name}
	case *batchv1.CronJob:
		return map[string]string{LabelPodName: w.Name}
	case *appsv1.Deployment:
		return w.Spec.Template.Labels
	case *appsv1.StatefulSet:
		return w.Spec.Template.Labels
	case *appsv1.DaemonSet:
		return w.Spec.Template.Labels
	}
	return nil
}

func podTemplateAnnotations(o client.Object) map[string]string {
	switch w := o.(type) {
	case *appsv1.Deployment:
		return w.Spec.Template.Annotations
	case *appsv1.StatefulSet:
		return w.Spec.Template.Annotations
	case *appsv1.DaemonSet:
		return w.Spec.Template.Annotations
	}
	return nil
}

func TestRemoteElasticsearchKeepsCredentialsOutOfConfigMaps(t *testing.T) {
	res := mustRender(t, newMalcolm(configurations["remote-elasticsearch"]), func(in *Inputs) {
		in.PrimaryCredentials = &Credentials{Username: "elastic", Password: "p@ss:word"}
		in.CACertificate = []byte("CA")
	})
	for _, o := range res.Objects {
		if cm, ok := o.(*corev1.ConfigMap); ok {
			for k, v := range cm.Data {
				if strings.Contains(v, "p@ss") || strings.Contains(v, "p%40ss") {
					t.Errorf("ConfigMap %s key %s contains the password", cm.Name, k)
				}
			}
		}
	}
	urls := find[*corev1.Secret](res, SecretOpenSearchURLEnv)
	if urls == nil {
		t.Fatal("missing credential URL secret")
	}
	if got := string(urls.Data["OPENSEARCH_URL"]); got != "https://elastic:p%40ss%3Aword@es.example.org:9200" {
		t.Errorf("OPENSEARCH_URL = %q", got)
	}
	curl := find[*corev1.Secret](res, SecretCurlrc)
	if got := string(curl.Data[".opensearch.primary.curlrc"]); got != "user: \"elastic:p@ss:word\"\ninsecure\n" {
		t.Errorf("curlrc = %q", got)
	}
	// The URL secret must come after opensearch-env so it takes precedence.
	logstash := find[*appsv1.Deployment](res, "logstash-deployment")
	ef := logstash.Spec.Template.Spec.Containers[0].EnvFrom
	osIdx, urlIdx := -1, -1
	for i, e := range ef {
		if e.ConfigMapRef != nil && e.ConfigMapRef.Name == "opensearch-env" {
			osIdx = i
		}
		if e.SecretRef != nil && e.SecretRef.Name == SecretOpenSearchURLEnv {
			urlIdx = i
		}
	}
	if osIdx < 0 || urlIdx < osIdx {
		t.Errorf("credential URL secret must follow opensearch-env (indexes %d, %d)", osIdx, urlIdx)
	}
	for _, n := range []string{"opensearch", "dashboards-deployment", "netbox-deployment", "postgres-statefulset"} {
		for _, w := range res.Workloads {
			if w.Name == n {
				t.Errorf("%s should not be rendered for a remote store without NetBox/Postgres", n)
			}
		}
	}
	nginx := find[*appsv1.Deployment](res, "nginx-proxy-deployment")
	if env := nginx.Spec.Template.Spec.Containers[0].Env; len(env) != 1 || env[0].Value != "https://kibana.example.org" {
		t.Errorf("nginx DASHBOARDS_URL env = %+v", env)
	}
	if find[*corev1.Secret](res, SecretKeystore) != nil {
		t.Error("opensearch-keystore should only exist for a local OpenSearch")
	}
}

func TestConfigHashTracksConsumedConfigOnly(t *testing.T) {
	hash := func(res *Result, name string) string {
		for _, o := range res.Objects {
			if o.GetName() == name {
				return podTemplateAnnotations(o)[AnnotationConfigHash]
			}
		}
		t.Fatalf("workload %s not found", name)
		return ""
	}
	a := mustRender(t, newMalcolm(nil))
	b := mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		s.Config = map[string]map[string]string{"freq": nil, "lookup-common": {"FREQ_SEVERITY_THRESHOLD": "3.0"}}
	}))
	if hash(a, "freq-deployment") == hash(b, "freq-deployment") {
		t.Error("freq should roll when lookup-common changes")
	}
	if hash(a, "htadmin-deployment") != hash(b, "htadmin-deployment") {
		t.Error("htadmin does not consume lookup-common and should not roll")
	}
	c := mustRender(t, newMalcolm(nil), func(in *Inputs) {
		in.ExternalHashes = map[string]string{"configmap/var-local-catrust": "x"}
	})
	if hash(a, "api-deployment") != hash(c, "api-deployment") {
		t.Error("external hashes must not override rendered objects")
	}
}

func TestComponentCustomization(t *testing.T) {
	cpu := resource.MustParse("2")
	res := mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		s.Components = map[string]malcolmv1.ComponentSpec{
			"logstash": {
				Replicas:       ptr.To[int32](4),
				Resources:      &corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: cpu}},
				NodeSelector:   map[string]string{"tier": "ingest"},
				ExtraEnv:       []corev1.EnvVar{{Name: "FOO", Value: "bar"}},
				PodLabels:      map[string]string{"team": "nsm", LabelPodName: "hijack"},
				InitContainers: raw(corev1.Container{Name: "first", Image: "busybox:1"}),
			},
			"zeek-live-remotesensor": {ContainerResources: map[string]corev1.ResourceRequirements{
				"filebeat-container": {Requests: corev1.ResourceList{corev1.ResourceCPU: cpu}},
			}},
			"freq":            {Enabled: ptr.To(false)},
			"strelka-backend": {Enabled: ptr.To(false)},
			"zeek-live":       {Enabled: ptr.To(false)},
			"suricata-live":   {Enabled: ptr.To(false)},
		}
		s.Logstash.Replicas = ptr.To[int32](2)
	}))
	ls := find[*appsv1.Deployment](res, "logstash-deployment")
	if *ls.Spec.Replicas != 4 {
		t.Errorf("components.logstash.replicas should win, got %d", *ls.Spec.Replicas)
	}
	pod := ls.Spec.Template
	if pod.Labels[LabelPodName] != "logstash-deployment" || pod.Labels["team"] != "nsm" {
		t.Errorf("unexpected pod labels %v", pod.Labels)
	}
	main := pod.Spec.Containers[0]
	if main.Resources.Requests.Cpu().String() != "2" || pod.Spec.NodeSelector["tier"] != "ingest" {
		t.Error("resources/nodeSelector not applied")
	}
	if !slices.ContainsFunc(main.Env, func(e corev1.EnvVar) bool { return e.Name == "FOO" }) {
		t.Error("extra env not applied")
	}
	if pod.Spec.InitContainers[0].Name != "first" {
		t.Error("user init containers must run first")
	}
	rs := find[*appsv1.DaemonSet](res, "zeek-live-daemonset-remotesensor")
	for _, c := range rs.Spec.Template.Spec.Containers {
		if c.Name == "filebeat-container" && c.Resources.Requests.Cpu().String() != "2" {
			t.Error("containerResources not applied")
		}
	}
	for _, gone := range []string{"freq-deployment", "strelka-backend-deployment", "zeek-live-daemonset", "suricata-live-daemonset", "filebeat-daemonset"} {
		for _, w := range res.Workloads {
			if w.Name == gone {
				t.Errorf("%s should be disabled", gone)
			}
		}
	}
	if find[*corev1.Service](res, "freq") != nil {
		t.Error("service of a disabled component should not be rendered")
	}
}

func TestIstioAndNetworkPolicies(t *testing.T) {
	m := newMalcolm(configurations["production-everything"])
	res := mustRender(t, m, func(in *Inputs) {
		in.IstioAvailable = true
		in.KubernetesAPIAddresses = []string{"10.43.0.1", "fd00::1"}
	})
	var vs *unstructured.Unstructured
	for _, o := range res.Objects {
		if u, ok := o.(*unstructured.Unstructured); ok && u.GetKind() == "VirtualService" {
			vs = u
		}
	}
	if vs == nil || res.URL != "https://malcolm.example.org" {
		t.Fatalf("expected VirtualService and URL, got %v %q", vs, res.URL)
	}
	if got := find[*corev1.ConfigMap](res, "netbox-env").Data["CSRF_TRUSTED_ORIGINS"]; got != "https://malcolm.example.org" {
		t.Errorf("CSRF_TRUSTED_ORIGINS = %q", got)
	}
	np := find[*networkingv1.NetworkPolicy](res, "dynamic-endpoint-policy")
	if np == nil || len(np.Spec.Egress[0].To) != 2 || np.Spec.Egress[0].To[1].IPBlock.CIDR != "fd00::1/128" {
		t.Errorf("unexpected dynamic-endpoint-policy %+v", np)
	}
	for _, n := range []string{"allow-internal-block-external", "allow-istio-ingress-egress", "arkime-pcap-download", "allow-all-to-ingress-proxy"} {
		if find[*networkingv1.NetworkPolicy](res, n) == nil {
			t.Errorf("missing NetworkPolicy %s", n)
		}
	}
	// Without the Istio CRD, a warning is reported instead of a VirtualService.
	res = mustRender(t, m)
	if len(res.Warnings) == 0 {
		t.Error("expected a warning when Istio is unavailable")
	}
}

func TestIndexLifecycleTemplatesAreValidJSON(t *testing.T) {
	res := mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) { s.IndexLifecycle = &malcolmv1.IndexLifecycleSpec{} }))
	cm := find[*corev1.ConfigMap](res, "malcolm-template-override")
	for k, v := range cm.Data {
		if !strings.HasPrefix(v, "{") || !strings.Contains(v, `"lifecycle.rollover_alias"`) {
			t.Errorf("%s does not look like an index template: %s", k, v)
		}
	}
	out := find[*corev1.ConfigMap](res, "elastic-output-override").Data["99_opensearch_output.conf"]
	for _, want := range []string{`ilm_rollover_alias => "malcolm_beats"`, `ilm_policy => "logs"`, `ilm_rollover_alias => "malcolm_network_zeek"`, `%{+YYMMdd}-%{[event][hash]}`} {
		if !strings.Contains(out, want) {
			t.Errorf("logstash output missing %q", want)
		}
	}
	if strings.Contains(out, "%!") {
		t.Errorf("format error in logstash output: %s", out)
	}
}

func TestExistingClaimAndStorageClass(t *testing.T) {
	res := mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		s.Storage.StorageClassName = ptr.To("nfs-client")
		s.Storage.PCAP.ExistingClaim = "nfs-pcap"
		s.Storage.Zeek.StorageClassName = ptr.To("fast")
		s.Storage.RetainOnDelete = ptr.To(false)
	}))
	if find[*corev1.PersistentVolumeClaim](res, ClaimPCAP) != nil {
		t.Error("pcap-claim should not be created when existingClaim is set")
	}
	up := find[*appsv1.Deployment](res, "upload-deployment")
	if c := up.Spec.Template.Spec.Volumes[1].PersistentVolumeClaim.ClaimName; c != "nfs-pcap" {
		t.Errorf("upload mounts claim %q", c)
	}
	if sc := find[*corev1.PersistentVolumeClaim](res, ClaimZeek).Spec.StorageClassName; sc == nil || *sc != "fast" {
		t.Errorf("zeek claim storage class %v", sc)
	}
	cfg := find[*corev1.PersistentVolumeClaim](res, ClaimConfig)
	if sc := cfg.Spec.StorageClassName; sc == nil || *sc != "nfs-client" {
		t.Errorf("config claim storage class %v", sc)
	}
	if cfg.Annotations[AnnotationRetain] == "true" {
		t.Error("claims must not be retained when retainOnDelete is false")
	}
	os := find[*appsv1.StatefulSet](res, "opensearch")
	if p := os.Spec.PersistentVolumeClaimRetentionPolicy; p == nil || p.WhenDeleted != appsv1.DeletePersistentVolumeClaimRetentionPolicyType {
		t.Errorf("StatefulSet claims should be deleted with the StatefulSet, got %+v", p)
	}
	if def := find[*appsv1.StatefulSet](mustRender(t, newMalcolm(nil)), "opensearch"); def.Spec.PersistentVolumeClaimRetentionPolicy != nil {
		t.Error("StatefulSet claims are retained by default")
	}
}

func TestAuthSecrets(t *testing.T) {
	res := mustRender(t, newMalcolm(nil))
	auth := find[*corev1.Secret](res, SecretAuthEnv)
	// MALCOLM_PASSWORD holds base64(openssl hash), matching the Helm chart.
	if got := string(auth.Data["MALCOLM_PASSWORD"]); got != "JDEkeGhaNXY5MFIkcVFtb1B1TVViMVhBS2l0SzBGb3FPLg==" {
		t.Errorf("MALCOLM_PASSWORD = %q", got)
	}
	res = mustRender(t, newMalcolm(configurations["hashed-credentials-and-custom-configmaps"]))
	if find[*corev1.Secret](res, SecretAuthEnv) != nil || find[*corev1.Secret](res, SecretNginxAuth) != nil {
		t.Error("auth secrets must not be rendered when hashedCredentials is used")
	}
	nginx := find[*appsv1.Deployment](res, "nginx-proxy-deployment")
	for _, v := range nginx.Spec.Template.Spec.Volumes {
		if v.Name == "nginx-etc-auth-default-secret-volume" {
			if v.Secret.SecretName != "malcolm-auth" || v.Secret.Items[0].Key != "htpass_cred" {
				t.Errorf("unexpected auth volume %+v", v.Secret)
			}
		}
	}
}

func raw(objs ...any) []runtime.RawExtension {
	out := make([]runtime.RawExtension, 0, len(objs))
	for _, o := range objs {
		b, err := json.Marshal(o)
		if err != nil {
			panic(err)
		}
		out = append(out, runtime.RawExtension{Raw: b})
	}
	return out
}

func TestInvalidRawObjectsAreRejected(t *testing.T) {
	m := newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		s.Components = map[string]malcolmv1.ComponentSpec{
			"logstash": {Sidecars: []runtime.RawExtension{{Raw: []byte(`{"name":"x","imagee":"typo"}`)}}},
		}
	})
	_, err := Render(Inputs{Malcolm: m, Secrets: testSecrets()})
	if err == nil || !strings.Contains(err.Error(), "components[logstash].sidecars") || !strings.Contains(err.Error(), "imagee") {
		t.Fatalf("expected a decode error naming the field, got %v", err)
	}
}
