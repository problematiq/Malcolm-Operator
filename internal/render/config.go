package render

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

//go:embed assets
var assets embed.FS

func asset(name string) string {
	b, err := assets.ReadFile(path.Join("assets", name))
	if err != nil {
		panic(fmt.Sprintf("missing embedded asset %s: %v", name, err))
	}
	return string(b)
}

func assetDir(dir string) map[string]string {
	out := map[string]string{}
	entries, err := fs.ReadDir(assets, path.Join("assets", dir))
	if err != nil {
		panic(fmt.Sprintf("missing embedded asset dir %s: %v", dir, err))
	}
	for _, e := range entries {
		if !e.IsDir() {
			out[e.Name()] = asset(path.Join(dir, e.Name()))
		}
	}
	return out
}

const javaOptsSuffix = "-XX:-HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom -Dlog4j.formatMsgNoLookups=true"

// computeEnv builds the final value of every environment group:
// built-in defaults -> production profile -> typed spec fields -> spec.config.
func (r *renderer) computeEnv() {
	env := map[string]map[string]string{}
	for _, g := range envGroups {
		m := map[string]string{}
		for k, v := range baseEnv[g.Stem] {
			m[k] = v
		}
		if r.profile == malcolmv1.ProfileProduction {
			for k, v := range productionEnv[g.Stem] {
				m[k] = v
			}
		}
		env[g.Stem] = m
	}

	r.typedEnv(env)

	overridden := func(stem, key string) bool {
		_, ok := r.spec.Config[stem][key]
		return ok
	}
	for stem, kv := range r.spec.Config {
		if _, ok := env[stem]; !ok {
			r.warn("ignoring unknown config group %q", stem)
			continue
		}
		for k, v := range kv {
			env[stem][k] = v
		}
	}

	// Values derived from other (possibly overridden) values.
	if !overridden("arkime", "ARKIME_QUERY_ALL_INDICES") {
		env["arkime"]["ARKIME_QUERY_ALL_INDICES"] = btoa(env["opensearch"]["MALCOLM_NETWORK_INDEX_PATTERN"] != "arkime_sessions3-*")
	}
	if !overridden("netbox", "REMOTE_AUTH_DEFAULT_GROUPS") {
		env["netbox"]["REMOTE_AUTH_DEFAULT_GROUPS"] = env["auth-common"]["ROLE_NETBOX_READ_ACCESS"]
	}
	if !overridden("pcap-capture", "PCAP_ROTATE_SECONDS") {
		if mins, err := strconv.Atoi(env["pcap-capture"]["PCAP_ROTATE_MINUTES"]); err == nil {
			env["pcap-capture"]["PCAP_ROTATE_SECONDS"] = strconv.Itoa(mins * 60)
		}
	}
	r.env = env
}

func (r *renderer) typedEnv(env map[string]map[string]string) {
	s := r.spec
	set := func(stem, key, val string) { env[stem][key] = val }

	// process / ssl
	set("process", "PUID", strconv.FormatInt(int64Default(s.Process.PUID, 1000), 10))
	set("process", "PGID", strconv.FormatInt(int64Default(s.Process.PGID, 1000), 10))
	if s.Process.TiniVerbosity != nil {
		set("process", "TINI_VERBOSITY", strconv.Itoa(int(*s.Process.TiniVerbosity)))
	}

	// auth-common
	set("auth-common", "NGINX_AUTH_MODE", string(r.authMode()))
	set("auth-common", "NGINX_REQUIRE_GROUP", strings.Join(s.Auth.RequireGroups, ","))
	set("auth-common", "NGINX_REQUIRE_ROLE", strings.Join(s.Auth.RequireRoles, ","))
	set("auth-common", "ROLE_BASED_ACCESS", btoa(s.Auth.RoleBasedAccess))

	// lookup-common
	set("lookup-common", "SENSITIVE_COUNTRY_CODES", strings.Join(listDefault(s.Lookup.SensitiveCountryCodes, defaultSensitiveCountryCodes), ","))

	// opensearch
	os := s.OpenSearch
	local := os.Local
	osJava := strDefault(local.JavaMemory, r.tun.OpenSearchJavaMemory)
	maxShards := int32Default(local.MaxShardsPerNode, r.tun.OpenSearchMaxShards)
	set("opensearch", "MAX_LOCKED_MEMORY", strDefault(local.MaxLockedMemory, "unlimited"))
	set("opensearch", "OPENSEARCH_JAVA_OPTS", "-server "+osJava+" "+javaOptsSuffix)
	set("opensearch", "CLUSTER_MAX_SHARDS_PER_NODE", strconv.Itoa(int(maxShards)))
	set("opensearch", "OPENSEARCH_PRIMARY", string(r.openSearchMode()))
	set("opensearch", "OPENSEARCH_URL", r.openSearchURL())
	set("opensearch", "OPENSEARCH_SSL_CERTIFICATE_VERIFICATION", btoa(os.SSLCertificateVerification))
	if os.Secondary != nil && os.Secondary.URL != "" {
		set("opensearch", "OPENSEARCH_SECONDARY", string(malcolmv1.OpenSearchMode(strDefault(string(os.Secondary.Mode), string(malcolmv1.OpenSearchModeRemote)))))
		set("opensearch", "OPENSEARCH_SECONDARY_URL", os.Secondary.URL)
		set("opensearch", "OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION", btoa(os.Secondary.SSLCertificateVerification))
	} else {
		set("opensearch", "OPENSEARCH_SECONDARY", "")
		set("opensearch", "OPENSEARCH_SECONDARY_URL", "")
		set("opensearch", "OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION", "false")
	}
	replicas := r.openSearchReplicas()
	seeds := make([]string, 0, replicas)
	managers := make([]string, 0, replicas)
	for i := int32(0); i < replicas; i++ {
		seeds = append(seeds, fmt.Sprintf("opensearch-%d.opensearch-headless.%s.svc.cluster.local:9300", i, r.ns))
		managers = append(managers, fmt.Sprintf("opensearch-%d", i))
	}
	set("opensearch", "discovery.seed_hosts", strings.Join(seeds, ","))
	if replicas == 1 {
		set("opensearch", "discovery.type", "single-node")
		set("opensearch", "OPENSEARCH_DEFAULT_REPLICA_COUNT", "0")
	} else {
		set("opensearch", "discovery.type", "")
		set("opensearch", "cluster.initial_cluster_manager_nodes", strings.Join(managers, ","))
		set("opensearch", "OPENSEARCH_DEFAULT_REPLICA_COUNT", strconv.Itoa(int(int32Default(local.DefaultReplicaCount, 1))))
	}
	searchAlias := "malcolm_network"
	if s.IndexLifecycle != nil {
		searchAlias = strDefault(s.IndexLifecycle.SearchAlias, searchAlias)
	}
	set("opensearch", "MALCOLM_NETWORK_INDEX_ALIAS", searchAlias)

	// dashboards
	set("dashboards", "DASHBOARDS_URL", r.dashboardsURL())

	// arkime
	set("arkime", "OPENSEARCH_MAX_SHARDS_PER_NODE", strconv.Itoa(int(maxShards)))
	if len(r.in.CACertificate) > 0 {
		set("arkime", "ARKIME_CERTFILE", "/usr/local/share/ca-certificates/elastic_ca.crt")
	}
	set("arkime-offline", "ARKIME_AUTO_ANALYZE_PCAP_FILES", btoa(boolDefault(s.Arkime.AutoAnalyzeUploads, true)))
	set("arkime-live", "ARKIME_LIVE_NODE_HOST", s.Capture.Arkime.NodeHost)
	set("arkime-offline", "ARKIME_EXPOSE_WISE_GUI", btoa(boolDefault(s.Arkime.ExposeWiseGUI, true)))
	set("arkime-offline", "ARKIME_ALLOW_WISE_GUI_CONFIG", btoa(s.Arkime.AllowWiseGUIConfig))

	// netbox
	nb := s.NetBox
	set("netbox-common", "NETBOX_DEFAULT_SITE", strDefault(nb.DefaultSite, "Malcolm"))
	set("netbox-common", "NETBOX_MODE", string(r.netboxMode()))
	if r.netboxMode() == malcolmv1.NetBoxModeRemote {
		set("netbox-common", "NETBOX_URL", nb.URL)
	} else {
		set("netbox-common", "NETBOX_URL", "")
	}
	set("netbox-common", "NETBOX_ENRICHMENT", btoa(boolDefault(nb.Enrichment, true)))
	set("netbox-common", "NETBOX_AUTO_POPULATE", btoa(boolDefault(nb.AutoPopulate, true)))
	set("netbox-common", "NETBOX_AUTO_POPULATE_SUBNETS", strings.Join(nb.AutoPopulateSubnets, ","))
	csrf := nb.CSRFTrustedOrigins
	if csrf == "" {
		csrf = strDefault(r.externalURL(), "http://* https://*")
	}
	set("netbox", "CSRF_TRUSTED_ORIGINS", csrf)
	if u := r.externalURL(); u != "" {
		set("dashboards-helper", "MALCOLM_URL", u)
	}

	// nginx
	set("nginx", "NGINX_X_FORWARDED_PROTO_OVERRIDE", s.Nginx.XForwardedProtoOverride)
	set("nginx", "NGINX_CSP_FORM_ACTION_EXTRA", strings.Join(s.Nginx.CSPFormActionExtra, " "))

	// capture
	c := s.Capture
	set("pcap-capture", "PCAP_ENABLE_NETSNIFF", btoa(boolDefault(c.Netsniff, false)))
	set("pcap-capture", "PCAP_ENABLE_TCPDUMP", btoa(boolDefault(c.Tcpdump, true)))
	set("pcap-capture", "PCAP_FILTER", c.Filter)
	set("pcap-capture", "PCAP_IFACE", strings.Join(listDefault(c.Interfaces, defaultInterfaces), ","))
	set("pcap-capture", "PCAP_IFACE_TWEAK", btoa(boolDefault(c.InterfaceTweak, true)))
	set("pcap-capture", "PCAP_ROTATE_MEGABYTES", strconv.Itoa(int(int32Default(c.RotateMegabytes, 4))))
	set("pcap-capture", "PCAP_ROTATE_MINUTES", strconv.Itoa(int(int32Default(c.RotateMinutes, 10))))
	set("pcap-capture", "PCAP_IFACE_STATS_CRON_EXPRESSION", c.StatsCronExpression)
	homeNet := listDefault(c.HomeNet, defaultHomeNet)

	// suricata
	su := s.Suricata
	set("suricata", "SURICATA_CUSTOM_RULES_ONLY", btoa(su.CustomRulesOnly))
	set("suricata", "SURICATA_UPDATE_RULES", btoa(su.UpdateRules))
	set("suricata", "SURICATA_UPDATE_ENABLE_SOURCES", strings.Join(listDefault(su.EnableSources, defaultSuricataSources), ","))
	set("suricata", "SURICATA_DISABLE_SIDS", strings.Join(su.DisableSIDs, ","))
	set("suricata", "SURICATA_HOME_NET", "'["+strings.Join(homeNet, ",")+"]'")
	set("suricata-offline", "SURICATA_AUTO_ANALYZE_PCAP_FILES", btoa(boolDefault(su.AutoAnalyzeUploads, true)))

	// upload
	set("upload-common", "PCAP_UPLOAD_MAX_FILE_GB", strconv.Itoa(int(int32Default(s.Upload.MaxFileGB, 50))))
	set("upload-common", "EXTRA_TAGS", strings.Join(s.Upload.ExtraTags, ","))

	// zeek
	set("zeek", "ZEEK_EXTRACTOR_MODE", strDefault(s.Zeek.ExtractMode, "interesting"))
	set("zeek", "ZEEK_LOCAL_NETS", strings.Join(homeNet, ","))
	set("zeek-offline", "ZEEK_AUTO_ANALYZE_PCAP_FILES", btoa(boolDefault(s.Zeek.AutoAnalyzeUploads, true)))

	// kafka
	set("kafka", "ZEEK_KAFKA_ENABLED", btoa(s.Kafka.Enabled))
	set("kafka", "ZEEK_KAFKA_BROKERS", strings.Join(listDefault(s.Kafka.Brokers, defaultKafkaBrokers), ","))
	set("kafka", "ZEEK_KAFKA_TOPIC", strDefault(s.Kafka.Topic, "zeek"))

	// logstash
	ls := s.Logstash
	set("logstash", "LOGSTASH_NETBOX_ENRICHMENT_DATASETS", strings.Join(listDefault(nb.EnrichmentDatasets, defaultNetboxDatasets), ","))
	set("logstash", "LS_JAVA_OPTS", "-server "+strDefault(ls.JavaMemory, r.tun.LogstashJavaMemory)+" "+javaOptsSuffix)
	set("logstash", "pipeline.workers", strconv.Itoa(int(int32Default(ls.Workers, r.tun.LogstashWorkers))))
	set("logstash", "pipeline.batch.size", strconv.Itoa(int(int32Default(ls.BatchSize, r.tun.LogstashBatchSize))))
	set("logstash", "pipeline.batch.delay", strconv.Itoa(int(int32Default(ls.BatchDelay, r.tun.LogstashBatchDelay))))
	if ls.OTKB != nil {
		set("logstash", "OTKB_ENRICHMENT", btoa(ls.OTKB.Enabled))
		set("logstash", "OTKB_URL", ls.OTKB.URL)
	} else {
		set("logstash", "OTKB_ENRICHMENT", "false")
		set("logstash", "OTKB_URL", "")
	}

	// filescan pipeline
	set("pipeline", "PIPELINE_DISABLED", btoa(s.FileScan.Disabled))
	set("pipeline", "STRELKA_SCANNERS", strings.Join(listDefault(s.FileScan.Scanners, defaultStrelkaScanners), ","))

	// keycloak
	kc := s.Keycloak
	set("keycloak", "KEYCLOAK_AUTH_REALM", strDefault(kc.AuthRealm, "master"))
	set("keycloak", "KEYCLOAK_AUTH_REDIRECT_URI", strDefault(kc.AuthRedirectURI, "/index.html"))
	set("keycloak", "KEYCLOAK_AUTH_URL", kc.AuthURL)
	set("keycloak", "KEYCLOAK_CLIENT_ID", kc.ClientID)
	set("keycloak", "KEYCLOAK_SSL_VERIFY", btoa(kc.SSLVerify))
	set("keycloak", "KC_HOSTNAME", kc.Hostname)
}

func int64Default(v *int64, def int64) int64 {
	if v == nil {
		return def
	}
	return *v
}

// openSearchURL is the primary store URL without embedded credentials.
func (r *renderer) openSearchURL() string {
	if r.openSearchLocal() {
		return strDefault(r.spec.OpenSearch.URL, "https://opensearch:9200")
	}
	return r.spec.OpenSearch.URL
}

// openSearchDashboards reports whether Malcolm runs its own OpenSearch
// Dashboards: for a local or a remote OpenSearch (but not for Elasticsearch,
// which comes with its own Kibana).
func (r *renderer) openSearchDashboards() bool {
	return r.openSearchMode() != malcolmv1.OpenSearchModeElasticsearchRemote
}

func (r *renderer) dashboardsURL() string {
	if r.openSearchDashboards() {
		return strDefault(r.spec.OpenSearch.DashboardsURL, "http://dashboards:5601/dashboards")
	}
	return r.spec.OpenSearch.DashboardsURL
}

// embedCredentials reports whether remote credentials are embedded in URLs.
func (r *renderer) embedCredentials() bool {
	return !r.openSearchLocal() && r.in.PrimaryCredentials != nil && r.in.PrimaryCredentials.Username != "" &&
		boolDefault(r.spec.OpenSearch.EmbedCredentialsInURL, true)
}

// withCredentials returns rawURL with user[:password]@ inserted after the scheme.
func withCredentials(rawURL string, c *Credentials) string {
	scheme, rest, ok := strings.Cut(rawURL, "://")
	if !ok || c == nil || c.Username == "" {
		return rawURL
	}
	userinfo := urlUserinfoEscape(c.Username)
	if c.Password != "" {
		userinfo += ":" + urlUserinfoEscape(c.Password)
	}
	return scheme + "://" + userinfo + "@" + rest
}

func urlUserinfoEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9',
			c == '-', c == '.', c == '_', c == '~', c == '!', c == '$', c == '&', c == '\'',
			c == '(', c == ')', c == '*', c == '+', c == ',', c == ';', c == '=':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// --- ConfigMaps ------------------------------------------------------------

func (r *renderer) configMap(name, component string, data map[string]string) *corev1.ConfigMap {
	if data == nil {
		data = map[string]string{}
	}
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.ns, Labels: r.labels(component)},
		Data:       data,
	}
}

var gitignorePlaceholder = map[string]string{".gitignore": "*\n!.gitignore\n"}

func (r *renderer) renderConfigMaps() {
	for _, g := range envGroups {
		if g.Secret {
			continue
		}
		if g.Stem == "arkime-live" && !r.arkimeLiveEnabled() {
			continue
		}
		r.add(r.configMap(g.Name, "config", copyMap(r.env[g.Stem])))
	}

	if r.spec.CATrustConfigMap == "" {
		r.add(r.configMap("var-local-catrust", "config", copyMap(gitignorePlaceholder)))
	}
	if r.spec.Suricata.RulesConfigMap == "" {
		r.add(r.configMap("suricata-rules", "suricata", copyMap(gitignorePlaceholder)))
	}
	if r.spec.Suricata.ConfigsConfigMap == "" {
		r.add(r.configMap("suricata-configs", "suricata", copyMap(gitignorePlaceholder)))
	}
	if r.spec.Zeek.IntelPreseedConfigMap == "" {
		r.add(r.configMap("zeek-intel-preseed", "zeek", map[string]string{
			".gitignore":                 "*\n!.gitignore\n\n",
			"__load__.zeek":              "",
			"MISP_MALDIR_.gitignore":     "*\n!.gitignore\n\n",
			"STIX_MALDIR_.gitignore":     "*\n!.gitignore\n\n",
			"Mandiant_MALDIR_.gitignore": "*\n!.gitignore\n\n",
			"Google_MALDIR_.gitignore":   "*\n!.gitignore\n",
		}))
	}
	if r.spec.Zeek.CustomConfigMap == "" {
		r.add(r.configMap("zeek-custom", "zeek", map[string]string{"__load__.zeek": "# This is a blank file\n"}))
	}
	if r.spec.Arkime.WiseConfigMap == "" {
		r.add(r.configMap("wise-config", "arkime", map[string]string{"wise.ini": asset("wise.ini")}))
	}
	if r.spec.Arkime.LuaConfigMap == "" {
		r.add(r.configMap("arkime-lua", "arkime", nil))
	}
	if r.spec.NetBox.CustomPluginsConfigMap == "" {
		r.add(r.configMap("netbox-custom-plugins", "netbox", nil))
	}
	if r.spec.FileScan.YaraRulesConfigMap == "" {
		r.add(r.configMap("yara-rules", "strelka", copyMap(gitignorePlaceholder)))
	}
	r.add(r.configMap("strelka-backend-config", "strelka", assetDir("strelka/strelka-backend-config")))
	r.add(r.configMap("strelka-frontend-config", "strelka", assetDir("strelka/strelka-frontend-config")))
	r.add(r.configMap("strelka-manager-config", "strelka", assetDir("strelka/strelka-manager-config")))

	if r.authMode() == malcolmv1.AuthModeKeycloakRemote {
		r.add(r.configMap("nginx-auth-keycloak-override", "nginx-proxy", map[string]string{"nginx_auth_keycloak.conf": asset("nginx_auth_keycloak.conf")}))
	}
	if r.coverageEnabled() {
		r.add(r.configMap(r.coverageConfigMapName(), "coverage", map[string]string{".coveragerc": strDefault(r.spec.Coverage.RC, defaultCoverageRC)}))
	}
	if il := r.spec.IndexLifecycle; il != nil {
		r.renderIndexLifecycle(il)
	}
}

func (r *renderer) coverageEnabled() bool { return r.spec.Coverage != nil && r.spec.Coverage.Enabled }
func (r *renderer) coverageConfigMapName() string {
	return "coverage-config-" + r.m.Name
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
