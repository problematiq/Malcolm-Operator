package render

import (
	"encoding/base64"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

// Names of Secrets the rendered workloads consume.
const (
	SecretAuthEnv          = "auth-env"
	SecretNginxAuth        = "etc-nginx-auth"
	SecretNginx            = "etc-nginx"
	SecretCurlrc           = "opensearch-curlrc"
	SecretKeystore         = "opensearch-keystore"
	SecretOpenSearchURLEnv = "opensearch-url-env"
	SecretRemoteCA         = "opensearch-remote-ca"
	SecretValkeyEnv        = "valkey-env"
	SecretValkeyRemoteEnv  = "valkey-remotesensor-env"
	SecretNetBoxEnv        = "netbox-secret-env"
	SecretLogstashEnv      = "logstash-secret-env"
	SecretPostgresEnv      = "postgres-env"
	SecretFilescanEnv      = "filescan-secret-env"
	SecretArkimeEnv        = "arkime-secret-env"
	SecretKeycloakEnv      = "keycloak-env"
)

func (r *renderer) secret(name, component string, data map[string]string) *corev1.Secret {
	b := make(map[string][]byte, len(data))
	for k, v := range data {
		b[k] = []byte(v)
	}
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.ns, Labels: r.labels(component)},
		Type:       corev1.SecretTypeOpaque,
		Data:       b,
	}
}

func (r *renderer) renderSecrets() {
	s := r.in.Secrets
	ports := r.valkeyPorts()

	r.add(r.secret(SecretValkeyEnv, "valkey", map[string]string{
		"VALKEY_PASSWORD":                           s.ValkeyPassword,
		"VALKEY_HOST":                               "valkey",
		"VALKEY_PORT":                               strconv.Itoa(int(ports.Local)),
		"VALKEY_CACHE_HOST":                         "valkey-cache",
		"VALKEY_CACHE_PORT":                         strconv.Itoa(int(ports.LocalCache)),
		"VALKEY_NETBOX_DATABASE":                    "0",
		"VALKEY_ZEEK_FILES_DATABASE":                "1",
		"VALKEY_NETBOX_CACHE_DATABASE":              "0",
		"VALKEY_STRELKA_COORDINATOR_CACHE_DATABASE": "1",
		"VALKEY_STRELKA_GATEKEEPER_CACHE_DATABASE":  "2",
		"VALKEY_FILESCAN_CACHE_DATABASE":            "3",
	}))
	r.add(r.secret(SecretValkeyRemoteEnv, "valkey", map[string]string{
		"VALKEY_PASSWORD":            s.ValkeyRemotePassword,
		"VALKEY_HOST":                "localhost",
		"VALKEY_PORT":                strconv.Itoa(int(ports.Remote)),
		"VALKEY_CACHE_HOST":          "localhost",
		"VALKEY_CACHE_PORT":          strconv.Itoa(int(ports.RemoteCache)),
		"VALKEY_ZEEK_FILES_DATABASE": "1",
		"VALKEY_STRELKA_COORDINATOR_CACHE_DATABASE": "1",
		"VALKEY_STRELKA_GATEKEEPER_CACHE_DATABASE":  "2",
		"VALKEY_FILESCAN_CACHE_DATABASE":            "3",
	}))

	netboxToken := ""
	if r.netboxMode() == malcolmv1.NetBoxModeRemote {
		netboxToken = s.NetBoxRemoteToken
	}
	r.add(r.secret(SecretNetBoxEnv, "netbox", map[string]string{
		"DB_USER":               r.postgresEnv()["POSTGRES_NETBOX_USER"],
		"EMAIL_PASSWORD":        "",
		"EMAIL_USERNAME":        "netbox",
		"NAPALM_PASSWORD":       "",
		"NAPALM_USERNAME":       "",
		"VALKEY_CACHE_PASSWORD": s.ValkeyPassword,
		"VALKEY_PASSWORD":       s.ValkeyPassword,
		"SECRET_KEY":            s.NetBoxSecretKey,
		"SUPERUSER_API_TOKEN":   s.NetBoxAPIToken,
		"SUPERUSER_NAME":        "admin",
		"SUPERUSER_PASSWORD":    s.NetBoxSuperuserPassword,
		"NETBOX_TOKEN":          netboxToken,
	}))

	r.add(r.secret(SecretLogstashEnv, "logstash", map[string]string{"OTKB_TOKEN": s.OTKBToken}))

	pg := r.spec.Postgres
	r.add(r.secret(SecretPostgresEnv, "postgres", r.postgresEnv()))
	for _, extra := range pg.ExtraSecrets {
		data := map[string]string{}
		for k, v := range extra.Data {
			if v == "" {
				v = s.PostgresPassword
			}
			data[k] = v
		}
		r.add(r.secret(extra.Name, "postgres", data))
	}

	r.add(r.secret(SecretFilescanEnv, "filescan", map[string]string{"FILESCAN_HTTP_SERVER_KEY": s.FilescanKey}))

	wiseURL := strDefault(r.spec.Arkime.WiseServiceURL, "http://arkime:8081")
	r.add(r.secret(SecretArkimeEnv, "arkime", map[string]string{
		"MAXMIND_GEOIP_DB_ACCOUNT_ID":             s.MaxMindAccountID,
		"MAXMIND_GEOIP_DB_LICENSE_KEY":            s.MaxMindLicenseKey,
		"MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL": r.spec.MaxMind.AlternateURL,
		"ARKIME_PASSWORD_SECRET":                  s.ArkimePassword,
		"ARKIME_WISE_CONFIG_PIN_CODE":             strDefault(s.ArkimeWisePIN, "WISE2019"),
		"ARKIME_WISE_SERVICE_URL":                 wiseURL,
	}))

	if r.keycloakAny() {
		kc := copyMap(r.env["keycloak"])
		if _, ok := r.spec.Config["keycloak"]["KEYCLOAK_CLIENT_SECRET"]; !ok {
			kc["KEYCLOAK_CLIENT_SECRET"] = s.KeycloakClientSecret
		}
		if _, ok := r.spec.Config["keycloak"]["KC_BOOTSTRAP_ADMIN_USERNAME"]; !ok {
			kc["KC_BOOTSTRAP_ADMIN_USERNAME"] = s.KeycloakAdminUsername
		}
		if _, ok := r.spec.Config["keycloak"]["KC_BOOTSTRAP_ADMIN_PASSWORD"]; !ok {
			kc["KC_BOOTSTRAP_ADMIN_PASSWORD"] = s.KeycloakAdminPassword
		}
		r.add(r.secret(SecretKeycloakEnv, "keycloak", kc))
	}

	if r.usesGeneratedAdmin() {
		r.add(r.secret(SecretAuthEnv, "auth", map[string]string{
			"MALCOLM_USERNAME": s.AdminUsername,
			// Malcolm expects MALCOLM_PASSWORD to be base64(openssl passwd -1 ...).
			"MALCOLM_PASSWORD": base64.StdEncoding.EncodeToString([]byte(s.AdminOpensslHash)),
		}))
		r.add(r.secret(SecretNginxAuth, "auth", map[string]string{"htpasswd": s.AdminHtpasswd}))
	}

	ldap := s.LDAPConfig
	if ldap == "" {
		ldap = asset("nginx_ldap.conf")
	}
	r.add(r.secret(SecretNginx, "nginx-proxy", map[string]string{"nginx_ldap.conf": ldap}))

	primary, secondary := "", ""
	if !r.openSearchLocal() {
		primary = curlrc(r.in.PrimaryCredentials, r.spec.OpenSearch.SSLCertificateVerification)
	}
	if sec := r.spec.OpenSearch.Secondary; sec != nil && sec.URL != "" {
		secondary = curlrc(r.in.SecondaryCredentials, sec.SSLCertificateVerification)
	}
	r.add(r.secret(SecretCurlrc, "opensearch", map[string]string{
		".opensearch.primary.curlrc":   primary,
		".opensearch.secondary.curlrc": secondary,
	}))

	if r.openSearchLocal() && r.componentEnabled("opensearch") {
		r.add(r.secret(SecretKeystore, "opensearch", nil))
	}

	if r.embedCredentials() {
		data := map[string]string{"OPENSEARCH_URL": withCredentials(r.openSearchURL(), r.in.PrimaryCredentials)}
		if u := r.dashboardsURL(); u != "" {
			data["DASHBOARDS_URL"] = withCredentials(u, r.in.PrimaryCredentials)
		}
		r.add(r.secret(SecretOpenSearchURLEnv, "opensearch", data))
	}

	if len(r.in.CACertificate) > 0 {
		r.add(r.secret(SecretRemoteCA, "opensearch", map[string]string{"elastic_ca.crt": string(r.in.CACertificate)}))
	}
}

// curlrc renders a curl config file in the format Malcolm's ParseCurlFile reads.
func curlrc(c *Credentials, verify bool) string {
	var b strings.Builder
	if c != nil && c.Username != "" {
		user := c.Username
		if c.Password != "" {
			user += ":" + c.Password
		}
		b.WriteString(`user: "` + curlEscape(user) + "\"\n")
	}
	if !verify {
		b.WriteString("insecure\n")
	}
	return b.String()
}

func curlEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\t", `\t`, "\n", `\n`, "\r", `\r`, "\v", `\v`).Replace(s)
}

func (r *renderer) valkeyPorts() malcolmv1.ValkeyPorts {
	p := r.spec.Valkey.Ports
	if p.Local == 0 {
		p.Local = 6379
	}
	if p.LocalCache == 0 {
		p.LocalCache = 6380
	}
	if p.Remote == 0 {
		p.Remote = 6381
	}
	if p.RemoteCache == 0 {
		p.RemoteCache = 6382
	}
	return p
}
