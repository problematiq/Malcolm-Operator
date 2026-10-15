package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Profile selects a set of built-in tuning defaults (heap sizes, worker counts,
// memcaps, volume sizes, ...). It is the equivalent of the Helm chart's
// `is_production` switch.
// +kubebuilder:validation:Enum=development;production
type Profile string

const (
	ProfileDevelopment Profile = "development"
	ProfileProduction  Profile = "production"
)

// AuthMode is the authentication method used by Malcolm's nginx reverse proxy.
// +kubebuilder:validation:Enum=basic;ldap;keycloak;keycloak_remote;no_authentication
type AuthMode string

const (
	AuthModeBasic            AuthMode = "basic"
	AuthModeLDAP             AuthMode = "ldap"
	AuthModeKeycloak         AuthMode = "keycloak"
	AuthModeKeycloakRemote   AuthMode = "keycloak_remote"
	AuthModeNoAuthentication AuthMode = "no_authentication"
)

// OpenSearchMode selects where Malcolm stores its data.
// +kubebuilder:validation:Enum=opensearch-local;opensearch-remote;elasticsearch-remote
type OpenSearchMode string

const (
	OpenSearchModeLocal               OpenSearchMode = "opensearch-local"
	OpenSearchModeRemote              OpenSearchMode = "opensearch-remote"
	OpenSearchModeElasticsearchRemote OpenSearchMode = "elasticsearch-remote"
)

// NetBoxMode selects whether NetBox is embedded, remote, or disabled.
// +kubebuilder:validation:Enum=local;remote;disabled
type NetBoxMode string

const (
	NetBoxModeLocal    NetBoxMode = "local"
	NetBoxModeRemote   NetBoxMode = "remote"
	NetBoxModeDisabled NetBoxMode = "disabled"
)

// MalcolmSpec defines the desired state of a Malcolm deployment.
//
// Every field is optional; an empty spec deploys the same set of workloads as
// the Malcolm Helm chart with its default values.yaml.
//
// +kubebuilder:validation:XValidation:rule="!has(self.capture) || !(has(self.capture.netsniff) && self.capture.netsniff && (!has(self.capture.tcpdump) || self.capture.tcpdump))",message="capture.netsniff and capture.tcpdump cannot both be enabled"
// +kubebuilder:validation:XValidation:rule="!has(self.netbox) || !has(self.netbox.mode) || self.netbox.mode != 'remote' || (has(self.netbox.url) && size(self.netbox.url) > 0)",message="netbox.url is required when netbox.mode is remote"
// +kubebuilder:validation:XValidation:rule="!has(self.opensearch) || !has(self.opensearch.mode) || self.opensearch.mode == 'opensearch-local' || (has(self.opensearch.url) && size(self.opensearch.url) > 0)",message="opensearch.url is required when opensearch.mode is not opensearch-local"
// +kubebuilder:validation:XValidation:rule="!has(self.auth) || !has(self.auth.mode) || self.auth.mode != 'keycloak_remote' || (has(self.keycloak) && has(self.keycloak.authURL) && size(self.keycloak.authURL) > 0)",message="keycloak.authURL is required when auth.mode is keycloak_remote"
// +kubebuilder:validation:XValidation:rule="!has(self.maxmind) || !has(self.maxmind.database) || !self.maxmind.database.enabled || (has(self.maxmind.database.updates) && !self.maxmind.database.updates) || (has(self.maxmind.credentialsSecret) && size(self.maxmind.credentialsSecret) > 0) || (has(self.maxmind.alternateURL) && size(self.maxmind.alternateURL) > 0)",message="maxmind.database requires maxmind.credentialsSecret or maxmind.alternateURL unless maxmind.database.updates is false"
// +kubebuilder:validation:XValidation:rule="!has(self.istio) || !has(self.istio.enabled) || !self.istio.enabled || (has(self.istio.host) && size(self.istio.host) > 0)",message="istio.host is required when istio.enabled is true"
type MalcolmSpec struct {
	// Profile selects the built-in tuning defaults.
	// +kubebuilder:default=development
	// +optional
	Profile Profile `json:"profile,omitempty"`

	// Version is the Malcolm release (e.g. 26.09.0) used as the image tag for
	// every Malcolm container unless overridden in image.overrides. Defaults to
	// the release this operator was built against.
	// +kubebuilder:validation:Pattern=`^[0-9A-Za-z][0-9A-Za-z._-]*$`
	// +optional
	Version string `json:"version,omitempty"`

	// Image controls where Malcolm container images are pulled from.
	// +optional
	Image ImageSpec `json:"image,omitempty"`

	// Process controls the unprivileged UID/GID that Malcolm's entrypoints drop to.
	// +optional
	Process ProcessSpec `json:"process,omitempty"`

	// CATrustConfigMap names a ConfigMap of PEM-encoded CA certificates that are
	// imported into every container's OS trust store. When empty, an empty
	// placeholder ConfigMap is created.
	// +optional
	CATrustConfigMap string `json:"caTrustConfigMap,omitempty"`

	// Storage configures the PersistentVolumeClaims used by Malcolm.
	// +optional
	Storage StorageSpec `json:"storage,omitempty"`

	// Auth configures authentication for Malcolm's web interfaces.
	// +optional
	Auth AuthSpec `json:"auth,omitempty"`

	// OpenSearch configures the primary (and optional secondary) data store.
	// +optional
	OpenSearch OpenSearchSpec `json:"opensearch,omitempty"`

	// IndexLifecycle points Logstash output at ILM rollover aliases and installs
	// matching index templates (Helm: siem_env.logstash_override).
	// +optional
	IndexLifecycle *IndexLifecycleSpec `json:"indexLifecycle,omitempty"`

	// Logstash configures log enrichment and ingestion.
	// +optional
	Logstash LogstashSpec `json:"logstash,omitempty"`

	// NetBox configures asset-inventory enrichment.
	// +optional
	NetBox NetBoxSpec `json:"netbox,omitempty"`

	// Postgres configures the PostgreSQL database used by NetBox and Keycloak.
	// +optional
	Postgres PostgresSpec `json:"postgres,omitempty"`

	// Keycloak configures the embedded or remote Keycloak identity provider
	// (used when auth.mode is keycloak or keycloak_remote).
	// +optional
	Keycloak KeycloakSpec `json:"keycloak,omitempty"`

	// Nginx configures Malcolm's internal reverse proxy.
	// +optional
	Nginx NginxSpec `json:"nginx,omitempty"`

	// Ingress configures a Kubernetes Ingress in front of the nginx proxy.
	// +optional
	Ingress IngressSpec `json:"ingress,omitempty"`

	// Istio configures an Istio VirtualService in front of the nginx proxy.
	// +optional
	Istio IstioSpec `json:"istio,omitempty"`

	// NetworkPolicy configures NetworkPolicy resources for the namespace.
	// +optional
	NetworkPolicy NetworkPolicySpec `json:"networkPolicy,omitempty"`

	// Placement controls which nodes run Malcolm's central services
	// (Deployments, StatefulSets and Jobs). Capture DaemonSets are placed by
	// the node selectors under capture.
	// +optional
	Placement PlacementSpec `json:"placement,omitempty"`

	// Capture configures live network traffic capture on labeled nodes.
	// +optional
	Capture CaptureSpec `json:"capture,omitempty"`

	// Zeek settings shared by offline (uploaded PCAP) and live analysis.
	// +optional
	Zeek ZeekSpec `json:"zeek,omitempty"`

	// Suricata settings shared by offline (uploaded PCAP) and live analysis.
	// +optional
	Suricata SuricataSpec `json:"suricata,omitempty"`

	// Arkime settings shared by the viewer and live capture.
	// +optional
	Arkime ArkimeSpec `json:"arkime,omitempty"`

	// FileScan configures scanning of Zeek-extracted files with Strelka.
	// +optional
	FileScan FileScanSpec `json:"filescan,omitempty"`

	// Filebeat configures log shipping.
	// +optional
	Filebeat FilebeatSpec `json:"filebeat,omitempty"`

	// Upload configures the PCAP/log upload interface.
	// +optional
	Upload UploadSpec `json:"upload,omitempty"`

	// Lookup configures enrichment lookups shared by Logstash and freq.
	// +optional
	Lookup LookupSpec `json:"lookup,omitempty"`

	// Valkey configures the Valkey key-value stores.
	// +optional
	Valkey ValkeySpec `json:"valkey,omitempty"`

	// MaxMind configures GeoIP database downloads.
	// +optional
	MaxMind MaxMindSpec `json:"maxmind,omitempty"`

	// Kafka configures forwarding of live Zeek logs to Kafka.
	// +optional
	Kafka KafkaSpec `json:"kafka,omitempty"`

	// Config overrides individual environment variables in the generated
	// configuration. The outer key is the Malcolm environment file name without
	// its extension (as found in Malcolm's ./config directory, e.g. "zeek" for
	// zeek.env, "filebeat" for filebeat.env); the inner map is variable -> value.
	// Values set here take precedence over every typed field and built-in default.
	// +kubebuilder:validation:XValidation:rule="self.all(k, k in ['arkime','arkime-live','arkime-offline','auth-common','beats-common','dashboards','dashboards-helper','filebeat','filescan','kafka','keycloak','logstash','lookup-common','netbox','netbox-common','nginx','opensearch','pcap-capture','pipeline','process','ssl','suricata','suricata-live','suricata-offline','upload-common','zeek','zeek-live','zeek-offline'])",message="unknown config group; see the operator documentation for the list of supported groups"
	// +kubebuilder:validation:MaxProperties=32
	// +optional
	Config map[string]map[string]string `json:"config,omitempty"`

	// Components customizes the pods of individual Malcolm workloads (resources,
	// scheduling, extra env/volumes, sidecars, ...). Keys are component names,
	// e.g. "logstash", "opensearch", "zeek-live".
	// +kubebuilder:validation:XValidation:rule="self.all(k, k in ['api','arkime','arkime-live','cont3xt','dashboards','dashboards-helper','filebeat','filebeat-offline','filescan','freq','htadmin','keycloak','logstash','maxmind-geoip','netbox','nginx-proxy','opensearch','parliament','pcap-capture','pcap-monitor','postgres','postgres-bootstrap','strelka-backend','strelka-frontend','strelka-manager','suricata-live','suricata-offline','upload','valkey','valkey-cache','zeek-live','zeek-live-remotesensor','zeek-offline'])",message="unknown component name; see the operator documentation for the list of components"
	// +kubebuilder:validation:MaxProperties=32
	// +optional
	Components map[string]ComponentSpec `json:"components,omitempty"`

	// Coverage instruments zeek-offline, suricata-offline and suricata-live
	// sidecars for Python code coverage collection (Helm: enable_coverage).
	// +optional
	Coverage *CoverageSpec `json:"coverage,omitempty"`
}

// ImageSpec controls image locations.
type ImageSpec struct {
	// Repository is the registry/path prefix for Malcolm images.
	// +kubebuilder:default="ghcr.io/idaholab/malcolm"
	// +optional
	Repository string `json:"repository,omitempty"`

	// PullPolicy for all Malcolm containers.
	// +kubebuilder:default=IfNotPresent
	// +optional
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`

	// PullSecrets are added to every Malcolm pod.
	// +optional
	PullSecrets []corev1.LocalObjectReference `json:"pullSecrets,omitempty"`

	// Overrides replaces the full image reference for a given Malcolm image name
	// (e.g. "zeek": "registry.example.com/malcolm/zeek:custom"). Image names:
	// api, arkime, dashboards, dashboards-helper, dirinit, file-upload,
	// filebeat-oss, filescan, freq, htadmin, keycloak, logstash-oss, netbox,
	// nginx-proxy, opensearch, pcap-capture, pcap-monitor, postgresql,
	// strelka-backend, strelka-frontend, strelka-manager, suricata, valkey, zeek.
	// +optional
	Overrides map[string]string `json:"overrides,omitempty"`
}

// ProcessSpec configures the in-container unprivileged user.
type ProcessSpec struct {
	// +kubebuilder:default=1000
	// +optional
	PUID *int64 `json:"puid,omitempty"`
	// +kubebuilder:default=1000
	// +optional
	PGID *int64 `json:"pgid,omitempty"`
	// TiniVerbosity for debugging container init.
	// +optional
	TiniVerbosity *int32 `json:"tiniVerbosity,omitempty"`
}

// StorageSpec configures persistent storage.
type StorageSpec struct {
	// StorageClassName is the default StorageClass for every claim. Empty uses the
	// cluster default. The class used for the shared claims (pcap, zeek, suricata,
	// config, runtimeLogs) must support ReadWriteMany.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// RetainOnDelete keeps PersistentVolumeClaims and generated credentials when
	// the Malcolm resource is deleted, so that a re-created instance picks up the
	// existing data and passwords. Defaults to true.
	// +optional
	RetainOnDelete *bool `json:"retainOnDelete,omitempty"`

	// PCAP stores uploaded and captured PCAP (pcap-claim).
	// +optional
	PCAP VolumeClaimSpec `json:"pcap,omitempty"`
	// Zeek stores Zeek logs and extracted files (zeek-claim).
	// +optional
	Zeek VolumeClaimSpec `json:"zeek,omitempty"`
	// Suricata stores Suricata logs from uploaded PCAP (suricata-claim-offline).
	// +optional
	Suricata VolumeClaimSpec `json:"suricata,omitempty"`
	// Config stores persistent configuration (config-claim).
	// +optional
	Config VolumeClaimSpec `json:"config,omitempty"`
	// RuntimeLogs stores runtime logs, e.g. nginx and filescan (runtime-logs-claim).
	// +optional
	RuntimeLogs VolumeClaimSpec `json:"runtimeLogs,omitempty"`
	// OpenSearch is the per-replica OpenSearch data claim template.
	// existingClaim is ignored.
	// +optional
	OpenSearch VolumeClaimSpec `json:"opensearch,omitempty"`
	// OpenSearchBackup is the per-replica OpenSearch snapshot claim template.
	// existingClaim is ignored.
	// +optional
	OpenSearchBackup VolumeClaimSpec `json:"opensearchBackup,omitempty"`
	// Postgres is the PostgreSQL data claim template. existingClaim is ignored.
	// +optional
	Postgres VolumeClaimSpec `json:"postgres,omitempty"`
}

// VolumeClaimSpec configures one persistent volume claim.
type VolumeClaimSpec struct {
	// Size of the claim. Defaults depend on the profile.
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`
	// StorageClassName overrides storage.storageClassName for this claim.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`
	// AccessModes overrides the default access modes (ReadWriteMany for shared
	// claims, ReadWriteOnce for StatefulSet claims).
	// +optional
	AccessModes []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`
	// ExistingClaim uses a pre-provisioned PersistentVolumeClaim instead of
	// creating one (for example, NFS-backed claims created by an administrator).
	// +optional
	ExistingClaim string `json:"existingClaim,omitempty"`
	// Selector restricts binding to matching PersistentVolumes.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// SecretKeyRef references a key in a Secret in the Malcolm namespace.
type SecretKeyRef struct {
	// Name of the Secret.
	Name string `json:"name"`
	// Key within the Secret.
	Key string `json:"key"`
}

// AuthSpec configures authentication.
type AuthSpec struct {
	// Mode is the authentication method for the nginx reverse proxy.
	// +kubebuilder:default=basic
	// +optional
	Mode AuthMode `json:"mode,omitempty"`

	// AdminSecret names a Secret holding the plaintext administrator
	// credentials under the keys "username" and "password". The operator
	// derives the MD5-crypt and bcrypt hashes Malcolm needs. When neither
	// adminSecret nor hashedCredentials is set, the operator generates
	// <name>-admin-credentials with username "malcolm" and a random password.
	// +optional
	AdminSecret string `json:"adminSecret,omitempty"`

	// HashedCredentials uses a Helm-chart-compatible Secret with pre-hashed
	// credentials (Helm: auth.existingSecret) instead of adminSecret.
	// +optional
	HashedCredentials *HashedCredentialsSpec `json:"hashedCredentials,omitempty"`

	// LDAPConfigSecret names a Secret whose "nginx_ldap.conf" key holds the
	// nginx ldap_server configuration used when mode is ldap. A sample
	// configuration is used when empty.
	// +optional
	LDAPConfigSecret string `json:"ldapConfigSecret,omitempty"`

	// RequireGroups lists groups a Keycloak user must belong to.
	// +optional
	RequireGroups []string `json:"requireGroups,omitempty"`
	// RequireRoles lists roles a Keycloak user must hold.
	// +optional
	RequireRoles []string `json:"requireRoles,omitempty"`
	// RoleBasedAccess enables Keycloak role-based access control. Individual role
	// names can be changed via config["auth-common"] (ROLE_ADMIN, ...).
	// +optional
	RoleBasedAccess bool `json:"roleBasedAccess,omitempty"`
}

// HashedCredentialsSpec references a Secret with pre-hashed credentials.
type HashedCredentialsSpec struct {
	// SecretName of the Secret.
	SecretName string `json:"secretName"`
	// +kubebuilder:default=username
	// +optional
	UsernameKey string `json:"usernameKey,omitempty"`
	// OpensslPasswordKey holds base64(openssl passwd -1 <password>).
	// +kubebuilder:default=openssl_password
	// +optional
	OpensslPasswordKey string `json:"opensslPasswordKey,omitempty"`
	// HtpasswdKey holds the output of htpasswd -bnB <username> <password>.
	// +kubebuilder:default=htpass_cred
	// +optional
	HtpasswdKey string `json:"htpasswdKey,omitempty"`
}

// OpenSearchSpec configures the data store.
type OpenSearchSpec struct {
	// Mode selects a local OpenSearch StatefulSet or a remote cluster.
	// +kubebuilder:default=opensearch-local
	// +optional
	Mode OpenSearchMode `json:"mode,omitempty"`

	// URL of the primary store. Defaults to https://opensearch:9200 for local mode;
	// required for remote modes.
	// +optional
	URL string `json:"url,omitempty"`

	// CredentialsSecret names a Secret with "username" and "password" keys for a
	// remote primary store.
	// +optional
	CredentialsSecret string `json:"credentialsSecret,omitempty"`

	// EmbedCredentialsInURL also embeds the remote credentials in OPENSEARCH_URL
	// and DASHBOARDS_URL (as the Helm chart does). The resulting URLs are stored
	// in a Secret, never in a ConfigMap. Defaults to true.
	// +optional
	EmbedCredentialsInURL *bool `json:"embedCredentialsInURL,omitempty"`

	// SSLCertificateVerification requires full TLS validation of the primary store.
	// +optional
	SSLCertificateVerification bool `json:"sslCertificateVerification,omitempty"`

	// DashboardsURL is the internal URL of OpenSearch Dashboards or Kibana.
	// Defaults to http://dashboards:5601/dashboards in local mode.
	// +optional
	DashboardsURL string `json:"dashboardsURL,omitempty"`

	// ExternalDashboardsURL is the browser-facing Dashboards/Kibana URL linked
	// from the Malcolm landing page when a remote store is used.
	// +optional
	ExternalDashboardsURL string `json:"externalDashboardsURL,omitempty"`

	// CACertificate copies a CA certificate (e.g. an Elasticsearch http CA) from
	// any namespace into the Malcolm namespace and mounts it into Arkime.
	// +optional
	CACertificate *CrossNamespaceSecretKeyRef `json:"caCertificate,omitempty"`

	// Local configures the operator-managed OpenSearch StatefulSet.
	// +optional
	Local OpenSearchLocalSpec `json:"local,omitempty"`

	// Secondary forwards logs to an additional remote store.
	// +optional
	Secondary *OpenSearchSecondarySpec `json:"secondary,omitempty"`
}

// CrossNamespaceSecretKeyRef references a key in a Secret in any namespace.
type CrossNamespaceSecretKeyRef struct {
	// Name of the Secret.
	Name string `json:"name"`
	// Namespace of the Secret; defaults to the Malcolm namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// Key within the Secret.
	// +kubebuilder:default="ca.crt"
	// +optional
	Key string `json:"key,omitempty"`
}

// OpenSearchLocalSpec configures the local OpenSearch cluster.
type OpenSearchLocalSpec struct {
	// Replicas is the number of OpenSearch nodes. 1 runs in single-node mode;
	// more than 1 requires transportCASecret.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=1
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`
	// DefaultReplicaCount is the number of replica shards for new indices in a
	// multi-node cluster (always 0 in single-node mode).
	// +kubebuilder:validation:Minimum=0
	// +optional
	DefaultReplicaCount *int32 `json:"defaultReplicaCount,omitempty"`
	// TransportCASecret names a Secret with ca.crt and ca.key used to secure
	// node-to-node transport in a multi-node cluster.
	// +optional
	TransportCASecret string `json:"transportCASecret,omitempty"`
	// JavaMemory are the heap/stack JVM flags, e.g. "-Xmx10g -Xms10g -Xss256k".
	// Defaults depend on the profile.
	// +optional
	JavaMemory string `json:"javaMemory,omitempty"`
	// MaxShardsPerNode sets cluster.max_shards_per_node. Defaults depend on the profile.
	// +optional
	MaxShardsPerNode *int32 `json:"maxShardsPerNode,omitempty"`
	// MaxLockedMemory is the memlock limit (default "unlimited").
	// +optional
	MaxLockedMemory string `json:"maxLockedMemory,omitempty"`
}

// OpenSearchSecondarySpec configures a secondary remote store.
type OpenSearchSecondarySpec struct {
	// +kubebuilder:validation:Enum=opensearch-remote;elasticsearch-remote
	// +kubebuilder:default=opensearch-remote
	// +optional
	Mode OpenSearchMode `json:"mode,omitempty"`
	// URL of the secondary store.
	URL string `json:"url"`
	// CredentialsSecret names a Secret with "username" and "password" keys.
	// +optional
	CredentialsSecret string `json:"credentialsSecret,omitempty"`
	// +optional
	SSLCertificateVerification bool `json:"sslCertificateVerification,omitempty"`
}

// IndexLifecycleSpec configures ILM/ISM rollover output.
type IndexLifecycleSpec struct {
	// +kubebuilder:default=nta
	// +optional
	ILMPolicy string `json:"ilmPolicy,omitempty"`
	// +kubebuilder:default=malcolm_network_zeek
	// +optional
	RolloverAliasZeek string `json:"rolloverAliasZeek,omitempty"`
	// +kubebuilder:default=malcolm_network_suricata
	// +optional
	RolloverAliasSuricata string `json:"rolloverAliasSuricata,omitempty"`
	// +kubebuilder:default=malcolm_beats
	// +optional
	RolloverAliasBeats string `json:"rolloverAliasBeats,omitempty"`
	// +kubebuilder:default=sensor-status
	// +optional
	DefaultBeatsPipeline string `json:"defaultBeatsPipeline,omitempty"`
	// +kubebuilder:default=logs
	// +optional
	ILMBeatsPolicy string `json:"ilmBeatsPolicy,omitempty"`
	// +kubebuilder:default=malcolm_network
	// +optional
	SearchAlias string `json:"searchAlias,omitempty"`
	// +kubebuilder:default="2"
	// +optional
	NumberOfShards string `json:"numberOfShards,omitempty"`
	// +kubebuilder:default="1"
	// +optional
	NumberOfReplicas string `json:"numberOfReplicas,omitempty"`
}

// LogstashSpec configures Logstash.
type LogstashSpec struct {
	// Replicas fixes the number of Logstash pods. When unset, the operator runs
	// max(1, N/2) replicas where N is the number of nodes matching
	// nodeCountLabel, and re-evaluates as nodes are labeled or removed.
	// +kubebuilder:validation:Minimum=0
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`
	// NodeCountLabel selects the nodes counted for automatic replica sizing.
	// Defaults to cnaps.io/node-type=Tier-1.
	// +optional
	NodeCountLabel *NodeLabel `json:"nodeCountLabel,omitempty"`
	// JavaMemory JVM flags, e.g. "-Xmx3g -Xms3g -Xss2048k". Defaults depend on the profile.
	// +optional
	JavaMemory string `json:"javaMemory,omitempty"`
	// Workers is pipeline.workers. Defaults depend on the profile.
	// +optional
	Workers *int32 `json:"workers,omitempty"`
	// BatchSize is pipeline.batch.size.
	// +optional
	BatchSize *int32 `json:"batchSize,omitempty"`
	// BatchDelay is pipeline.batch.delay (milliseconds).
	// +optional
	BatchDelay *int32 `json:"batchDelay,omitempty"`
	// ServiceType of the logstash Service (ClusterIP or LoadBalancer).
	// +optional
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
	// OTKB configures MITRE OT Knowledge Base enrichment.
	// +optional
	OTKB *OTKBSpec `json:"otkb,omitempty"`
}

// NodeLabel is a label key/value pair.
type NodeLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// OTKBSpec configures MITRE OTKB enrichment.
type OTKBSpec struct {
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// URL of the OTKB service.
	// +optional
	URL string `json:"url,omitempty"`
	// TokenSecret references the OTKB API token.
	// +optional
	TokenSecret *SecretKeyRef `json:"tokenSecret,omitempty"`
}

// NetBoxSpec configures NetBox.
type NetBoxSpec struct {
	// +kubebuilder:default=local
	// +optional
	Mode NetBoxMode `json:"mode,omitempty"`
	// URL of a remote NetBox (mode remote).
	// +optional
	URL string `json:"url,omitempty"`
	// TokenSecret references the API token of a remote NetBox.
	// +optional
	TokenSecret *SecretKeyRef `json:"tokenSecret,omitempty"`
	// Enrichment enables NetBox enrichment of Logstash data. Defaults to true.
	// +optional
	Enrichment *bool `json:"enrichment,omitempty"`
	// EnrichmentDatasets lists which logs are enriched (provider.dataset pairs,
	// "default", "ics"/"ot", or "all"). Defaults to ["default"].
	// +optional
	EnrichmentDatasets []string `json:"enrichmentDatasets,omitempty"`
	// AutoPopulate creates NetBox entries for unobserved hosts. Defaults to true.
	// +optional
	AutoPopulate *bool `json:"autoPopulate,omitempty"`
	// AutoPopulateSubnets controls which subnets are eligible for autopopulation;
	// prefix a CIDR with "!" to exclude it.
	// +optional
	AutoPopulateSubnets []string `json:"autoPopulateSubnets,omitempty"`
	// DefaultSite is the NetBox site created on initialization. Defaults to "Malcolm".
	// +optional
	DefaultSite string `json:"defaultSite,omitempty"`
	// CSRFTrustedOrigins for the reverse proxy URL(s), space separated.
	// Defaults to the istio host when istio is enabled, otherwise "http://* https://*".
	// +optional
	CSRFTrustedOrigins string `json:"csrfTrustedOrigins,omitempty"`
	// CustomPluginsConfigMap names a ConfigMap of NetBox plugins to install.
	// +optional
	CustomPluginsConfigMap string `json:"customPluginsConfigMap,omitempty"`
}

// PostgresSpec configures PostgreSQL.
// +kubebuilder:validation:XValidation:rule="!has(self.mode) || self.mode != 'external' || (has(self.external) && size(self.external.host) > 0)",message="postgres.external.host is required when postgres.mode is external"
type PostgresSpec struct {
	// Mode selects the in-cluster PostgreSQL StatefulSet (local), an existing
	// server (external), or no PostgreSQL at all (disabled; NetBox must then be
	// remote or disabled and Keycloak unused). Defaults to local, or to disabled
	// when enabled is false.
	// +kubebuilder:validation:Enum=local;external;disabled
	// +optional
	Mode PostgresMode `json:"mode,omitempty"`
	// External configures the connection to an existing PostgreSQL server.
	// +optional
	External *PostgresExternalSpec `json:"external,omitempty"`
	// Enabled deploys the PostgreSQL StatefulSet. Deprecated: use mode.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// Host of the local PostgreSQL server. Defaults to "postgres". For an
	// external server use external.host.
	// +optional
	Host string `json:"host,omitempty"`
	// PasswordSecret supplies the database password; one is generated when unset.
	// +optional
	PasswordSecret *SecretKeyRef `json:"passwordSecret,omitempty"`
	// NetBoxDatabase name. Defaults to "netbox".
	// +optional
	NetBoxDatabase string `json:"netboxDatabase,omitempty"`
	// KeycloakDatabase name. Defaults to "keycloak".
	// +optional
	KeycloakDatabase string `json:"keycloakDatabase,omitempty"`
	// ExtraSecrets creates additional Secrets for custom database integrations.
	// Empty values are filled with the PostgreSQL password.
	// +optional
	ExtraSecrets []PostgresExtraSecret `json:"extraSecrets,omitempty"`
}

// PostgresMode selects where PostgreSQL runs.
type PostgresMode string

const (
	PostgresModeLocal    PostgresMode = "local"
	PostgresModeExternal PostgresMode = "external"
	PostgresModeDisabled PostgresMode = "disabled"
)

// PostgresExternalSpec describes an existing PostgreSQL server.
type PostgresExternalSpec struct {
	// Host name or address of the server.
	Host string `json:"host"`
	// Port of the server.
	// +kubebuilder:default=5432
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`
	// SSLMode is the libpq sslmode used by NetBox and Malcolm's readiness checks.
	// Keycloak's JDBC driver always uses its default ("prefer": TLS when the
	// server offers it, without certificate verification).
	// +kubebuilder:validation:Enum=disable;allow;prefer;require;verify-ca;verify-full
	// +kubebuilder:default=prefer
	// +optional
	SSLMode string `json:"sslMode,omitempty"`
	// MaintenanceDatabase is the database Malcolm connects to when checking
	// that the application databases exist. Defaults to "postgres".
	// +optional
	MaintenanceDatabase string `json:"maintenanceDatabase,omitempty"`
	// NetBox database and credentials.
	// +optional
	NetBox PostgresDatabaseSpec `json:"netbox,omitempty"`
	// Keycloak database and credentials.
	// +optional
	Keycloak PostgresDatabaseSpec `json:"keycloak,omitempty"`
	// Bootstrap creates the application roles and databases if they are
	// missing, using administrator credentials (the same steps Malcolm's own
	// PostgreSQL image performs). Without it the databases must already exist.
	// +optional
	Bootstrap *PostgresBootstrapSpec `json:"bootstrap,omitempty"`
}

// PostgresDatabaseSpec names an application database and its login.
type PostgresDatabaseSpec struct {
	// Database name. Defaults to "netbox" or "keycloak".
	// +optional
	Database string `json:"database,omitempty"`
	// CredentialsSecret names a Secret with "username" and "password" keys.
	// When unset, the user "netbox"/"keycloak" with a generated password is
	// used, which requires bootstrap to create it.
	// +optional
	CredentialsSecret string `json:"credentialsSecret,omitempty"`
}

// PostgresBootstrapSpec configures creation of roles and databases.
type PostgresBootstrapSpec struct {
	// AdminCredentialsSecret names a Secret with "username" and "password" keys
	// of a role allowed to create roles and databases.
	AdminCredentialsSecret string `json:"adminCredentialsSecret"`
}

// PostgresExtraSecret is an additional Secret for a custom database.
type PostgresExtraSecret struct {
	Name string            `json:"name"`
	Data map[string]string `json:"data,omitempty"`
}

// KeycloakSpec configures Keycloak.
type KeycloakSpec struct {
	// +kubebuilder:default=master
	// +optional
	AuthRealm string `json:"authRealm,omitempty"`
	// +kubebuilder:default="/index.html"
	// +optional
	AuthRedirectURI string `json:"authRedirectURI,omitempty"`
	// AuthURL of the Keycloak server (required for keycloak_remote).
	// +optional
	AuthURL string `json:"authURL,omitempty"`
	// +optional
	ClientID string `json:"clientID,omitempty"`
	// ClientSecret references the OIDC client secret.
	// +optional
	ClientSecret *SecretKeyRef `json:"clientSecret,omitempty"`
	// +optional
	SSLVerify bool `json:"sslVerify,omitempty"`
	// Hostname sets KC_HOSTNAME for the embedded instance.
	// +optional
	Hostname string `json:"hostname,omitempty"`
	// BootstrapAdminSecret names a Secret with "username" and "password" keys
	// for the embedded instance's bootstrap administrator; generated when unset.
	// +optional
	BootstrapAdminSecret string `json:"bootstrapAdminSecret,omitempty"`
}

// NginxSpec configures the internal reverse proxy.
type NginxSpec struct {
	// ServiceType of the nginx-proxy Service. Use LoadBalancer to expose Malcolm
	// without an ingress controller.
	// +kubebuilder:default=ClusterIP
	// +optional
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
	// ServiceAnnotations are added to the nginx-proxy Service.
	// +optional
	ServiceAnnotations map[string]string `json:"serviceAnnotations,omitempty"`
	// XForwardedProtoOverride, e.g. "https" when TLS is terminated in front of Malcolm.
	// +optional
	XForwardedProtoOverride string `json:"xForwardedProtoOverride,omitempty"`
	// CSPFormActionExtra lists additional CSP form-action targets (e.g. for SAML).
	// +optional
	CSPFormActionExtra []string `json:"cspFormActionExtra,omitempty"`
}

// IngressSpec configures the Kubernetes Ingress.
type IngressSpec struct {
	// Enabled creates an Ingress. Defaults to true.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// ClassName of the ingress controller. Defaults to "traefik".
	// +optional
	ClassName *string `json:"className,omitempty"`
	// Host restricts the default rule to a hostname.
	// +optional
	Host string `json:"host,omitempty"`
	// TLSSecretName enables TLS for host using this certificate Secret.
	// +optional
	TLSSecretName string `json:"tlsSecretName,omitempty"`
	// Annotations are added to the Ingress.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
	// NginxProxyBufferBypass adds annotations disabling proxy buffering when
	// className is nginx (needed for large uploads). Defaults to true.
	// +optional
	NginxProxyBufferBypass *bool `json:"nginxProxyBufferBypass,omitempty"`
	// Rules replaces the generated rules entirely.
	// +optional
	Rules []networkingv1.IngressRule `json:"rules,omitempty"`
	// TLS replaces the generated TLS configuration entirely.
	// +optional
	TLS []networkingv1.IngressTLS `json:"tls,omitempty"`
}

// IstioSpec configures an Istio VirtualService.
type IstioSpec struct {
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// Gateway in namespace/name form. Defaults to istio-system/tenant.
	// +optional
	Gateway string `json:"gateway,omitempty"`
	// Host served by the VirtualService, e.g. malcolm.vp.bigbang.dev.
	// +optional
	Host string `json:"host,omitempty"`
	// Namespace where Istio's ingress gateway runs. Defaults to istio-system.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// NetworkPolicySpec configures NetworkPolicies.
type NetworkPolicySpec struct {
	// Enabled creates policies that allow traffic within the namespace and block
	// other ingress/egress.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// NodeCIDR covers all cluster nodes; Arkime is allowed to reach port 8005 on
	// nodes in this range to retrieve PCAP from live capture. Defaults to 10.0.0.0/8.
	// +optional
	NodeCIDR string `json:"nodeCIDR,omitempty"`
	// AdditionalEgress rules, e.g. to reach a remote Elasticsearch/Kibana.
	// +optional
	AdditionalEgress []networkingv1.NetworkPolicyEgressRule `json:"additionalEgress,omitempty"`
	// AdditionalIngress rules.
	// +optional
	AdditionalIngress []networkingv1.NetworkPolicyIngressRule `json:"additionalIngress,omitempty"`
}

// PlacementSpec controls workload placement.
type PlacementSpec struct {
	// Server applies to every Deployment, StatefulSet and Job.
	// +optional
	Server ServerPlacementSpec `json:"server,omitempty"`
}

// ServerPlacementSpec places Malcolm's central services.
type ServerPlacementSpec struct {
	// NodeSelector restricts central services to matching nodes, e.g.
	// {"cnaps.io/node-type": "Tier-1"}. spec.components[*].nodeSelector is
	// merged on top.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Tolerations added to central services.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// AvoidCaptureNodes keeps central services off every node selected by an
	// enabled capture DaemonSet (capture.*.nodeSelector), so capture nodes run
	// only the capture DaemonSets. Leave it off when one node does everything.
	// A component's own affinity (spec.components[*].affinity) replaces this rule.
	// +optional
	AvoidCaptureNodes bool `json:"avoidCaptureNodes,omitempty"`
}

// CaptureSpec configures live traffic capture.
type CaptureSpec struct {
	// Interfaces to capture on (PCAP_IFACE). Defaults to ["ens192"].
	// +optional
	Interfaces []string `json:"interfaces,omitempty"`
	// Filter is a tcpdump-style capture filter.
	// +optional
	Filter string `json:"filter,omitempty"`
	// HomeNet defines local networks for Zeek (Site::local_nets) and Suricata
	// (HOME_NET). Defaults to the RFC 1918 ranges.
	// +optional
	HomeNet []string `json:"homeNet,omitempty"`
	// Netsniff uses netsniff-ng to write PCAP for Arkime (pcapCapture only).
	// +optional
	Netsniff *bool `json:"netsniff,omitempty"`
	// Tcpdump uses tcpdump to write PCAP for Arkime (pcapCapture only). Defaults to true.
	// +optional
	Tcpdump *bool `json:"tcpdump,omitempty"`
	// RotateMegabytes closes captured PCAP files at this size. Defaults to 4.
	// +optional
	RotateMegabytes *int32 `json:"rotateMegabytes,omitempty"`
	// RotateMinutes closes captured PCAP files after this interval. Defaults to 10.
	// +optional
	RotateMinutes *int32 `json:"rotateMinutes,omitempty"`
	// InterfaceTweak disables NIC offloading and tunes ring buffers. Defaults to true.
	// +optional
	InterfaceTweak *bool `json:"interfaceTweak,omitempty"`
	// StatsCronExpression collects interface statistics periodically.
	// +optional
	StatsCronExpression string `json:"statsCronExpression,omitempty"`
	// Tolerations applied to every capture DaemonSet.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// HostPaths are the node directories used by capture DaemonSets.
	// +optional
	HostPaths CaptureHostPaths `json:"hostPaths,omitempty"`

	// Zeek live capture.
	// +optional
	Zeek ZeekLiveSpec `json:"zeek,omitempty"`
	// Suricata live capture.
	// +optional
	Suricata LiveCaptureSpec `json:"suricata,omitempty"`
	// Arkime live capture.
	// +optional
	Arkime ArkimeLiveSpec `json:"arkime,omitempty"`
	// PCAP writes PCAP files with tcpdump/netsniff-ng for offline processing.
	// Disabled by default.
	// +optional
	PCAP LiveCaptureSpec `json:"pcap,omitempty"`
}

// CaptureHostPaths are node-local directories used by capture DaemonSets.
type CaptureHostPaths struct {
	// +kubebuilder:default="/var/lib/malcolm/zeek-logs"
	// +optional
	ZeekLogs string `json:"zeekLogs,omitempty"`
	// +kubebuilder:default="/var/lib/malcolm/extracted-files"
	// +optional
	ZeekExtractedFiles string `json:"zeekExtractedFiles,omitempty"`
	// +kubebuilder:default="/var/lib/malcolm/suricata-logs"
	// +optional
	SuricataLogs string `json:"suricataLogs,omitempty"`
	// +kubebuilder:default="/var/lib/malcolm/arkime-pcap"
	// +optional
	ArkimePCAP string `json:"arkimePCAP,omitempty"`
	// +kubebuilder:default="/var/lib/malcolm/filescan-logs"
	// +optional
	FilescanLogs string `json:"filescanLogs,omitempty"`
	// +kubebuilder:default="/var/lib/malcolm/valkey-aof"
	// +optional
	ValkeyAOF string `json:"valkeyAOF,omitempty"`
}

// LiveCaptureSpec enables a capture DaemonSet on labeled nodes.
type LiveCaptureSpec struct {
	// Enabled creates the DaemonSet.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// NodeSelector picks the capture nodes.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// ZeekLiveSpec configures live Zeek capture.
type ZeekLiveSpec struct {
	LiveCaptureSpec `json:",inline"`
	// RemoteSensor runs a self-contained "hedgehog" sensor pod (Zeek, filescan,
	// Strelka, Valkey and Filebeat) on nodes matching its nodeSelector.
	// +optional
	RemoteSensor LiveCaptureSpec `json:"remoteSensor,omitempty"`
}

// ArkimeLiveSpec configures live Arkime capture.
type ArkimeLiveSpec struct {
	LiveCaptureSpec `json:",inline"`
	// NodeHost associates capture metadata with this host instead of the node name.
	// +optional
	NodeHost string `json:"nodeHost,omitempty"`
}

// ZeekSpec configures Zeek.
type ZeekSpec struct {
	// ExtractMode determines which files Zeek extracts from traffic.
	// +kubebuilder:validation:Enum=none;interesting;notcommtxt;mapped;known;all
	// +kubebuilder:default=interesting
	// +optional
	ExtractMode string `json:"extractMode,omitempty"`
	// CustomConfigMap names a ConfigMap of custom Zeek scripts (must contain
	// __load__.zeek). An empty placeholder is used when unset.
	// +optional
	CustomConfigMap string `json:"customConfigMap,omitempty"`
	// IntelPreseedConfigMap names a ConfigMap of Zeek Intelligence Framework files.
	// +optional
	IntelPreseedConfigMap string `json:"intelPreseedConfigMap,omitempty"`
	// AutoAnalyzeUploads analyzes uploaded PCAP with Zeek. Defaults to true.
	// +optional
	AutoAnalyzeUploads *bool `json:"autoAnalyzeUploads,omitempty"`
}

// SuricataSpec configures Suricata.
type SuricataSpec struct {
	// RulesConfigMap names a ConfigMap of custom Suricata rules.
	// +optional
	RulesConfigMap string `json:"rulesConfigMap,omitempty"`
	// ConfigsConfigMap names a ConfigMap of Suricata include-config YAML files.
	// +optional
	ConfigsConfigMap string `json:"configsConfigMap,omitempty"`
	// CustomRulesOnly ignores the default ruleset.
	// +optional
	CustomRulesOnly bool `json:"customRulesOnly,omitempty"`
	// UpdateRules periodically runs suricata-update.
	// +optional
	UpdateRules bool `json:"updateRules,omitempty"`
	// EnableSources lists suricata-update sources (e.g. "et/open",
	// "et/pro|secret-code=..."). Defaults to ["et/open"].
	// +optional
	EnableSources []string `json:"enableSources,omitempty"`
	// DisableSIDs lists rule SIDs to disable.
	// +optional
	DisableSIDs []string `json:"disableSIDs,omitempty"`
	// AutoAnalyzeUploads analyzes uploaded PCAP with Suricata. Defaults to true.
	// +optional
	AutoAnalyzeUploads *bool `json:"autoAnalyzeUploads,omitempty"`
}

// ArkimeSpec configures Arkime.
type ArkimeSpec struct {
	// PasswordSecret supplies Arkime's cluster passwordSecret; generated when unset.
	// +optional
	PasswordSecret *SecretKeyRef `json:"passwordSecret,omitempty"`
	// WisePINSecret supplies the WISE configuration GUI PIN. Defaults to "WISE2019".
	// +optional
	WisePINSecret *SecretKeyRef `json:"wisePINSecret,omitempty"`
	// ExposeWiseGUI serves the WISE web interface at /wise through the nginx
	// proxy (WISE runs in the arkime pod). Defaults to true.
	// +optional
	ExposeWiseGUI *bool `json:"exposeWiseGUI,omitempty"`
	// AllowWiseGUIConfig makes the WISE web interface editable (protected by
	// the PIN from wisePINSecret) instead of read-only.
	// +optional
	AllowWiseGUIConfig bool `json:"allowWiseGUIConfig,omitempty"`
	// WiseServiceURL used by live Arkime capture. Defaults to http://arkime:8081.
	// +optional
	WiseServiceURL string `json:"wiseServiceURL,omitempty"`
	// LuaConfigMap names a ConfigMap of custom Arkime Lua scripts.
	// +optional
	LuaConfigMap string `json:"luaConfigMap,omitempty"`
	// WiseConfigMap names a ConfigMap with a "wise.ini" key replacing the default.
	// +optional
	WiseConfigMap string `json:"wiseConfigMap,omitempty"`
	// AutoAnalyzeUploads analyzes uploaded PCAP with Arkime. Defaults to true.
	// +optional
	AutoAnalyzeUploads *bool `json:"autoAnalyzeUploads,omitempty"`
	// Parliament runs Arkime Parliament (Service parliament:8008), a dashboard
	// of Arkime clusters, preconfigured with this Malcolm's Arkime. The nginx
	// image must route /parliament/ to it (see docs/nginx-parliament.conf).
	// +optional
	Parliament ArkimeAppSpec `json:"parliament,omitempty"`
	// Cont3xt runs Arkime Cont3xt (Service cont3xt:3218), served at /cont3xt/
	// by an nginx image that routes it there.
	// +optional
	Cont3xt ArkimeAppSpec `json:"cont3xt,omitempty"`
}

// ArkimeAppSpec enables an additional Arkime web application.
type ArkimeAppSpec struct {
	// Enabled deploys the application.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
}

// FileScanSpec configures file scanning.
type FileScanSpec struct {
	// Disabled turns off Strelka file scanning.
	// +optional
	Disabled bool `json:"disabled,omitempty"`
	// Scanners lists enabled Strelka scanners. Defaults to ["default"].
	// +optional
	Scanners []string `json:"scanners,omitempty"`
	// YaraRulesConfigMap names a ConfigMap of custom YARA rules.
	// +optional
	YaraRulesConfigMap string `json:"yaraRulesConfigMap,omitempty"`
	// HTTPServerKeySecret supplies the password for extracted files served over
	// HTTP; generated when unset.
	// +optional
	HTTPServerKeySecret *SecretKeyRef `json:"httpServerKeySecret,omitempty"`
	// RemoteSensorHTTPServer serves extracted files from remote sensors. Defaults to false.
	// +optional
	RemoteSensorHTTPServer *bool `json:"remoteSensorHTTPServer,omitempty"`
	// RemoteSensorPreservation is the preservation policy on remote sensors.
	// Defaults to "none".
	// +optional
	RemoteSensorPreservation string `json:"remoteSensorPreservation,omitempty"`
}

// FilebeatSpec configures Filebeat.
type FilebeatSpec struct {
	// DaemonSetNodeAffinity replaces the derived node affinity of the live
	// filebeat DaemonSet. By default it runs on nodes selected for live Zeek or
	// Suricata capture that are not remote sensors.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Type=object
	DaemonSetNodeAffinity *corev1.NodeAffinity `json:"daemonSetNodeAffinity,omitempty"`
	// ServiceType of the filebeat Service (ClusterIP or LoadBalancer).
	// +optional
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
}

// UploadSpec configures uploads.
type UploadSpec struct {
	// ExtraTags are applied to all data generated by Malcolm.
	// +optional
	ExtraTags []string `json:"extraTags,omitempty"`
	// MaxFileGB is the maximum uploadable file size. Defaults to 50.
	// +optional
	MaxFileGB *int32 `json:"maxFileGB,omitempty"`
}

// LookupSpec configures enrichment lookups.
type LookupSpec struct {
	// SensitiveCountryCodes (ISO 3166-1 alpha-2) used for severity scoring.
	// +optional
	SensitiveCountryCodes []string `json:"sensitiveCountryCodes,omitempty"`
}

// ValkeySpec configures Valkey.
type ValkeySpec struct {
	// MaxMemory for the persistent store ("0" = no limit).
	// +optional
	MaxMemory string `json:"maxMemory,omitempty"`
	// MaxMemoryPolicy for the persistent store. Defaults to allkeys-lru.
	// +optional
	MaxMemoryPolicy string `json:"maxMemoryPolicy,omitempty"`
	// CacheMaxMemory for the cache ("0" = no limit).
	// +optional
	CacheMaxMemory string `json:"cacheMaxMemory,omitempty"`
	// CacheMaxMemoryPolicy for the cache. Defaults to allkeys-lru.
	// +optional
	CacheMaxMemoryPolicy string `json:"cacheMaxMemoryPolicy,omitempty"`
	// AutoAOFRewriteMinSize for the persistent store. Defaults to 64mb.
	// +optional
	AutoAOFRewriteMinSize string `json:"autoAOFRewriteMinSize,omitempty"`
	// Ports used by the central (local) and remote-sensor Valkey instances.
	// +optional
	Ports ValkeyPorts `json:"ports,omitempty"`
}

// ValkeyPorts are Valkey listening ports.
type ValkeyPorts struct {
	// +kubebuilder:default=6379
	// +optional
	Local int32 `json:"local,omitempty"`
	// +kubebuilder:default=6380
	// +optional
	LocalCache int32 `json:"localCache,omitempty"`
	// +kubebuilder:default=6381
	// +optional
	Remote int32 `json:"remote,omitempty"`
	// +kubebuilder:default=6382
	// +optional
	RemoteCache int32 `json:"remoteCache,omitempty"`
}

// MaxMindSpec configures GeoIP downloads.
type MaxMindSpec struct {
	// CredentialsSecret names a Secret with "accountID" and "licenseKey" keys.
	// +optional
	CredentialsSecret string `json:"credentialsSecret,omitempty"`
	// AlternateURL for downloading MMDB tarballs.
	// +optional
	AlternateURL string `json:"alternateURL,omitempty"`
	// Database deploys a shared GeoIP database volume that is kept up to date
	// centrally and mounted into Arkime (including the arkime-live capture
	// DaemonSet), so capture nodes need no Internet access for GeoIP lookups.
	// +optional
	Database *GeoIPDatabaseSpec `json:"database,omitempty"`
}

// GeoIPDatabaseSpec configures the shared MaxMind GeoLite2 database volume.
type GeoIPDatabaseSpec struct {
	// Enabled deploys the volume and the update jobs.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// Updates runs the download Jobs (an initial Job and a CronJob). Set it to
	// false to place the .mmdb files in the volume yourself, e.g. on an
	// isolated network. Defaults to true.
	// +optional
	Updates *bool `json:"updates,omitempty"`
	// UpdateSchedule is the cron schedule of the update CronJob. MaxMind
	// publishes GeoLite2 updates on Tuesdays and Fridays.
	// +kubebuilder:default="0 4 * * 3,6"
	// +optional
	UpdateSchedule string `json:"updateSchedule,omitempty"`
	// Storage for the database volume. It must be ReadWriteMany (the default
	// access mode) and reachable from the capture nodes. Defaults to 1Gi.
	// +optional
	Storage VolumeClaimSpec `json:"storage,omitempty"`
	// RolloutOnUpdate restarts Arkime pods after each successful update so they
	// load the new databases (capture pods restart one node at a time).
	// Defaults to true.
	// +optional
	RolloutOnUpdate *bool `json:"rolloutOnUpdate,omitempty"`
}

// KafkaSpec configures Kafka output for live Zeek.
type KafkaSpec struct {
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// Brokers as host:port. Defaults to ["kafka.local:9091"].
	// +optional
	Brokers []string `json:"brokers,omitempty"`
	// +kubebuilder:default=zeek
	// +optional
	Topic string `json:"topic,omitempty"`
}

// CoverageSpec configures Python code-coverage instrumentation of sidecars.
type CoverageSpec struct {
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// RC is the content of the .coveragerc file.
	// +optional
	RC string `json:"rc,omitempty"`
}

// ComponentSpec customizes the pods of one Malcolm workload.
type ComponentSpec struct {
	// Enabled=false removes the component's workload (and Service). Disabling a
	// component that other services depend on will break those services.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// Replicas for Deployments (ignored for DaemonSets). Only scale components
	// that support it; most Malcolm services are singletons.
	// +kubebuilder:validation:Minimum=0
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`
	// Resources for the component's main container.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// ContainerResources for other containers in the pod, keyed by container name
	// (useful for the multi-container zeek-live-remotesensor pod).
	// +optional
	ContainerResources map[string]corev1.ResourceRequirements `json:"containerResources,omitempty"`
	// NodeSelector merged into the pod's node selector.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Tolerations appended to the pod's tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// Affinity replaces the pod's affinity.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Type=object
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// PriorityClassName for the pod.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
	// ServiceAccountName for the pod.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// PodAnnotations added to the pod template.
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`
	// PodLabels added to the pod template.
	// +optional
	PodLabels map[string]string `json:"podLabels,omitempty"`
	// ExtraEnv appended to the main container's environment.
	// +optional
	ExtraEnv []corev1.EnvVar `json:"extraEnv,omitempty"`
	// ExtraEnvFrom prepended to the main container's envFrom (so Malcolm's own
	// configuration takes precedence).
	// +optional
	ExtraEnvFrom []corev1.EnvFromSource `json:"extraEnvFrom,omitempty"`
	// ExtraVolumes appended to the pod's volumes (core/v1 Volume objects).
	// +optional
	ExtraVolumes []runtime.RawExtension `json:"extraVolumes,omitempty"`
	// ExtraVolumeMounts appended to the main container's volume mounts.
	// +optional
	ExtraVolumeMounts []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`
	// Sidecars appended to the pod's containers (core/v1 Container objects).
	// +optional
	Sidecars []runtime.RawExtension `json:"sidecars,omitempty"`
	// InitContainers run before Malcolm's own init containers (core/v1 Container objects).
	// +optional
	InitContainers []runtime.RawExtension `json:"initContainers,omitempty"`
}

// ComponentStatus reports the state of one workload.
type ComponentStatus struct {
	// Name of the component.
	Name string `json:"name"`
	// Kind of the workload (Deployment, StatefulSet, DaemonSet).
	Kind string `json:"kind"`
	// Ready is true when all desired pods are available.
	Ready bool `json:"ready"`
	// Desired number of pods.
	Desired int32 `json:"desired"`
	// Available number of pods.
	Available int32 `json:"available"`
}

// MalcolmStatus defines the observed state of Malcolm.
type MalcolmStatus struct {
	// ObservedGeneration is the generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Phase summarizes the deployment: Pending, Progressing, Ready, Degraded or Error.
	// +optional
	Phase string `json:"phase,omitempty"`
	// Version of Malcolm deployed.
	// +optional
	Version string `json:"version,omitempty"`
	// ReadyComponents is a "ready/total" summary.
	// +optional
	ReadyComponents string `json:"readyComponents,omitempty"`
	// URL where Malcolm is reachable, when known.
	// +optional
	URL string `json:"url,omitempty"`
	// AdminCredentialsSecret names the Secret holding the administrator login
	// when the operator generated it.
	// +optional
	AdminCredentialsSecret string `json:"adminCredentialsSecret,omitempty"`
	// GeoIPUpdated is when the shared GeoIP database was last updated successfully.
	// +optional
	GeoIPUpdated *metav1.Time `json:"geoIPUpdated,omitempty"`
	// LogstashReplicas currently requested.
	// +optional
	LogstashReplicas int32 `json:"logstashReplicas,omitempty"`
	// Components lists per-workload readiness.
	// +optional
	Components []ComponentStatus `json:"components,omitempty"`
	// Conditions: Ready, Progressing, Degraded.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Malcolm is a network traffic analysis tool suite deployment.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mal
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.profile`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.status.version`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.readyComponents`
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.status.url`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Malcolm struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MalcolmSpec   `json:"spec,omitempty"`
	Status MalcolmStatus `json:"status,omitempty"`
}

// MalcolmList contains a list of Malcolm.
// +kubebuilder:object:root=true
type MalcolmList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Malcolm `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Malcolm{}, &MalcolmList{})
}
