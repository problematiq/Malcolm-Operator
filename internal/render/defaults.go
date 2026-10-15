package render

import (
	"k8s.io/apimachinery/pkg/api/resource"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

// DefaultVersion is the Malcolm release this operator was built and tested
// against. It is used as the image tag when spec.version is empty.
const DefaultVersion = "26.09.0"

const (
	DefaultImageRepository = "ghcr.io/idaholab/malcolm"
	DefaultAdminUsername   = "malcolm"
)

// envGroup describes one Malcolm environment file rendered as a ConfigMap
// (or Secret). Stem is the key used in spec.config and matches the Malcolm
// ./config/<stem>.env file name.
type envGroup struct {
	Stem   string
	Name   string
	Secret bool
}

// envGroups lists every overridable environment group in render order.
var envGroups = []envGroup{
	{Stem: "arkime", Name: "arkime-env"},
	{Stem: "arkime-live", Name: "arkime-live-env"},
	{Stem: "arkime-offline", Name: "arkime-offline-env"},
	{Stem: "auth-common", Name: "auth-common-env"},
	{Stem: "beats-common", Name: "beats-common-env"},
	{Stem: "dashboards", Name: "dashboards-env"},
	{Stem: "dashboards-helper", Name: "dashboards-helper-env"},
	{Stem: "filebeat", Name: "filebeat-env"},
	{Stem: "filescan", Name: "filescan-env"},
	{Stem: "kafka", Name: "kafka-config"},
	{Stem: "keycloak", Name: "keycloak-env", Secret: true},
	{Stem: "logstash", Name: "logstash-env"},
	{Stem: "lookup-common", Name: "lookup-common-env"},
	{Stem: "netbox", Name: "netbox-env"},
	{Stem: "netbox-common", Name: "netbox-common-env"},
	{Stem: "nginx", Name: "nginx-env"},
	{Stem: "opensearch", Name: "opensearch-env"},
	{Stem: "pcap-capture", Name: "pcap-capture-env"},
	{Stem: "pipeline", Name: "pipeline-env"},
	{Stem: "process", Name: "process-env"},
	{Stem: "ssl", Name: "ssl-env"},
	{Stem: "suricata", Name: "suricata-env"},
	{Stem: "suricata-live", Name: "suricata-live-env"},
	{Stem: "suricata-offline", Name: "suricata-offline-env"},
	{Stem: "upload-common", Name: "upload-common-env"},
	{Stem: "zeek", Name: "zeek-env"},
	{Stem: "zeek-live", Name: "zeek-live-env"},
	{Stem: "zeek-offline", Name: "zeek-offline-env"},
}

// ConfigGroupStems returns the stems accepted in spec.config.
func ConfigGroupStems() []string {
	out := make([]string, 0, len(envGroups))
	for _, g := range envGroups {
		out = append(out, g.Stem)
	}
	return out
}

// baseEnv holds the development-profile defaults for variables that are
// passed through verbatim. They mirror the Malcolm Helm chart's values.yaml.
// Variables that are derived from typed spec fields are computed in config.go.
var baseEnv = map[string]map[string]string{
	"auth-common": {
		"ROLE_ADMIN":                                 "admin",
		"ROLE_READ_ACCESS":                           "read_access",
		"ROLE_READ_WRITE_ACCESS":                     "read_write_access",
		"ROLE_ARKIME_ADMIN":                          "arkime_admin",
		"ROLE_ARKIME_READ_ACCESS":                    "arkime_read_access",
		"ROLE_ARKIME_READ_WRITE_ACCESS":              "arkime_read_write_access",
		"ROLE_ARKIME_PCAP_ACCESS":                    "arkime_pcap_access",
		"ROLE_ARKIME_HUNT_ACCESS":                    "arkime_hunt_access",
		"ROLE_ARKIME_WISE_READ_ACCESS":               "arkime_wise_read_access",
		"ROLE_ARKIME_WISE_READ_WRITE_ACCESS":         "arkime_wise_read_write_access",
		"ROLE_DASHBOARDS_READ_ACCESS":                "dashboards_read_access",
		"ROLE_DASHBOARDS_READ_ALL_APPS_ACCESS":       "dashboards_read_all_apps_access",
		"ROLE_DASHBOARDS_READ_WRITE_ACCESS":          "dashboards_read_write_access",
		"ROLE_DASHBOARDS_READ_WRITE_ALL_APPS_ACCESS": "dashboards_read_write_all_apps_access",
		"ROLE_EXTRACTED_FILES":                       "extracted_files",
		"ROLE_NETBOX_READ_ACCESS":                    "netbox_read_access",
		"ROLE_NETBOX_READ_WRITE_ACCESS":              "netbox_read_write_access",
		"ROLE_UPLOAD":                                "upload",
		"ROLE_CAPTURE_SERVICE":                       "capture_service",
	},
	"beats-common": {
		"BEATS_SSL":     "false",
		"LOGSTASH_HOST": "logstash:5044",
	},
	"lookup-common": {
		"FREQ_LOOKUP":                        "true",
		"FREQ_SEVERITY_THRESHOLD":            "2.0",
		"TOTAL_MEGABYTES_SEVERITY_THRESHOLD": "1000",
	},
	"filebeat": {
		"FILEBEAT_CLEAN_INACTIVE":                    "180m",
		"FILEBEAT_CLEAN_REMOVED":                     "true",
		"FILEBEAT_CLOSE_EOF":                         "true",
		"FILEBEAT_CLOSE_INACTIVE":                    "120s",
		"FILEBEAT_CLOSE_INACTIVE_LIVE":               "90m",
		"FILEBEAT_CLOSE_REMOVED":                     "true",
		"FILEBEAT_CLOSE_RENAMED":                     "true",
		"FILEBEAT_IGNORE_OLDER":                      "120m",
		"FILEBEAT_SCAN_FREQUENCY":                    "10s",
		"ZIP_CLEANUP_MINUTES":                        "90",
		"LOG_CLEANUP_MINUTES":                        "60",
		"FILEBEAT_CLEANUP_VERBOSITY":                 "",
		"FILEBEAT_TCP_LISTEN":                        "true",
		"FILEBEAT_TCP_LOG_FORMAT":                    "json",
		"FILEBEAT_TCP_PARSE_DROP_FIELD":              "message",
		"FILEBEAT_TCP_PARSE_SOURCE_FIELD":            "message",
		"FILEBEAT_TCP_PARSE_TARGET_FIELD":            "miscbeat",
		"FILEBEAT_TCP_TAG":                           "_malcolm_beats",
		"FILEBEAT_WATCHER_POLLING":                   "true",
		"FILEBEAT_WATCHER_POLLING_ASSUME_CLOSED_SEC": "10",
		"FILEBEAT_SCANNER_FINGERPRINT_OFFSET":        "0",
		"FILEBEAT_SCANNER_FINGERPRINT_LENGTH":        "512",
		"FILEBEAT_PREPARE_PROCESS_COUNT":             "1",
		"FILEBEAT_SYSLOG_UDP_LISTEN":                 "false",
		"FILEBEAT_SYSLOG_UDP_PORT":                   "0",
		"FILEBEAT_SYSLOG_TCP_LISTEN":                 "false",
		"FILEBEAT_SYSLOG_TCP_PORT":                   "0",
	},
	"netbox-common": {
		"NETBOX_DEFAULT_AUTOCREATE_MANUFACTURER": "true",
		"NETBOX_DEFAULT_FUZZY_THRESHOLD":         "0.95",
		"NETBOX_AUTO_CREATE_PREFIX":              "false",
		"NETBOX_ENRICHMENT_LOOKUP_SERVICE":       "true",
		"NETBOX_CACHE_SIZE":                      "10000",
		"NETBOX_CACHE_TTL":                       "300",
	},
	"netbox": {
		"BASE_PATH":                            "netbox",
		"CENSUS_REPORTING_ENABLED":             "false",
		"CORS_ORIGIN_ALLOW_ALL":                "True",
		"EMAIL_FROM":                           "netbox@bar.com",
		"EMAIL_PORT":                           "25",
		"EMAIL_SERVER":                         "localhost",
		"EMAIL_SSL_CERTFILE":                   "",
		"EMAIL_SSL_KEYFILE":                    "",
		"EMAIL_TIMEOUT":                        "5",
		"EMAIL_USE_SSL":                        "false",
		"EMAIL_USE_TLS":                        "false",
		"EXEMPT_VIEW_PERMISSIONS":              "*",
		"LOGIN_REQUIRED":                       "True",
		"LOGIN_PERSISTENCE":                    "True",
		"ISOLATED_DEPLOYMENT":                  "True",
		"GRAPHQL_ENABLED":                      "true",
		"HOUSEKEEPING_INTERVAL":                "86400",
		"MAX_PAGE_SIZE":                        "1000",
		"MEDIA_ROOT":                           "/opt/netbox/netbox/media",
		"METRICS_ENABLED":                      "false",
		"NAPALM_TIMEOUT":                       "10",
		"REDIS_CACHE_INSECURE_SKIP_TLS_VERIFY": "false",
		"REDIS_CACHE_SSL":                      "false",
		"REDIS_INSECURE_SKIP_TLS_VERIFY":       "false",
		"REDIS_SSL":                            "false",
		"RELEASE_CHECK_URL":                    "",
		"REMOTE_AUTH_AUTO_CREATE_GROUPS":       "False",
		"REMOTE_AUTH_AUTO_CREATE_USER":         "True",
		"REMOTE_AUTH_BACKEND":                  "netbox.authentication.RemoteUserBackend",
		"REMOTE_AUTH_DEFAULT_PERMISSIONS":      "standard_permission",
		"REMOTE_AUTH_ENABLED":                  "True",
		"REMOTE_AUTH_GROUP_HEADER":             "HTTP_X_FORWARDED_ROLES",
		"REMOTE_AUTH_GROUP_SEPARATOR":          ",",
		"REMOTE_AUTH_GROUP_SYNC_ENABLED":       "True",
		"REMOTE_AUTH_HEADER":                   "HTTP_X_FORWARDED_USER",
		"REMOTE_AUTH_STAFF_GROUPS":             "admin",
		"REMOTE_AUTH_SUPERUSER_GROUPS":         "admin",
		"REMOTE_AUTH_USER_EMAIL":               "HTTP_X_FORWARDED_EMAIL",
		"REMOTE_AUTH_USER_FIRST_NAME":          "HTTP_X_FORWARDED_GIVEN_NAME",
		"REMOTE_AUTH_USER_LAST_NAME":           "HTTP_X_FORWARDED_FAMILY_NAME",
		"ENFORCE_GLOBAL_UNIQUE":                "false",
		"SKIP_STARTUP_SCRIPTS":                 "true",
		"SKIP_SUPERUSER":                       "false",
		"SUPERUSER_EMAIL":                      "admin@example.com",
		"WEBHOOKS_ENABLED":                     "true",
		"GRANIAN_EXTRA_ARGS":                   "--host=0.0.0.0",
		"OPENSSL_FORCE_FIPS_MODE":              "0",
	},
	"nginx": {
		"NGINX_LOG_ACCESS_AND_ERRORS":         "false",
		"NGINX_SSL":                           "false",
		"NGINX_DASHBOARDS_PREFIX":             "",
		"NGINX_DASHBOARDS_PROXY_PASS":         "",
		"NGINX_RESOLVER_OVERRIDE":             "",
		"NGINX_RESOLVER_IPV4":                 "true",
		"NGINX_RESOLVER_IPV6":                 "true",
		"NGINX_ERROR_LOG_LEVEL":               "",
		"NGINX_LDAP_TLS_STUNNEL":              "false",
		"NGINX_LDAP_TLS_STUNNEL_CHECK_HOST":   "",
		"NGINX_LDAP_TLS_STUNNEL_CHECK_IP":     "",
		"NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL": "2",
	},
	"opensearch": {
		"OPENSEARCH_CREDS_CONFIG_FILE":                                 "/var/local/curlrc/.opensearch.primary.curlrc",
		"OPENSEARCH_SECONDARY_CREDS_CONFIG_FILE":                       "/var/local/curlrc/.opensearch.secondary.curlrc",
		"bootstrap.memory_lock":                                        "true",
		"cluster.routing.allocation.disk.threshold_enabled":            "false",
		"cluster.routing.allocation.node_initial_primaries_recoveries": "8",
		"cluster.name":                                   "opensearch-cluster",
		"network.host":                                   "0.0.0.0",
		"indices.query.bool.max_clause_count":            "8192",
		"logger.level":                                   "INFO",
		"path.repo":                                      "/opt/opensearch/backup",
		"node.roles":                                     "ingest,data,remote_cluster_client,cluster_manager",
		"MALCOLM_INDEX_MAX_RESULT_WINDOW":                "",
		"MALCOLM_NETWORK_INDEX_PATTERN":                  "arkime_sessions3-*",
		"MALCOLM_NETWORK_INDEX_DEFAULT_PIPELINE":         "",
		"MALCOLM_NETWORK_INDEX_LIFECYCLE_NAME":           "",
		"MALCOLM_NETWORK_INDEX_LIFECYCLE_ROLLOVER_ALIAS": "",
		"MALCOLM_NETWORK_INDEX_TIME_FIELD":               "firstPacket",
		"MALCOLM_NETWORK_INDEX_SUFFIX":                   "%{%y%m%d}",
		"MALCOLM_OTHER_INDEX_PATTERN":                    "malcolm_beats_*",
		"MALCOLM_OTHER_INDEX_ALIAS":                      "",
		"MALCOLM_OTHER_INDEX_DEFAULT_PIPELINE":           "",
		"MALCOLM_OTHER_INDEX_LIFECYCLE_NAME":             "",
		"MALCOLM_OTHER_INDEX_LIFECYCLE_ROLLOVER_ALIAS":   "",
		"MALCOLM_OTHER_INDEX_TIME_FIELD":                 "@timestamp",
		"MALCOLM_OTHER_INDEX_SUFFIX":                     "%{%y%m%d}",
		"ARKIME_NETWORK_INDEX_PATTERN":                   "arkime_sessions3-*",
		"ARKIME_NETWORK_INDEX_TIME_FIELD":                "firstPacket",
		"ARKIME_INIT_SHARDS":                             "1",
		"ARKIME_INIT_REPLICAS":                           "1",
		"ARKIME_INIT_REFRESH_SEC":                        "",
		"ARKIME_INIT_SHARDS_PER_NODE":                    "",
	},
	"process": {
		"CONFIG_MAP_DIR":  "configmap;secretmap",
		"MALCOLM_PROFILE": "malcolm",
		"TINI_VERBOSITY":  "1",
	},
	"ssl": {
		"PUSER_CA_TRUST": "/var/local/ca-trust",
	},
	"suricata": {
		"SURICATA_UPDATE_DEBUG":             "false",
		"SURICATA_DISABLE_ICS_ALL":          "false",
		"SURICATA_UPDATE_SOURCES":           "true",
		"SURICATA_UPDATE_CRON_EXPRESSION":   "0 0 * * *",
		"LUA_PATH":                          "/opt/suricata/rules/?.lua;;",
		"PCAP_PROCESSED_DIRECTORY":          "/data/pcap/processed",
		"SURICATA_STREAM_MEMCAP":            "1gb",
		"SURICATA_HOST_MEMCAP":              "32mb",
		"SURICATA_DEFRAG_MEMCAP":            "32mb",
		"SURICATA_FTP_MEMCAP":               "64mb",
		"SURICATA_STREAM_REASSEMBLY_MEMCAP": "256mb",
		"SURICATA_FLOW_MEMCAP":              "128mb",
	},
	"upload-common": {
		"AUTO_TAG":                                "true",
		"PCAP_MONITOR_HOST":                       "pcap-monitor",
		"PCAP_PIPELINE_IGNORE_PREEXISTING":        "false",
		"PCAP_PIPELINE_POLLING":                   "true",
		"PCAP_PIPELINE_POLLING_ASSUME_CLOSED_SEC": "10",
		"PCAP_PIPELINE_VERBOSITY":                 "",
		"WATCHER_UPLOAD":                          "true",
		"WATCHER_PUBLISH":                         "true",
		"SAFE_EXTRACT_MAX_ENTRIES":                "5000",
		"SAFE_EXTRACT_MAX_DEPTH":                  "20",
		"SAFE_EXTRACT_MAX_BYTES":                  "4294967296",
	},
	"zeek": {
		"EXTRACTED_FILE_MAX_BYTES":                     "134217728",
		"ZEEK_FILE_ANALYZER_TIMEOUT_SEC":               "5",
		"ZEEK_JA4SSH_PACKET_COUNT":                     "200",
		"ZEEK_LONG_CONN_REPEAT_LAST_DURATION":          "true",
		"ZEEK_LONG_CONN_DO_NOTICE":                     "true",
		"ZEEK_LONG_CONN_DURATIONS":                     "600,1800,3600,43200,86400",
		"ZEEK_METRICS_PORT":                            "",
		"ZEEK_DISABLE_BEST_GUESS_ICS":                  "",
		"ZEEK_DISABLE_ICS_ALL":                         "",
		"ZEEK_DISABLE_ICS_BACNET":                      "",
		"ZEEK_DISABLE_ICS_BSAP":                        "",
		"ZEEK_DISABLE_ICS_C1222":                       "",
		"ZEEK_DISABLE_ICS_DNP3":                        "",
		"ZEEK_DISABLE_ICS_ENIP":                        "",
		"ZEEK_DISABLE_ICS_ETHERCAT":                    "",
		"ZEEK_DISABLE_ICS_GENISYS":                     "true",
		"ZEEK_DISABLE_ICS_GE_SRTP":                     "",
		"ZEEK_DISABLE_ICS_IEC104":                      "",
		"ZEEK_DISABLE_ICS_HART_IP":                     "",
		"ZEEK_DISABLE_ICS_OMRON_FINS":                  "",
		"ZEEK_DISABLE_ICS_OPCUA_BINARY":                "",
		"ZEEK_DISABLE_ICS_MODBUS":                      "",
		"ZEEK_DISABLE_ICS_PROFINET":                    "",
		"ZEEK_DISABLE_ICS_PROFINET_IO_CM":              "",
		"ZEEK_DISABLE_ICS_ROC_PLUS":                    "",
		"ZEEK_DISABLE_ICS_S7COMM":                      "",
		"ZEEK_DISABLE_ICS_SYNCHROPHASOR":               "",
		"ZEEK_C1222_AUTHENTICATION_VALUE":              "true",
		"ZEEK_C1222_IDENTIFICATION_SERVICE":            "true",
		"ZEEK_C1222_READ_WRITE_SERVICE":                "true",
		"ZEEK_C1222_LOGON_SECURITY_SERVICE":            "true",
		"ZEEK_C1222_WAIT_SERVICE":                      "true",
		"ZEEK_C1222_DEREG_REG_SERVICE":                 "true",
		"ZEEK_C1222_RESOLVE_SERVICE":                   "true",
		"ZEEK_C1222_TRACE_SERVICE":                     "true",
		"ZEEK_DISABLE_LOG_PASSWORDS":                   "",
		"ZEEK_DISABLE_DETECT_ROUTERS":                  "true",
		"ZEEK_DISABLE_IANA_LOOKUP":                     "",
		"ZEEK_DISABLE_SPICY_IPSEC":                     "",
		"ZEEK_DISABLE_SPICY_LDAP":                      "",
		"ZEEK_DISABLE_SPICY_OPENVPN":                   "",
		"ZEEK_DISABLE_SPICY_QUIC":                      "true",
		"ZEEK_DISABLE_SPICY_STUN":                      "",
		"ZEEK_DISABLE_SPICY_TAILSCALE":                 "",
		"ZEEK_DISABLE_SPICY_TFTP":                      "",
		"ZEEK_DISABLE_SPICY_WIREGUARD":                 "",
		"ZEEK_DISABLE_SPICY_ZIP":                       "true",
		"ZEEK_DISABLE_SSL_VALIDATE_CERTS":              "",
		"ZEEK_DISABLE_TRACK_ALL_ASSETS":                "",
		"ZEEK_EXTRACTOR_PATH":                          "/zeek/extract_files",
		"ZEEK_ENIP_PORTS":                              "",
		"ZEEK_GENISYS_PORTS":                           "",
		"ZEEK_INTEL_FEED_SINCE":                        "",
		"ZEEK_INTEL_FEED_SSL_CERTIFICATE_VERIFICATION": "false",
		"ZEEK_INTEL_ITEM_EXPIRATION":                   "-1min",
		"ZEEK_INTEL_REFRESH_THREADS":                   "2",
		"ZEEK_SYNCHROPHASOR_DETAILED":                  "",
		"ZEEK_OMRON_FINS_DETAILED":                     "true",
		"ZEEK_SYNCHROPHASOR_PORTS":                     "",
		"ZEEK_JSON":                                    "",
		"PCAP_PROCESSED_DIRECTORY":                     "/pcap/processed",
		"ZEEK_UPLOAD_DIRECTORY":                        "/zeek/upload",
	},
	"arkime-offline": {
		"ARKIME_ROTATED_PCAP":              "true",
		"ARKIME_AUTO_ANALYZE_PCAP_THREADS": "1",
		"ARKIME_EXPOSE_WISE_GUI":           "true",
		"ARKIME_ALLOW_WISE_GUI_CONFIG":     "false",
	},
	"arkime": {
		"ARKIME_SSL":                               "false",
		"ARKIME_VIEWER_PORT":                       "8005",
		"MANAGE_PCAP_FILES":                        "true",
		"ARKIME_PCAP_LIBPCAP":                      "false",
		"ARKIME_DEBUG_LEVEL":                       "0",
		"ARKIME_FREESPACEG":                        "10%",
		"ARKIME_ROTATE_INDEX":                      "daily",
		"INDEX_MANAGEMENT_ENABLED":                 "true",
		"INDEX_MANAGEMENT_OPTIMIZATION_PERIOD":     "30d",
		"INDEX_MANAGEMENT_RETENTION_TIME":          "90d",
		"INDEX_MANAGEMENT_OLDER_SESSION_REPLICAS":  "0",
		"INDEX_MANAGEMENT_HISTORY_RETENTION_WEEKS": "13",
		"INDEX_MANAGEMENT_SEGMENTS":                "1",
		"INDEX_MANAGEMENT_HOT_WARM_ENABLED":        "false",
		"ARKIME_SPI_DATA_MAX_INDICES":              "7",
	},
	"arkime-live": {
		"ARKIME_LIVE_CAPTURE":          "true",
		"ARKIME_MAGIC_MODE":            "basic",
		"ARKIME_PCAP_WRITE_METHOD":     "simple",
		"ARKIME_PCAP_READ_METHOD":      "tpacketv3",
		"ARKIME_PCAP_PROCESSOR":        "false",
		"WISE":                         "off",
		"ARKIME_COMPRESSION_TYPE":      "none",
		"ARKIME_COMPRESSION_LEVEL":     "0",
		"ARKIME_DB_BULK_SIZE":          "4000000",
		"ARKIME_MAX_PACKETS_IN_QUEUE":  "300000",
		"ARKIME_PACKET_THREADS":        "2",
		"ARKIME_PCAP_WRITE_SIZE":       "2560000",
		"ARKIME_TPACKETV3_NUM_THREADS": "2",
		"ARKIME_TPACKETV3_BLOCK_SIZE":  "8388608",
	},
	"dashboards-helper": {
		"DASHBOARDS_DARKMODE":                   "true",
		"ISM_SNAPSHOT_COMPRESSED":               "false",
		"ISM_SNAPSHOT_REPO":                     "logs",
		"OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT":     "0",
		"OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT": "false",
		"OPENSEARCH_DEFAULT_DASHBOARD":          "0ad3d7c2-3441-485e-9dfe-dbb22e84e576",
		"DASHBOARDS_PREFIX":                     "",
		"DASHBOARDS_TIMEPICKER_FROM":            "now-24h",
		"DASHBOARDS_TIMEPICKER_TO":              "now",
		"DASHBOARDS_DATA_SOURCES_ENABLED":       "false",
		"MALCOLM_URL":                           "https://malcolm.vp.bigbang.dev",
	},
	"dashboards": {},
	"zeek-offline": {
		"ZEEK_AUTO_ANALYZE_PCAP_THREADS":     "1",
		"ZEEK_ROTATED_PCAP":                  "false",
		"ZEEK_ZAM":                           "false",
		"ZEEK_DISABLE_STATS":                 "true",
		"ZEEK_INTEL_REFRESH_CRON_EXPRESSION": "0 */12 * * *",
		"ZEEK_INTEL_REFRESH_ON_STARTUP":      "true",
		"ZEEK_DISABLE_INTEL_OFFLINE":         "false",
	},
	"suricata-offline": {
		"SURICATA_AUTO_ANALYZE_PCAP_THREADS":   "0",
		"SURICATA_AUTO_ANALYZE_PCAP_PROCESSES": "1",
		"SURICATA_ROTATED_PCAP":                "false",
	},
	"logstash": {
		"LOGSTASH_ZEEK_IGNORED_LOGS":    "analyzer,broker,cluster,config,loaded_scripts,packet_filter,png,print,prof,reporter,roc_plus_unknown_data,stderr,stdout",
		"LOGSTASH_OUI_LOOKUP":           "true",
		"LOGSTASH_REVERSE_DNS":          "false",
		"LOGSTASH_SEVERITY_SCORING":     "true",
		"OTKB_ENRICHMENT_TTL":           "3600",
		"OTKB_SSL_VERIFY":               "false",
		"OTKB_ENRICHMENT_VERBOSE":       "false",
		"OTKB_ENRICHMENT_DEBUG":         "false",
		"OTKB_ENRICHMENT_DEBUG_TIMINGS": "false",
		"pipeline.ordered":              "false",
	},
	"zeek-live": {
		"EXTRACT_FILES_PATH":           "/zeek/extract_files",
		"ZEEK_INTEL_PATH":              "/usr/local/zeek/share/zeek/site/intel",
		"ZEEK_LIVE_CAPTURE":            "true",
		"ZEEK_LOG_PATH":                "/zeek/live",
		"ZEEK_PCAP_PROCESSOR":          "false",
		"ZEEK_CLUSTER_BACKEND":         "ZeroMQ",
		"ZEEK_ZAM":                     "false",
		"ZEEK_DISABLE_STATS":           "",
		"ZEEK_DISABLE_INTEL_LIVE":      "false",
		"ZEEK_LB_PROCS_WORKER_DEFAULT": "",
		"ZEEK_LB_PROCS":                "1",
		"WORKER_LB_PROCS":              "1",
		"ZEEK_LB_METHOD":               "custom",
		"ZEEK_AF_PACKET_BUFFER_SIZE":   "67108864",
		"ZEEK_PIN_CPUS_WORKER_1":       "",
	},
	"suricata-live": {
		"SURICATA_LIVE_CAPTURE":            "true",
		"SURICATA_PCAP_PROCESSOR":          "false",
		"SURICATA_RUNMODE":                 "workers",
		"SURICATA_STATS_ENABLED":           "true",
		"SURICATA_STATS_EVE_ENABLED":       "true",
		"SURICATA_STATS_INTERVAL":          "30",
		"SURICATA_STATS_DECODER_EVENTS":    "false",
		"SURICATA_AF_PACKET_IFACE_THREADS": "2",
		"SURICATA_AF_PACKET_RING_SIZE":     "2048",
		"SURICATA_AF_PACKET_BLOCK_SIZE":    "32768",
		"SURICATA_AF_PACKET_BLOCK_TIMEOUT": "100",
		"SURICATA_MAX_PENDING_PACKETS":     "1024",
		"SURICATA_EVE_THREADED":            "true",
		"SURICATA_EVE_ROTATE_INTERVAL":     "1h",
	},
	"filescan": {
		"FILESCAN_PRUNE_THRESHOLD_MAX_SIZE":                 "1TB",
		"FILESCAN_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT": "0",
		"FILESCAN_PRUNE_INTERVAL_SECONDS":                   "300",
		"FILESCAN_HTTP_SERVER_ENABLE":                       "true",
		"FILESCAN_HTTP_SERVER_ZIP":                          "false",
		"FILESCAN_HTTP_SERVER_MAGIC":                        "false",
		"FILESCAN_HTTP_SERVER_RECURSIVE":                    "true",
		"FILESCAN_VERBOSITY":                                "",
		"FILESCAN_PRESERVATION":                             "quarantined",
		"FILESCAN_OUTPUT_PATH":                              "/filescan/data/logs/filescan-%(ts)s.log",
		"FILESCAN_HEALTH_PORT":                              "8001",
		"STRELKA_HOST":                                      "strelka-frontend",
		"STRELKA_PORT":                                      "57314",
	},
	"pipeline": {
		"RULES_UPDATE_ENABLED":   "false",
		"YARA_CUSTOM_RULES_ONLY": "false",
		"CLAMD_SCAN_ARCHIVE":     "false",
		"STRELKA_BACKEND_PROCS":  "1",
		"CLAMD_MAX_THREADS":      "8",
		"CLAMD_MAX_QUEUE":        "200",
		"CLAMD_MAX_CONN_QUEUE":   "400",
	},
	"keycloak": {
		"KC_CACHE":              "local",
		"KC_HEALTH_ENABLED":     "true",
		"KC_HOSTNAME_STRICT":    "false",
		"KC_HTTP_ENABLED":       "true",
		"KC_HTTP_RELATIVE_PATH": "/keycloak",
		"KC_METRICS_ENABLED":    "false",
		"KC_PROXY_HEADERS":      "xforwarded",
	},
}

// productionEnv overrides baseEnv when spec.profile is production.
var productionEnv = map[string]map[string]string{
	"opensearch": {
		"ARKIME_INIT_SHARDS": "2",
	},
	"suricata": {
		"SURICATA_STREAM_MEMCAP":            "16gb",
		"SURICATA_DEFRAG_MEMCAP":            "16gb",
		"SURICATA_FTP_MEMCAP":               "4gb",
		"SURICATA_STREAM_REASSEMBLY_MEMCAP": "16gb",
		"SURICATA_FLOW_MEMCAP":              "16gb",
	},
	"arkime": {
		"ARKIME_FREESPACEG":           "5%",
		"ARKIME_SPI_DATA_MAX_INDICES": "-1",
	},
	"arkime-live": {
		"ARKIME_COMPRESSION_LEVEL": "3",
		"ARKIME_DB_BULK_SIZE":      "15000000",
		"ARKIME_PACKET_THREADS":    "6",
	},
	"zeek-offline": {
		"ZEEK_AUTO_ANALYZE_PCAP_THREADS": "3",
	},
	"suricata-offline": {
		"SURICATA_AUTO_ANALYZE_PCAP_PROCESSES": "10",
	},
	"zeek-live": {
		"ZEEK_LB_PROCS_WORKER_DEFAULT": "8",
		"ZEEK_LB_PROCS":                "32",
		"WORKER_LB_PROCS":              "32",
		"ZEEK_AF_PACKET_BUFFER_SIZE":   "134217728",
	},
	"suricata-live": {
		"SURICATA_AF_PACKET_IFACE_THREADS": "32",
		"SURICATA_AF_PACKET_RING_SIZE":     "131072",
		"SURICATA_AF_PACKET_BLOCK_SIZE":    "1048576",
		"SURICATA_AF_PACKET_BLOCK_TIMEOUT": "1000",
		"SURICATA_MAX_PENDING_PACKETS":     "30000",
	},
	"pipeline": {
		"STRELKA_BACKEND_PROCS": "4",
	},
}

// profileTunables are typed, profile-dependent defaults.
type profileTunables struct {
	OpenSearchJavaMemory  string
	OpenSearchMaxShards   int32
	LogstashJavaMemory    string
	LogstashWorkers       int32
	LogstashBatchDelay    int32
	LogstashBatchSize     int32
	ValkeyMaxMemory       string
	ValkeyMaxMemoryPolicy string
	ValkeyAOFRewriteMin   string
	StoragePCAP           string
	StorageZeek           string
	StorageSuricata       string
	StorageConfig         string
	StorageRuntimeLogs    string
	StorageOpenSearch     string
	StorageOpenSearchBkp  string
	StoragePostgres       string
}

var tunables = map[malcolmv1.Profile]profileTunables{
	malcolmv1.ProfileDevelopment: {
		OpenSearchJavaMemory:  "-Xmx10g -Xms10g -Xss256k",
		OpenSearchMaxShards:   1000,
		LogstashJavaMemory:    "-Xmx3g -Xms3g -Xss2048k",
		LogstashWorkers:       2,
		LogstashBatchDelay:    50,
		LogstashBatchSize:     75,
		ValkeyMaxMemory:       "0",
		ValkeyMaxMemoryPolicy: "allkeys-lru",
		ValkeyAOFRewriteMin:   "64mb",
		StoragePCAP:           "25Gi",
		StorageZeek:           "25Gi",
		StorageSuricata:       "25Gi",
		StorageConfig:         "25Gi",
		StorageRuntimeLogs:    "25Gi",
		StorageOpenSearch:     "25Gi",
		StorageOpenSearchBkp:  "25Gi",
		StoragePostgres:       "15Gi",
	},
	malcolmv1.ProfileProduction: {
		OpenSearchJavaMemory:  "-Xmx32g -Xms32g -Xss256k",
		OpenSearchMaxShards:   2500,
		LogstashJavaMemory:    "-Xmx16g -Xms16g -Xss2048k",
		LogstashWorkers:       18,
		LogstashBatchDelay:    50,
		LogstashBatchSize:     75,
		ValkeyMaxMemory:       "0",
		ValkeyMaxMemoryPolicy: "allkeys-lru",
		ValkeyAOFRewriteMin:   "64mb",
		StoragePCAP:           "100Gi",
		StorageZeek:           "50Gi",
		StorageSuricata:       "50Gi",
		StorageConfig:         "25Gi",
		StorageRuntimeLogs:    "25Gi",
		StorageOpenSearch:     "25Gi",
		StorageOpenSearchBkp:  "25Gi",
		StoragePostgres:       "15Gi",
	},
}

var defaultSensitiveCountryCodes = []string{
	"AM", "AZ", "BY", "CN", "CU", "DZ", "GE", "HK", "IL", "IN", "IQ", "IR", "KG", "KP", "KR",
	"KZ", "LY", "MD", "MO", "PK", "RU", "SD", "SS", "SY", "TJ", "TM", "TW", "UA", "UZ",
}

var (
	defaultHomeNet          = []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}
	defaultInterfaces       = []string{"ens192"}
	defaultKafkaBrokers     = []string{"kafka.local:9091"}
	defaultSuricataSources  = []string{"et/open"}
	defaultStrelkaScanners  = []string{"default"}
	defaultNetboxDatasets   = []string{"default"}
	defaultNodeCountLabel   = malcolmv1.NodeLabel{Key: "cnaps.io/node-type", Value: "Tier-1"}
	defaultZeekSelector     = map[string]string{"cnaps.io/zeek-capture": "true"}
	defaultZeekRemoteSel    = map[string]string{"cnaps.io/zeek-remote-capture": "true"}
	defaultSuricataSelector = map[string]string{"cnaps.io/suricata-capture": "true"}
	defaultArkimeSelector   = map[string]string{"cnaps.io/arkime-capture": "true"}
	defaultPCAPSelector     = map[string]string{"cnaps.io/pcap-capture": "true"}
)

const defaultCoverageRC = `[run]
concurrency = thread
data_file = /tmp/coverage/.coverage
parallel = true
relative_files = false
`

func mustQuantity(s string) resource.Quantity { return resource.MustParse(s) }
