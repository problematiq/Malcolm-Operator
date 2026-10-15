package render

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

var (
	capIPCLock     = corev1.Capability("IPC_LOCK")
	capSysResource = corev1.Capability("SYS_RESOURCE")
	capSysAdmin    = corev1.Capability("SYS_ADMIN")
	capNetAdmin    = corev1.Capability("NET_ADMIN")
	capNetRaw      = corev1.Capability("NET_RAW")
	capSysNice     = corev1.Capability("SYS_NICE")
)

// renderCoreWorkloads renders the central (non-capture) Malcolm services.
func (r *renderer) renderCoreWorkloads() {
	steps := []struct {
		component string
		enabled   bool
		fn        func()
	}{
		{"opensearch", r.openSearchLocal(), r.renderOpenSearch},
		{"dashboards", r.openSearchDashboards(), r.renderDashboards},
		{"upload", true, r.renderUpload},
		{"pcap-monitor", true, r.renderPCAPMonitor},
		{"arkime", true, r.renderArkime},
		{"api", true, r.renderAPI},
		{"dashboards-helper", true, r.renderDashboardsHelper},
		{"zeek-offline", true, r.renderZeekOffline},
		{"suricata-offline", true, r.renderSuricataOffline},
		{"filescan", true, r.renderFilescan},
		{"filebeat-offline", true, r.renderFilebeatOffline},
		{"logstash", true, r.renderLogstash},
		{"valkey", true, r.renderValkey},
		{"valkey-cache", true, r.renderValkeyCache},
		{"postgres", r.postgresEnabled(), r.renderPostgres},
		{"netbox", r.netboxMode() == malcolmv1.NetBoxModeLocal, r.renderNetBox},
		{"htadmin", true, r.renderHTAdmin},
		{"freq", true, r.renderFreq},
		{"keycloak", r.keycloakLocal(), r.renderKeycloak},
		{"strelka-frontend", true, r.renderStrelkaFrontend},
		{"strelka-backend", true, r.renderStrelkaBackend},
		{"strelka-manager", true, r.renderStrelkaManager},
		{"nginx-proxy", true, r.renderNginx},
	}
	for _, s := range steps {
		if s.enabled && r.componentEnabled(s.component) {
			s.fn()
		}
	}
}

func (r *renderer) renderOpenSearch() {
	replicas := r.openSearchReplicas()
	caSecret := r.spec.OpenSearch.Local.TransportCASecret
	if replicas > 1 && caSecret == "" {
		r.warn("opensearch.local.replicas > 1 requires opensearch.local.transportCASecret for node-to-node TLS")
	}

	r.service("opensearch", "opensearch", "opensearch", svcPort{"http", 9200, 0})
	headless := r.service("opensearch", "opensearch-headless", "opensearch", svcPort{"http", 9200, 0}, svcPort{"transport", 9300, 0})
	headless.Spec.ClusterIP = corev1.ClusterIPNone
	headless.Spec.Type = corev1.ServiceTypeClusterIP
	headless.Spec.PublishNotReadyAddresses = true

	c := r.container("opensearch-container", "opensearch", capIPCLock, capSysResource)
	c.Ports = []corev1.ContainerPort{tcpPort("http", 9200), tcpPort("transport", 9300)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "opensearch-env", "auth-common-env")
	c.LivenessProbe = healthProbe(600, 60, 30, 5)
	c.VolumeMounts = []corev1.VolumeMount{
		catrustMount(),
		curlrcMount("opensearch-opensearch-curlrc-secret-volume"),
		mount("opensearch-claim", "/usr/share/opensearch/data"),
		mount("opensearch-backup-claim", "/opt/opensearch/backup"),
		mount("opensearch-keystore-default-secret-volume", "/usr/share/opensearch/config/bootstrap/secretmap"),
		mountSub("opensearch-claim", "/usr/share/opensearch/config/persist", "opensearch"),
	}
	volumes := []corev1.Volume{
		r.catrustVolume(),
		r.curlrcVolume("opensearch-opensearch-curlrc-secret-volume"),
		secretVolume("opensearch-keystore-default-secret-volume", SecretKeystore),
	}
	if caSecret != "" {
		c.VolumeMounts = append(c.VolumeMounts, mountRO(mount("opensearch-ca-secret-volume", "/usr/share/opensearch/config/certs/secretmap")))
		volumes = append(volumes, secretVolume("opensearch-ca-secret-volume", caSecret))
	}
	st := r.spec.Storage
	r.statefulSet("opensearch", "opensearch", "opensearch-headless", replicas,
		[]corev1.PersistentVolumeClaim{
			r.claimTemplate("opensearch-claim", st.OpenSearch, r.tun.StorageOpenSearch),
			r.claimTemplate("opensearch-backup-claim", st.OpenSearchBackup, r.tun.StorageOpenSearchBkp),
		},
		corev1.PodSpec{
			Containers: []corev1.Container{c},
			InitContainers: []corev1.Container{r.dirinit("opensearch-dirinit-container",
				[]corev1.EnvVar{mkdir("/data/config:opensearch;/data/opensearch:nodes")},
				mount("opensearch-claim", "/data/opensearch"),
				mount("opensearch-claim", "/data/config"))},
			Volumes: volumes,
		})
}

func (r *renderer) renderDashboards() {
	r.service("dashboards", "dashboards", "dashboards-deployment", svcPort{"http", 5601, 0})
	c := r.container("dashboards-container", "dashboards")
	c.Ports = []corev1.ContainerPort{tcpPort("http", 5601)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "opensearch-env")
	c.LivenessProbe = healthProbe(600, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{catrustMount(), curlrcMount("dashboards-opensearch-curlrc-secret-volume")}
	r.deployment("dashboards", "dashboards-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		Volumes:    []corev1.Volume{r.catrustVolume(), r.curlrcVolume("dashboards-opensearch-curlrc-secret-volume")},
	})
}

func (r *renderer) renderUpload() {
	svc := r.service("upload", "upload", "upload-deployment", svcPort{"sftp", 22, 0}, svcPort{"http", 80, 0})
	svc.Spec.Type = corev1.ServiceTypeClusterIP
	c := r.container("upload-container", "file-upload")
	c.Ports = []corev1.ContainerPort{tcpPort("sftp", 22), tcpPort("http", 80)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "upload-common-env")
	c.Env = []corev1.EnvVar{r.adminUsernameEnv(), r.adminPasswordEnv()}
	c.LivenessProbe = healthProbe(60, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{catrustMount(), mountSub("upload-pcap-volume", "/var/www/upload/server/php/chroot/files", "upload")}
	r.deployment("upload", "upload-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("upload-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/pcap:upload/tmp/spool,upload/variants")},
			mount("upload-pcap-volume", "/data/pcap"))},
		Volumes: []corev1.Volume{r.catrustVolume(), r.pvcVolume("upload-pcap-volume", ClaimPCAP)},
	})
}

func (r *renderer) renderPCAPMonitor() {
	r.service("pcap-monitor", "pcap-monitor", "pcap-monitor-deployment", svcPort{"zmq", 30441, 0})
	c := r.container("pcap-monitor-container", "pcap-monitor")
	c.Env = []corev1.EnvVar{nodeNameEnv()}
	c.Ports = []corev1.ContainerPort{tcpPort("zmq", 30441)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "opensearch-env", "upload-common-env")
	c.LivenessProbe = healthProbe(90, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{
		catrustMount(),
		curlrcMount("pcap-monitor-opensearch-curlrc-secret-volume"),
		mount("pcap-monitor-pcap-volume", "/pcap"),
		mount("pcap-monitor-zeek-volume", "/zeek"),
	}
	r.deployment("pcap-monitor", "pcap-monitor-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("pcap-monitor-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/pcap:processed,upload")},
			mount("pcap-monitor-pcap-volume", "/data/pcap"))},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			r.curlrcVolume("pcap-monitor-opensearch-curlrc-secret-volume"),
			r.pvcVolume("pcap-monitor-pcap-volume", ClaimPCAP),
			r.pvcVolume("pcap-monitor-zeek-volume", ClaimZeek),
		},
	})
}

func (r *renderer) renderArkime() {
	r.service("arkime", "arkime", "arkime-deployment", svcPort{"http", 8005, 0}, svcPort{"wise", 8081, 0})
	c := r.arkimeContainer("arkime-container", []corev1.Capability{capIPCLock, capSysResource},
		[]string{"process-env", "ssl-env", "opensearch-env", "upload-common-env", "arkime-env", "arkime-offline-env", "auth-common-env", "secret:" + SecretArkimeEnv},
		[]corev1.VolumeMount{
			catrustMount(),
			curlrcMount("arkime-opensearch-curlrc-secret-volume"),
			mount("arkime-pcap-volume", "/data/pcap"),
			mountSub("wise-config", "/opt/arkime/etc/wise.ini.example", "wise.ini"),
			mount("arkime-config-volume", "/opt/arkime/wiseini"),
			mount("arkime-lua-volume", "/opt/arkime/lua/configmap"),
		})
	c.Ports = []corev1.ContainerPort{tcpPort("http", 8005)}
	c.Env = []corev1.EnvVar{r.adminUsernameEnv(), nodeNameEnv()}
	d := r.deployment("arkime", "arkime-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("arkime-dirinit-container",
			[]corev1.EnvVar{
				mkdir("/data/config:arkime/wiseini;/data/pcap:processed,arkime-live"),
				pcopy("/opt/arkime/etc/wise.ini.example:/opt/arkime/wiseini/wise.ini"),
			},
			mount("arkime-pcap-volume", "/data/pcap"),
			mount("arkime-config-volume", "/opt/arkime/wiseini"),
			mountSub("wise-config", "/opt/arkime/etc/wise.ini.example", "wise.ini"))},
		Volumes: append([]corev1.Volume{
			r.catrustVolume(),
			r.arkimeLuaVolume("arkime-lua-volume"),
			r.wiseVolume(),
			emptyDirVolume("arkime-config-volume", "50Mi"),
			r.curlrcVolume("arkime-opensearch-curlrc-secret-volume"),
			r.pvcVolume("arkime-pcap-volume", ClaimPCAP),
		}, r.elasticCertVolumes()...),
	})
	r.attachGeoIP(&d.Spec.Template)
}

func (r *renderer) renderAPI() {
	r.service("api", "api", "api-deployment", svcPort{"http", 5000, 0})
	c := r.container("api-container", "api")
	c.Command = []string{"/usr/bin/tini"}
	c.Args = []string{"--", "/usr/local/bin/docker-uid-gid-setup.sh", "/usr/local/bin/service_check_passthrough.sh",
		"-s", "api", "gunicorn", "--bind", "0:5000", "manage:app"}
	c.Ports = []corev1.ContainerPort{tcpPort("http", 5000)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "arkime-env", "upload-common-env", "dashboards-env", "netbox-common-env",
		"auth-common-env", "secret:"+SecretNetBoxEnv, "secret:"+SecretValkeyEnv, "opensearch-env")
	c.Env = []corev1.EnvVar{envVal("ARKIME_PORT", "8005")}
	c.LivenessProbe = healthProbe(60, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{catrustMount(), curlrcMount("api-opensearch-curlrc-secret-volume")}
	r.deployment("api", "api-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		Volumes:    []corev1.Volume{r.catrustVolume(), r.curlrcVolume("api-opensearch-curlrc-secret-volume")},
	})
}

func (r *renderer) renderDashboardsHelper() {
	r.service("dashboards-helper", "dashboards-helper", "dashboards-helper-deployment", svcPort{"http", 28991, 0})
	c := r.container("dashboards-helper-container", "dashboards-helper")
	c.Ports = []corev1.ContainerPort{tcpPort("http", 28991)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "opensearch-env", "netbox-common-env", "dashboards-env", "dashboards-helper-env")
	c.LivenessProbe = healthProbe(30, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{catrustMount(), curlrcMount("dashboards-helper-opensearch-curlrc-secret-volume")}
	volumes := []corev1.Volume{r.catrustVolume(), r.curlrcVolume("dashboards-helper-opensearch-curlrc-secret-volume")}
	if r.spec.IndexLifecycle != nil {
		for _, f := range []string{"malcolm_template.json", "malcolm_template_suricata.json", "malcolm_beats_template.json"} {
			c.VolumeMounts = append(c.VolumeMounts, mountSub("malcolm-template-override", "/opt/templates/"+f, f))
		}
		volumes = append(volumes, cmVolume("malcolm-template-override", "malcolm-template-override"))
	}
	r.deployment("dashboards-helper", "dashboards-helper-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		Volumes:    volumes,
	})
}

func (r *renderer) renderZeekOffline() {
	c := r.zeekContainer(zeekOffline, nil, []corev1.EnvVar{nodeNameEnv()}, []corev1.VolumeMount{
		catrustMount(),
		mount("zeek-offline-pcap-volume", "/pcap"),
		mountSub("zeek-offline-zeek-volume", "/zeek/extract_files", "extract_files"),
		mountSub("zeek-offline-zeek-volume", "/zeek/upload", "upload"),
		mount("zeek-offline-intel-preseed-volume", "/usr/local/zeek/share/zeek/site/intel-preseed/configmap"),
		mountSub("zeek-intel-volume", "/usr/local/zeek/share/zeek/site/intel", "zeek/intel"),
	})
	d := r.deployment("zeek-offline", "zeek-offline-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("zeek-offline-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/config:zeek/intel/Mandiant,zeek/intel/Google,zeek/intel/MISP,zeek/intel/STIX;/data/pcap:processed;/data/zeek-logs:current,extract_files/filescan,live,processed,upload")},
			mount("zeek-intel-volume", "/data/config"),
			mount("zeek-offline-pcap-volume", "/data/pcap"),
			mount("zeek-offline-zeek-volume", "/data/zeek-logs"))},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			r.pvcVolume("zeek-offline-pcap-volume", ClaimPCAP),
			r.pvcVolume("zeek-offline-zeek-volume", ClaimZeek),
			r.zeekIntelPreseedVolume("zeek-offline-intel-preseed-volume"),
			r.pvcVolume("zeek-intel-volume", ClaimConfig),
			r.zeekCustomVolume(),
		},
	})
	r.instrumentCoverage(&d.Spec.Template.Spec, len(r.component("zeek-offline").Sidecars))
}

func (r *renderer) renderSuricataOffline() {
	c := r.suricataContainer(false, nil,
		[]string{"process-env", "ssl-env", "upload-common-env", "suricata-env", "suricata-offline-env"},
		[]corev1.EnvVar{nodeNameEnv()},
		[]corev1.VolumeMount{
			catrustMount(),
			mount("suricata-offline-pcap-volume", "/data/pcap"),
			mount("suricata-offline-suricata-logs-volume", "/var/log/suricata"),
		})
	d := r.deployment("suricata-offline", "suricata-offline-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("suricata-offline-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/pcap:processed")},
			mount("suricata-offline-pcap-volume", "/data/pcap"))},
		Volumes: append([]corev1.Volume{
			r.catrustVolume(),
			r.pvcVolume("suricata-offline-pcap-volume", ClaimPCAP),
			r.pvcVolume("suricata-offline-suricata-logs-volume", ClaimSuricata),
		}, r.suricataConfigVolumes()...),
	})
	r.instrumentCoverage(&d.Spec.Template.Spec, len(r.component("suricata-offline").Sidecars))
}

func (r *renderer) renderFilescan() {
	r.service("filescan", "filescan", "filescan-deployment", svcPort{"health", 8001, 0}, svcPort{"files", 8006, 0})
	c := r.filescanContainer(SecretValkeyEnv, "filescan-zeek-volume", "filescan-logs-volume", nil)
	r.deployment("filescan", "filescan-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("filescan-live-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/zeek-logs:extract_files/filescan;/data/runtime-logs:filescan")},
			mount("filescan-zeek-volume", "/data/zeek-logs"),
			mount("filescan-logs-volume", "/data/runtime-logs"))},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			r.pvcVolume("filescan-zeek-volume", ClaimZeek),
			r.pvcVolume("filescan-logs-volume", ClaimRuntimeLogs),
		},
	})
}

func (r *renderer) renderFilebeatOffline() {
	svc := r.service("filebeat-offline", "filebeat", "filebeat-offline-deployment", svcPort{"tcpjson", 5045, 0})
	svc.Spec.Type = serviceType(r.spec.Filebeat.ServiceType)
	c := r.filebeatContainer(SecretValkeyEnv,
		[]corev1.ContainerPort{tcpPort("tcpjson", 5045)},
		[]corev1.EnvVar{nodeNameEnv(), envVal("FILEBEAT_SURICATA_LOG_PATH", "/suricata-offline")},
		[]corev1.VolumeMount{
			catrustMount(),
			curlrcMount("filebeat-opensearch-curlrc-secret-volume"),
			mount("filebeat-zeek-volume", "/zeek"),
			mountSub("filebeat-runtime-logs-volume", "/filescan", "filescan"),
			mount("filebeat-suricata-offline-volume", "/suricata-offline"),
			mountSub("filebeat-runtime-logs-volume", "/nginx", "nginx"),
		})
	r.deployment("filebeat-offline", "filebeat-offline-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("filebeat-offline-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/runtime-logs:nginx,filescan")},
			mount("filebeat-runtime-logs-volume", "/data/runtime-logs"))},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			r.curlrcVolume("filebeat-opensearch-curlrc-secret-volume"),
			r.pvcVolume("filebeat-zeek-volume", ClaimZeek),
			r.pvcVolume("filebeat-suricata-offline-volume", ClaimSuricata),
			r.pvcVolume("filebeat-runtime-logs-volume", ClaimRuntimeLogs),
		},
	})
}

func serviceType(t corev1.ServiceType) corev1.ServiceType {
	if t == "" {
		return corev1.ServiceTypeClusterIP
	}
	return t
}

// LogstashReplicas returns the replica count for a given number of counted nodes.
func LogstashReplicas(nodes int) int32 {
	n := int32(nodes / 2)
	if n < 1 {
		n = 1
	}
	return n
}

func (r *renderer) logstashReplicas() int32 {
	if r.spec.Logstash.Replicas != nil {
		return *r.spec.Logstash.Replicas
	}
	if r.in.LogstashReplicas > 0 {
		return r.in.LogstashReplicas
	}
	return 1
}

func (r *renderer) renderLogstash() {
	svc := r.service("logstash", "logstash", "logstash-deployment",
		svcPort{"lumberjack", 5044, 0}, svcPort{"supervisord", 9001, 0}, svcPort{"http", 9600, 0})
	svc.Spec.Type = serviceType(r.spec.Logstash.ServiceType)
	c := r.container("logstash-container", "logstash-oss", capIPCLock, capSysResource)
	c.Ports = []corev1.ContainerPort{tcpPort("lumberjack", 5044), tcpPort("supervisord", 9001), tcpPort("http", 9600)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "opensearch-env", "netbox-common-env", "netbox-env", "filescan-env",
		"secret:"+SecretNetBoxEnv, "beats-common-env", "lookup-common-env", "logstash-env", "secret:"+SecretLogstashEnv)
	c.LivenessProbe = healthProbe(600, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{
		catrustMount(),
		curlrcMount("logstash-opensearch-curlrc-secret-volume"),
		mountSub("logstash-config-persist-volume", "/usr/share/logstash/config/persist", "logstash"),
	}
	volumes := []corev1.Volume{
		r.catrustVolume(),
		r.curlrcVolume("logstash-opensearch-curlrc-secret-volume"),
		r.pvcVolume("logstash-config-persist-volume", ClaimConfig),
	}
	if r.spec.IndexLifecycle != nil {
		c.VolumeMounts = append(c.VolumeMounts, mountSub("elastic-output-override",
			"/usr/share/logstash/malcolm-pipelines/output/99_opensearch_output.conf", "99_opensearch_output.conf"))
		volumes = append(volumes, cmVolume("elastic-output-override", "elastic-output-override"))
	}
	// Replicas from spec.components["logstash"].replicas take precedence in deployment().
	r.deployment("logstash", "logstash-deployment", r.logstashReplicas(), corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("logstash-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/config:logstash")},
			mount("logstash-config-persist-volume", "/data/config"))},
		Volumes: volumes,
	})
}

func (r *renderer) renderValkey() {
	p := r.valkeyPorts()
	r.service("valkey", "valkey", "valkey-deployment", svcPort{"valkey", p.Local, 0})
	c := r.valkeyContainer("valkey-container", SecretValkeyEnv, p.Local, "valkey", true, mountSub("valkey-volume", "/data", "valkey"))
	r.deployment("valkey", "valkey-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("valkey-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/config:valkey")},
			mount("valkey-volume", "/data/config"))},
		Volumes: []corev1.Volume{r.catrustVolume(), r.pvcVolume("valkey-volume", ClaimConfig)},
	})
}

func (r *renderer) renderValkeyCache() {
	p := r.valkeyPorts()
	r.service("valkey-cache", "valkey-cache", "valkey-cache-deployment", svcPort{"valkey", p.LocalCache, 0})
	c := r.valkeyContainer("valkey-cache-container", SecretValkeyEnv, p.LocalCache, "valkey-cache", false)
	r.deployment("valkey-cache", "valkey-cache-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		Volumes:    []corev1.Volume{r.catrustVolume()},
	})
}

func (r *renderer) renderPostgres() {
	r.service("postgres", "postgres", "postgres-statefulset", svcPort{"postgresql", 5432, 0})
	headless := r.service("postgres", "postgres-headless", "postgres-statefulset", svcPort{"postgresql", 5432, 0})
	headless.Spec.ClusterIP = corev1.ClusterIPNone
	headless.Spec.Type = corev1.ServiceTypeClusterIP
	headless.Spec.PublishNotReadyAddresses = true

	c := r.container("postgres-container", "postgresql")
	c.Ports = []corev1.ContainerPort{tcpPort("postgresql", 5432)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "netbox-common-env", "secret:"+SecretPostgresEnv)
	c.LivenessProbe = healthProbe(90, 60, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{catrustMount(), mountSub("postgres-claim", "/var/lib/postgresql/data", "postgres")}
	r.statefulSet("postgres", "postgres-statefulset", "postgres-headless", 1,
		[]corev1.PersistentVolumeClaim{r.claimTemplate("postgres-claim", r.spec.Storage.Postgres, r.tun.StoragePostgres)},
		corev1.PodSpec{
			Containers: []corev1.Container{c},
			InitContainers: []corev1.Container{r.dirinit("postgres-dirinit-container",
				[]corev1.EnvVar{mkdir("/data/config:postgres")},
				mount("postgres-claim", "/data/config"))},
			Volumes: []corev1.Volume{r.catrustVolume()},
		})
}

func (r *renderer) renderNetBox() {
	r.service("netbox", "netbox", "netbox-deployment",
		svcPort{"http-main", 8080, 0}, svcPort{"http-status", 8081, 0}, svcPort{"supervisord", 9001, 0})
	c := r.container("netbox-container", "netbox")
	c.Ports = []corev1.ContainerPort{tcpPort("http-main", 8080), tcpPort("http-status", 8081), tcpPort("supervisord", 9001)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "netbox-common-env", "netbox-env", "auth-common-env",
		"secret:"+SecretNetBoxEnv, "secret:"+SecretPostgresEnv, "secret:"+SecretValkeyEnv)
	c.LivenessProbe = healthProbe(600, 60, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{
		catrustMount(),
		mount("netbox-custom-plugins-volume", "/opt/netbox-custom-plugins"),
		mountSub("netbox-media-volume", "/opt/netbox/netbox/media", "netbox/media"),
	}
	r.deployment("netbox", "netbox-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("netbox-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/config:netbox/media")},
			mount("netbox-media-volume", "/data/config"))},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			cmVolume("netbox-custom-plugins-volume", strDefault(r.spec.NetBox.CustomPluginsConfigMap, "netbox-custom-plugins")),
			r.pvcVolume("netbox-media-volume", ClaimConfig),
		},
	})
}

func (r *renderer) renderHTAdmin() {
	r.service("htadmin", "htadmin", "htadmin-deployment", svcPort{"http", 80, 0})
	c := r.container("htadmin-container", "htadmin")
	c.Ports = []corev1.ContainerPort{tcpPort("http", 80)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "auth-common-env")
	c.Env = []corev1.EnvVar{r.adminUsernameEnv()}
	c.LivenessProbe = healthProbe(60, 60, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{
		catrustMount(),
		mountSub("htadmin-config-volume", "/var/www/htadmin/auth", "auth"),
		mountSub("htadmin-config-volume", "/var/www/htadmin/config", "htadmin"),
	}
	r.deployment("htadmin", "htadmin-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("htadmin-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/config:auth,htadmin")},
			mount("htadmin-config-volume", "/data/config"))},
		Volumes: []corev1.Volume{r.catrustVolume(), r.pvcVolume("htadmin-config-volume", ClaimConfig)},
	})
}

func (r *renderer) renderFreq() {
	r.service("freq", "freq", "freq-deployment", svcPort{"http", 10004, 0})
	c := r.container("freq-container", "freq")
	c.Ports = []corev1.ContainerPort{tcpPort("http", 10004)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "lookup-common-env")
	c.LivenessProbe = healthProbe(60, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{catrustMount()}
	r.deployment("freq", "freq-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		Volumes:    []corev1.Volume{r.catrustVolume()},
	})
}

func (r *renderer) renderKeycloak() {
	r.service("keycloak", "keycloak", "keycloak-deployment", svcPort{"http", 8080, 0})
	c := r.container("keycloak-container", "keycloak")
	c.Command = []string{"/usr/bin/tini"}
	c.Args = []string{"--", "/usr/local/bin/docker-uid-gid-setup.sh", "/usr/local/bin/service_check_passthrough.sh",
		"-s", "keycloak", "/usr/local/bin/docker-entrypoint.sh", "/opt/keycloak/bin/kc.sh", "start"}
	c.Ports = []corev1.ContainerPort{tcpPort("http", 8080)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "auth-common-env", "secret:"+SecretPostgresEnv, "secret:"+SecretKeycloakEnv)
	c.LivenessProbe = healthProbe(45, 60, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{catrustMount()}
	r.deployment("keycloak", "keycloak-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		Volumes:    []corev1.Volume{r.catrustVolume()},
	})
}

func (r *renderer) renderStrelkaFrontend() {
	r.service("strelka-frontend", "strelka-frontend", "strelka-frontend-deployment", svcPort{"enqueue", 57314, 0})
	c := r.strelkaContainer("frontend", SecretValkeyEnv, "strelka-frontend-config-volume")
	c.VolumeMounts = append(c.VolumeMounts, mountSub("strelka-frontend-logs-volume", "/var/log/strelka", "strelka-frontend"))
	r.deployment("strelka-frontend", "strelka-frontend-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("strelka-frontend-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/runtime-logs:strelka-frontend")},
			mount("strelka-frontend-logs-volume", "/data/runtime-logs"))},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			cmVolume("strelka-frontend-config-volume", "strelka-frontend-config"),
			r.pvcVolume("strelka-frontend-logs-volume", ClaimRuntimeLogs),
		},
	})
}

func (r *renderer) renderStrelkaBackend() {
	c := r.strelkaContainer("backend", SecretValkeyEnv, "strelka-backend-config-volume")
	r.deployment("strelka-backend", "strelka-backend-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			cmVolume("strelka-backend-config-volume", "strelka-backend-config"),
			r.yaraVolume(),
		},
	})
}

func (r *renderer) renderStrelkaManager() {
	c := r.strelkaContainer("manager", SecretValkeyEnv, "strelka-manager-config-volume")
	r.deployment("strelka-manager", "strelka-manager-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			cmVolume("strelka-manager-config-volume", "strelka-manager-config"),
		},
	})
}

func (r *renderer) renderNginx() {
	svc := r.service("nginx-proxy", "nginx-proxy", "nginx-proxy-deployment",
		svcPort{"http", 80, 443}, svcPort{"healthhttp", 8443, 0}, svcPort{"opensearch", 9200, 0})
	svc.Spec.Type = serviceType(r.spec.Nginx.ServiceType)
	if len(r.spec.Nginx.ServiceAnnotations) > 0 {
		svc.Annotations = copyMap(r.spec.Nginx.ServiceAnnotations)
	}

	envFrom := []string{"process-env", "ssl-env", "opensearch-env", "arkime-env", "dashboards-env", "netbox-common-env"}
	if r.keycloakAny() {
		envFrom = append(envFrom, "secret:"+SecretKeycloakEnv)
	}
	envFrom = append(envFrom, "upload-common-env", "auth-common-env", "nginx-env")

	c := r.container("nginx-proxy-container", "nginx-proxy")
	c.Ports = []corev1.ContainerPort{tcpPort("http", 443), tcpPort("healthhttp", 8443), tcpPort("opensearch", 9200)}
	c.EnvFrom = r.envFrom(envFrom...)
	if !r.openSearchLocal() && r.spec.OpenSearch.ExternalDashboardsURL != "" {
		c.Env = []corev1.EnvVar{envVal("DASHBOARDS_URL", r.spec.OpenSearch.ExternalDashboardsURL)}
	}
	// nginx serves /wise unless told otherwise; keep it in step with the arkime
	// pod, which reads the same switch from arkime-offline-env.
	if expose := r.env["arkime-offline"]["ARKIME_EXPOSE_WISE_GUI"]; expose != "true" {
		c.Env = append(c.Env, envVal("ARKIME_EXPOSE_WISE_GUI", expose))
	}
	c.LivenessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
			Path: "/", Port: intstr.FromInt32(8443), Scheme: corev1.URISchemeHTTP,
		}},
		InitialDelaySeconds: 120, PeriodSeconds: 30, TimeoutSeconds: 15, SuccessThreshold: 1, FailureThreshold: 10,
	}
	c.VolumeMounts = []corev1.VolumeMount{
		mount("nginx-etc-nginx-secret-volume", "/etc/nginx/secretmap"),
		catrustMount(),
		curlrcMount("nginx-opensearch-curlrc-secret-volume"),
		mountSub("nginx-etc-auth-volume", "/etc/nginx/auth", "auth"),
		mount("nginx-etc-auth-default-secret-volume", "/tmp/auth/default/secretmap"),
		mountSub("nginx-runtime-logs-volume", "/var/log/nginx", "nginx"),
	}

	authSecret, authKey := SecretNginxAuth, "htpasswd"
	if !r.usesGeneratedAdmin() {
		h := r.spec.Auth.HashedCredentials
		authSecret, authKey = h.SecretName, strDefault(h.HtpasswdKey, "htpass_cred")
	}
	authVolume := corev1.Volume{Name: "nginx-etc-auth-default-secret-volume", VolumeSource: corev1.VolumeSource{
		Secret: &corev1.SecretVolumeSource{SecretName: authSecret, Items: []corev1.KeyToPath{{Key: authKey, Path: "htpasswd"}}},
	}}
	volumes := []corev1.Volume{
		secretVolume("nginx-etc-nginx-secret-volume", SecretNginx),
		r.catrustVolume(),
		r.curlrcVolume("nginx-opensearch-curlrc-secret-volume"),
		r.pvcVolume("nginx-etc-auth-volume", ClaimConfig),
		authVolume,
		r.pvcVolume("nginx-runtime-logs-volume", ClaimRuntimeLogs),
	}
	if r.authMode() == malcolmv1.AuthModeKeycloakRemote {
		c.VolumeMounts = append(c.VolumeMounts, mountSub("nginx-auth-keycloak-override-volume", "/etc/nginx/nginx_auth_keycloak.conf", "nginx_auth_keycloak.conf"))
		volumes = append(volumes, cmVolume("nginx-auth-keycloak-override-volume", "nginx-auth-keycloak-override"))
	}
	r.deployment("nginx-proxy", "nginx-proxy-deployment", 1, corev1.PodSpec{
		Containers: []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("nginx-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/config:auth;/data/runtime-logs:nginx")},
			mount("nginx-etc-auth-volume", "/data/config"),
			mount("nginx-runtime-logs-volume", "/data/runtime-logs"))},
		Volumes: volumes,
	})
}
