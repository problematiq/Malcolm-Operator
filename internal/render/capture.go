package render

import (
	corev1 "k8s.io/api/core/v1"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

func selectorOrDefault(sel, def map[string]string) map[string]string {
	if len(sel) == 0 {
		return copyMap(def)
	}
	return copyMap(sel)
}

func (r *renderer) zeekSelector() map[string]string {
	return selectorOrDefault(r.spec.Capture.Zeek.NodeSelector, defaultZeekSelector)
}
func (r *renderer) zeekRemoteSelector() map[string]string {
	return selectorOrDefault(r.spec.Capture.Zeek.RemoteSensor.NodeSelector, defaultZeekRemoteSel)
}
func (r *renderer) suricataSelector() map[string]string {
	return selectorOrDefault(r.spec.Capture.Suricata.NodeSelector, defaultSuricataSelector)
}

func (r *renderer) hostPaths() malcolmv1.CaptureHostPaths {
	h := r.spec.Capture.HostPaths
	h.ZeekLogs = strDefault(h.ZeekLogs, "/var/lib/malcolm/zeek-logs")
	h.ZeekExtractedFiles = strDefault(h.ZeekExtractedFiles, "/var/lib/malcolm/extracted-files")
	h.SuricataLogs = strDefault(h.SuricataLogs, "/var/lib/malcolm/suricata-logs")
	h.ArkimePCAP = strDefault(h.ArkimePCAP, "/var/lib/malcolm/arkime-pcap")
	h.FilescanLogs = strDefault(h.FilescanLogs, "/var/lib/malcolm/filescan-logs")
	h.ValkeyAOF = strDefault(h.ValkeyAOF, "/var/lib/malcolm/valkey-aof")
	return h
}

// capturePod returns a host-networked pod spec scheduled by nodeSelector.
func (r *renderer) capturePod(nodeSelector map[string]string) corev1.PodSpec {
	return corev1.PodSpec{
		// ClusterFirstWithHostNet keeps cluster DNS working with hostNetwork.
		DNSPolicy:    corev1.DNSClusterFirstWithHostNet,
		HostNetwork:  true,
		NodeSelector: nodeSelector,
		Tolerations:  append([]corev1.Toleration{}, r.spec.Capture.Tolerations...),
	}
}

func (r *renderer) renderCaptureWorkloads() {
	if r.pcapCaptureEnabled() {
		r.renderPCAPCapture()
	}
	if r.zeekLiveEnabled() {
		r.renderZeekLive()
	}
	if r.zeekRemoteEnabled() {
		r.renderZeekRemoteSensor()
	}
	if r.suricataLiveEnabled() {
		r.renderSuricataLive()
	}
	if r.arkimeLiveEnabled() {
		r.renderArkimeLive()
	}
	if (r.zeekLiveEnabled() || r.suricataLiveEnabled()) && r.componentEnabled("filebeat") {
		r.renderFilebeatLive()
	}
}

func (r *renderer) renderPCAPCapture() {
	c := r.container("pcap-capture-container", "pcap-capture", capIPCLock, capSysResource, capSysAdmin, capNetAdmin, capNetRaw)
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "pcap-capture-env")
	c.Env = []corev1.EnvVar{envVal("PCAP_CAPTURE_DISABLED", "false")}
	c.LivenessProbe = healthProbe(60, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{catrustMount(), mountSub("capture-pcap-volume", "/pcap", "upload")}
	ps := r.capturePod(selectorOrDefault(r.spec.Capture.PCAP.NodeSelector, defaultPCAPSelector))
	ps.Containers = []corev1.Container{c}
	ps.InitContainers = []corev1.Container{r.dirinit("pcap-capture-dirinit-container",
		[]corev1.EnvVar{mkdir("/data/pcap:processed,upload")},
		mount("capture-pcap-volume", "/data/pcap"))}
	ps.Volumes = []corev1.Volume{r.catrustVolume(), r.pvcVolume("capture-pcap-volume", ClaimPCAP)}
	r.daemonSet("pcap-capture", "pcap-capture-deployment", ps)
}

func zeekLiveMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		catrustMount(),
		mountSub("zeek-live-extract-files-volume", "/zeek/extract_files", "extract_files"),
		mountSub("zeek-live-logs-volume", "/zeek/live", "live"),
		mount("zeek-live-intel-preseed-volume", "/usr/local/zeek/share/zeek/site/intel-preseed/configmap"),
		mountSub("zeek-intel-volume", "/usr/local/zeek/share/zeek/site/intel", "zeek/intel"),
	}
}

const zeekIntelDirs = "zeek/intel/Mandiant,zeek/intel/Google,zeek/intel/MISP,zeek/intel/STIX"

func (r *renderer) renderZeekLive() {
	hp := r.hostPaths()
	c := r.zeekContainer(zeekLive, []corev1.Capability{capNetAdmin, capNetRaw, capSysNice},
		[]corev1.EnvVar{envVal("ZEEK_DISABLED", "false"), nodeNameEnv()},
		zeekLiveMounts())
	ps := r.capturePod(r.zeekSelector())
	ps.Containers = []corev1.Container{c}
	ps.InitContainers = []corev1.Container{r.dirinit("zeek-live-dirinit-container",
		[]corev1.EnvVar{
			chown("/zeek"),
			mkdir("/config:" + zeekIntelDirs + ";/zeek:current,extract_files/filescan,live/logs,processed,upload;/zeek-files:extract_files/filescan"),
		},
		mount("zeek-intel-volume", "/config"),
		mount("zeek-live-logs-volume", "/zeek"),
		mount("zeek-live-extract-files-volume", "/zeek-files"))}
	ps.Volumes = []corev1.Volume{
		r.catrustVolume(),
		r.pvcVolume("zeek-live-extract-files-volume", ClaimZeek),
		r.zeekIntelPreseedVolume("zeek-live-intel-preseed-volume"),
		r.pvcVolume("zeek-intel-volume", ClaimConfig),
		hostPathVolume("zeek-live-logs-volume", hp.ZeekLogs),
		r.zeekCustomVolume(),
	}
	r.daemonSet("zeek-live", "zeek-live-daemonset", ps)
}

// renderZeekRemoteSensor renders the self-contained "hedgehog" sensor: Zeek plus
// its own filescan/Strelka pipeline, Valkey and Filebeat, all on node-local storage.
func (r *renderer) renderZeekRemoteSensor() {
	hp := r.hostPaths()
	p := r.valkeyPorts()
	zeekOff := r.env["zeek-offline"]

	zeek := r.zeekContainer(zeekLive, []corev1.Capability{capNetAdmin, capNetRaw, capSysNice},
		[]corev1.EnvVar{
			envVal("ZEEK_DISABLED", "false"),
			nodeNameEnv(),
			envVal("ZEEK_INTEL_REFRESH_CRON_EXPRESSION", zeekOff["ZEEK_INTEL_REFRESH_CRON_EXPRESSION"]),
			envVal("ZEEK_INTEL_REFRESH_ON_STARTUP", zeekOff["ZEEK_INTEL_REFRESH_ON_STARTUP"]),
		},
		zeekLiveMounts())
	filescan := r.filescanContainer(SecretValkeyRemoteEnv, "zeek-live-extract-files-volume", "filescan-live-logs-volume",
		[]corev1.EnvVar{
			envVal("FILESCAN_HTTP_SERVER_ENABLE", btoa(boolDefault(r.spec.FileScan.RemoteSensorHTTPServer, false))),
			envVal("FILESCAN_PRESERVATION", strDefault(r.spec.FileScan.RemoteSensorPreservation, "none")),
		})
	filebeat := r.filebeatContainer(SecretValkeyRemoteEnv, nil,
		[]corev1.EnvVar{
			envVal("MALCOLM_PROFILE", "hedgehog"),
			nodeNameEnv(),
			envVal("FILEBEAT_ZEEK_LOG_LIVE_PATH", "/zeek/live"),
			envVal("FILEBEAT_SURICATA_LOG_PATH", "/suricata"),
			envVal("FILEBEAT_FILESCAN_LOG_PATH", "/filescan"),
		},
		[]corev1.VolumeMount{
			catrustMount(),
			curlrcMount("filebeat-opensearch-curlrc-secret-volume"),
			mount("suricata-live-logs-volume", "/suricata"),
			mount("zeek-live-logs-volume", "/zeek"),
			mountSub("filescan-live-logs-volume", "/filescan", "filescan"),
		})

	ps := r.capturePod(r.zeekRemoteSelector())
	ps.Containers = []corev1.Container{
		zeek,
		filescan,
		r.strelkaContainer("frontend", SecretValkeyRemoteEnv, "strelka-frontend-live-config-volume"),
		r.strelkaContainer("backend", SecretValkeyRemoteEnv, "strelka-backend-live-config-volume"),
		r.strelkaContainer("manager", SecretValkeyRemoteEnv, "strelka-manager-live-config-volume"),
		r.valkeyContainer("valkey-container", SecretValkeyRemoteEnv, p.Remote, "valkey-sensor", true,
			mountSub("valkey-remotesensor-volume", "/data", "data")),
		r.valkeyContainer("valkey-cache-container", SecretValkeyRemoteEnv, p.RemoteCache, "valkeyca-sensor", false),
		filebeat,
	}
	ps.InitContainers = []corev1.Container{r.dirinit("zeek-remotesensor-dirinit-container",
		[]corev1.EnvVar{
			chown("/config;/filescan;/valkey;/suricata-live-logs;/zeek-live-logs;/zeek-files"),
			mkdir("/suricata-live-logs:live;/filescan:filescan;/config:" + zeekIntelDirs +
				";/zeek-live-logs:current,live/logs,processed,upload;/zeek-files:extract_files/filescan;/valkey:data"),
		},
		mount("filescan-live-logs-volume", "/filescan"),
		mount("zeek-intel-volume", "/config"),
		mount("zeek-live-logs-volume", "/zeek-live-logs"),
		mount("suricata-live-logs-volume", "/suricata-live-logs"),
		mount("zeek-live-extract-files-volume", "/zeek-files"),
		mount("valkey-remotesensor-volume", "/valkey"))}
	ps.Volumes = []corev1.Volume{
		r.catrustVolume(),
		hostPathVolume("zeek-live-extract-files-volume", hp.ZeekExtractedFiles),
		hostPathVolume("valkey-remotesensor-volume", hp.ValkeyAOF),
		r.zeekIntelPreseedVolume("zeek-live-intel-preseed-volume"),
		emptyDirVolume("zeek-intel-volume", "4Gi"),
		hostPathVolume("zeek-live-logs-volume", hp.ZeekLogs),
		hostPathVolume("suricata-live-logs-volume", hp.SuricataLogs),
		r.curlrcVolume("filebeat-opensearch-curlrc-secret-volume"),
		hostPathVolume("filescan-live-logs-volume", hp.FilescanLogs),
		cmVolume("strelka-frontend-live-config-volume", "strelka-frontend-config"),
		cmVolume("strelka-backend-live-config-volume", "strelka-backend-config"),
		r.yaraVolume(),
		cmVolume("strelka-manager-live-config-volume", "strelka-manager-config"),
		r.zeekCustomVolume(),
	}
	r.daemonSet("zeek-live-remotesensor", "zeek-live-daemonset-remotesensor", ps)
}

func (r *renderer) renderSuricataLive() {
	hp := r.hostPaths()
	c := r.suricataContainer(true, []corev1.Capability{capIPCLock, capSysResource, capNetAdmin, capNetRaw, capSysNice},
		[]string{"process-env", "ssl-env", "upload-common-env", "suricata-env", "suricata-live-env", "pcap-capture-env"},
		[]corev1.EnvVar{envVal("SURICATA_DISABLED", "false"), nodeNameEnv()},
		[]corev1.VolumeMount{catrustMount(), mount("suricata-live-logs-volume", "/var/log/suricata")})
	ps := r.capturePod(r.suricataSelector())
	ps.Containers = []corev1.Container{c}
	ps.InitContainers = []corev1.Container{r.dirinit("suricata-live-dirinit-container",
		[]corev1.EnvVar{chown("/suricata"), mkdir("/suricata:live")},
		mount("suricata-live-logs-volume", "/suricata"))}
	ps.Volumes = append([]corev1.Volume{
		r.catrustVolume(),
		hostPathVolume("suricata-live-logs-volume", hp.SuricataLogs),
	}, r.suricataConfigVolumes()...)
	d := r.daemonSet("suricata-live", "suricata-live-daemonset", ps)
	r.instrumentCoverage(&d.Spec.Template.Spec, len(r.component("suricata-live").Sidecars))
}

func (r *renderer) renderArkimeLive() {
	hp := r.hostPaths()
	c := r.arkimeContainer("arkime-live-container",
		[]corev1.Capability{capIPCLock, capSysResource, capNetAdmin, capNetRaw, capSysNice},
		[]string{"process-env", "ssl-env", "opensearch-env", "upload-common-env", "pcap-capture-env", "arkime-env", "arkime-live-env", "secret:" + SecretArkimeEnv},
		[]corev1.VolumeMount{
			mount("arkime-live-lua-volume", "/opt/arkime/lua/configmap"),
			catrustMount(),
			curlrcMount("arkime-live-opensearch-curlrc-secret-volume"),
			mount("arkime-live-pcap-volume", "/data/pcap"),
			mount("arkime-live-config-volume", "/opt/arkime/wiseini"),
		})
	c.Env = []corev1.EnvVar{nodeNameEnv()}
	ps := r.capturePod(selectorOrDefault(r.spec.Capture.Arkime.NodeSelector, defaultArkimeSelector))
	ps.Containers = []corev1.Container{c}
	ps.InitContainers = []corev1.Container{r.dirinit("arkime-live-dirinit-container",
		[]corev1.EnvVar{
			chown("/pcap"),
			mkdir("/pcap:arkime-live;/opt/arkime:wiseini"),
			pcopy("/opt/arkime/etc/wise.ini.example:/opt/arkime/wiseini/wise.ini"),
		},
		mount("arkime-live-pcap-volume", "/pcap"),
		mount("arkime-live-config-volume", "/opt/arkime/wiseini"),
		mountSub("wise-config", "/opt/arkime/etc/wise.ini.example", "wise.ini"))}
	ps.Volumes = append([]corev1.Volume{
		r.catrustVolume(),
		r.arkimeLuaVolume("arkime-live-lua-volume"),
		r.curlrcVolume("arkime-live-opensearch-curlrc-secret-volume"),
		r.wiseVolume(),
		emptyDirVolume("arkime-live-config-volume", "50Mi"),
		hostPathVolume("arkime-live-pcap-volume", hp.ArkimePCAP),
	}, r.elasticCertVolumes()...)
	ds := r.daemonSet("arkime-live", "arkime-live-daemonset", ps)
	r.attachGeoIP(&ds.Spec.Template)
}

func (r *renderer) renderFilebeatLive() {
	hp := r.hostPaths()
	c := r.filebeatContainer(SecretValkeyEnv,
		[]corev1.ContainerPort{tcpPort("tcpjson", 5045)},
		[]corev1.EnvVar{
			nodeNameEnv(),
			envVal("FILEBEAT_ZEEK_LOG_LIVE_PATH", "/zeek/live"),
			envVal("FILEBEAT_FILESCAN_LOG_PATH", "/filescan"),
		},
		[]corev1.VolumeMount{
			catrustMount(),
			curlrcMount("filebeat-opensearch-curlrc-secret-volume"),
			mount("suricata-live-logs-volume", "/suricata"),
			mount("zeek-live-logs-volume", "/zeek"),
			mount("filescan-logs-volume", "/filescan"),
		})
	ps := corev1.PodSpec{
		Affinity:    &corev1.Affinity{NodeAffinity: r.filebeatNodeAffinity()},
		Tolerations: append([]corev1.Toleration{}, r.spec.Capture.Tolerations...),
		Containers:  []corev1.Container{c},
		InitContainers: []corev1.Container{r.dirinit("filebeat-dirinit-container",
			[]corev1.EnvVar{chown("/filescan;/suricata;/zeek"), mkdir("/suricata:live;/zeek:live")},
			mount("filescan-logs-volume", "/filescan"),
			mount("suricata-live-logs-volume", "/suricata"),
			mount("zeek-live-logs-volume", "/zeek"))},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			r.curlrcVolume("filebeat-opensearch-curlrc-secret-volume"),
			hostPathVolume("filescan-logs-volume", hp.FilescanLogs),
			hostPathVolume("suricata-live-logs-volume", hp.SuricataLogs),
			hostPathVolume("zeek-live-logs-volume", hp.ZeekLogs),
		},
	}
	r.daemonSet("filebeat", "filebeat-daemonset", ps)
}

// filebeatNodeAffinity schedules the live filebeat DaemonSet on nodes selected
// for live Zeek or Suricata capture, excluding remote-sensor nodes (whose
// sensor pod ships its own filebeat). With the default selectors this is
// identical to the Helm chart's filebeat.daemonsetNodeAffinity.
func (r *renderer) filebeatNodeAffinity() *corev1.NodeAffinity {
	if a := r.spec.Filebeat.DaemonSetNodeAffinity; a != nil {
		return a.DeepCopy()
	}
	var selectors []map[string]string
	if r.suricataLiveEnabled() {
		selectors = append(selectors, r.suricataSelector())
	}
	if r.zeekLiveEnabled() {
		selectors = append(selectors, r.zeekSelector())
	}
	var remote map[string]string
	if r.zeekRemoteEnabled() {
		remote = r.zeekRemoteSelector()
	}
	var terms []corev1.NodeSelectorTerm
	for _, sel := range selectors {
		base := make([]corev1.NodeSelectorRequirement, 0, len(sel))
		for _, k := range sortedKeys(sel) {
			base = append(base, corev1.NodeSelectorRequirement{Key: k, Operator: corev1.NodeSelectorOpIn, Values: []string{sel[k]}})
		}
		if len(remote) == 0 {
			terms = append(terms, corev1.NodeSelectorTerm{MatchExpressions: base})
			continue
		}
		// "not a remote sensor" == for some remote key k: k missing OR k != value.
		for _, k := range sortedKeys(remote) {
			terms = append(terms,
				corev1.NodeSelectorTerm{MatchExpressions: append(append([]corev1.NodeSelectorRequirement{}, base...),
					corev1.NodeSelectorRequirement{Key: k, Operator: corev1.NodeSelectorOpDoesNotExist})},
				corev1.NodeSelectorTerm{MatchExpressions: append(append([]corev1.NodeSelectorRequirement{}, base...),
					corev1.NodeSelectorRequirement{Key: k, Operator: corev1.NodeSelectorOpNotIn, Values: []string{remote[k]}})},
			)
		}
	}
	return &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: terms}}
}
