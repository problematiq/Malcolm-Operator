package render

import (
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

// Container builders shared by several workloads (the equivalent of the Helm
// chart's _*_container.tpl helpers).

func (r *renderer) arkimeContainer(name string, caps []corev1.Capability, envFrom []string, mounts []corev1.VolumeMount) corev1.Container {
	c := r.container(name, "arkime", caps...)
	c.EnvFrom = r.envFrom(envFrom...)
	c.LivenessProbe = healthProbe(210, 90, 15, 10)
	if len(r.in.CACertificate) > 0 {
		mounts = append(mounts, mountSub("elastic-cert", "/usr/local/share/ca-certificates/elastic_ca.crt", "elastic_ca.crt"))
	}
	c.VolumeMounts = mounts
	return c
}

func (r *renderer) elasticCertVolumes() []corev1.Volume {
	if len(r.in.CACertificate) == 0 {
		return nil
	}
	return []corev1.Volume{secretVolume("elastic-cert", SecretRemoteCA)}
}

func (r *renderer) filebeatContainer(valkeySecret string, ports []corev1.ContainerPort, env []corev1.EnvVar, mounts []corev1.VolumeMount) corev1.Container {
	c := r.container("filebeat-container", "filebeat-oss")
	c.Ports = ports
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "nginx-env", "secret:"+valkeySecret, "zeek-env",
		"opensearch-env", "upload-common-env", "beats-common-env", "netbox-common-env", "filebeat-env")
	c.Env = env
	c.LivenessProbe = healthProbe(60, 30, 15, 10)
	c.VolumeMounts = mounts
	return c
}

func (r *renderer) filescanContainer(valkeySecret, zeekVolume, logsVolume string, env []corev1.EnvVar) corev1.Container {
	c := r.container("filescan-container", "filescan")
	c.Ports = []corev1.ContainerPort{tcpPort("health", 8001), tcpPort("files", 8006)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "auth-common-env", "zeek-env", "pipeline-env",
		"secret:"+valkeySecret, "secret:"+SecretFilescanEnv, "filescan-env")
	c.Env = env
	c.LivenessProbe = healthProbe(60, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{
		catrustMount(),
		mountSub(zeekVolume, "/zeek/extract_files", "extract_files"),
		mountRO(mountSub(zeekVolume, "/filescan/data/files", "extract_files/filescan")),
		mountSub(logsVolume, "/filescan/data/logs", "filescan"),
	}
	return c
}

func (r *renderer) strelkaContainer(kind, valkeySecret, configVolume string) corev1.Container {
	c := r.container("strelka-"+kind+"-container", "strelka-"+kind)
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "secret:"+valkeySecret, "pipeline-env")
	c.LivenessProbe = healthProbe(60, 30, 15, 10)
	c.VolumeMounts = []corev1.VolumeMount{catrustMount(), mount(configVolume, "/etc/strelka/configmap")}
	switch kind {
	case "frontend":
		c.Ports = []corev1.ContainerPort{tcpPort("enqueue", 57314)}
	case "backend":
		c.VolumeMounts = append(c.VolumeMounts, mount("strelka-backend-yara-rules-custom-volume", "/yara-rules/custom/configmap"))
	}
	return c
}

func (r *renderer) yaraVolume() corev1.Volume {
	return cmVolume("strelka-backend-yara-rules-custom-volume", strDefault(r.spec.FileScan.YaraRulesConfigMap, "yara-rules"))
}

// valkeyContainer runs valkey-server; persistent=true enables AOF persistence.
func (r *renderer) valkeyContainer(name, secret string, port int32, portName string, persistent bool, mounts ...corev1.VolumeMount) corev1.Container {
	v := r.spec.Valkey
	var args string
	if persistent {
		args = fmt.Sprintf("--dir /data --appendonly yes --appendfsync everysec --no-appendfsync-on-rewrite yes "+
			"--auto-aof-rewrite-percentage 100 --auto-aof-rewrite-min-size %s --save '' --maxmemory %s "+
			"--maxmemory-policy %s --requirepass $(VALKEY_PASSWORD)",
			strDefault(v.AutoAOFRewriteMinSize, r.tun.ValkeyAOFRewriteMin),
			strDefault(v.MaxMemory, r.tun.ValkeyMaxMemory),
			strDefault(v.MaxMemoryPolicy, r.tun.ValkeyMaxMemoryPolicy))
	} else {
		args = fmt.Sprintf("--save '' --appendonly no --maxmemory %s --maxmemory-policy %s --maxmemory-samples 10 "+
			"--lazyfree-lazy-eviction yes --timeout 300 --tcp-keepalive 60 --requirepass $(VALKEY_PASSWORD)",
			strDefault(v.CacheMaxMemory, r.tun.ValkeyMaxMemory),
			strDefault(v.CacheMaxMemoryPolicy, r.tun.ValkeyMaxMemoryPolicy))
	}
	c := r.container(name, "valkey")
	c.Command = []string{"/sbin/tini"}
	c.Args = []string{"--", "/usr/local/bin/docker-uid-gid-setup.sh", "/usr/local/bin/service_check_passthrough.sh",
		"-s", "valkey", "sh", "-c", "valkey-server --port " + strconv.Itoa(int(port)) + " " + args}
	c.Ports = []corev1.ContainerPort{tcpPort(portName, port)}
	c.EnvFrom = r.envFrom("process-env", "ssl-env", "secret:"+secret)
	c.LivenessProbe = healthProbe(45, 60, 15, 10)
	c.VolumeMounts = append([]corev1.VolumeMount{catrustMount()}, mounts...)
	return c
}

type zeekMode int

const (
	zeekOffline zeekMode = iota
	zeekLive
)

func (r *renderer) zeekContainer(mode zeekMode, caps []corev1.Capability, env []corev1.EnvVar, mounts []corev1.VolumeMount) corev1.Container {
	c := r.container("zeek-container", "zeek", caps...)
	if mode == zeekLive {
		c.EnvFrom = r.envFrom("process-env", "ssl-env", "upload-common-env", "zeek-env", "kafka-config", "zeek-live-env", "pcap-capture-env")
		c.LivenessProbe = healthProbe(600, 60, 30, 3)
	} else {
		// No liveness probe offline: pulling intel feeds at startup can take a long time.
		c.EnvFrom = r.envFrom("process-env", "ssl-env", "upload-common-env", "zeek-env", "zeek-offline-env")
	}
	c.Env = env
	c.VolumeMounts = append(mounts, mount("zeek-custom-volume", "/usr/local/zeek/share/zeek/site/custom/configmap"))
	return c
}

func (r *renderer) zeekCustomVolume() corev1.Volume {
	return cmVolume("zeek-custom-volume", strDefault(r.spec.Zeek.CustomConfigMap, "zeek-custom"))
}

func (r *renderer) zeekIntelPreseedVolume(name string) corev1.Volume {
	return cmVolume(name, strDefault(r.spec.Zeek.IntelPreseedConfigMap, "zeek-intel-preseed"))
}

func (r *renderer) suricataContainer(live bool, caps []corev1.Capability, envFrom []string, env []corev1.EnvVar, mounts []corev1.VolumeMount) corev1.Container {
	c := r.container("suricata-container", "suricata", caps...)
	c.EnvFrom = r.envFrom(envFrom...)
	c.Env = env
	if live {
		c.LivenessProbe = healthProbe(600, 60, 30, 3)
	} else {
		c.LivenessProbe = healthProbe(120, 30, 15, 10)
	}
	c.VolumeMounts = append(mounts,
		mount("suricata-custom-rules-volume", "/opt/suricata/rules/configmap"),
		mount("suricata-custom-configs-volume", "/opt/suricata/include-configs/configmap"))
	return c
}

func (r *renderer) suricataConfigVolumes() []corev1.Volume {
	return []corev1.Volume{
		cmVolume("suricata-custom-rules-volume", strDefault(r.spec.Suricata.RulesConfigMap, "suricata-rules")),
		cmVolume("suricata-custom-configs-volume", strDefault(r.spec.Suricata.ConfigsConfigMap, "suricata-configs")),
	}
}

func (r *renderer) wiseVolume() corev1.Volume {
	return cmVolume("wise-config", strDefault(r.spec.Arkime.WiseConfigMap, "wise-config"))
}

func (r *renderer) arkimeLuaVolume(name string) corev1.Volume {
	return cmVolume(name, strDefault(r.spec.Arkime.LuaConfigMap, "arkime-lua"))
}
