package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

const (
	// ClaimGeoIP holds the shared MaxMind GeoLite2 databases.
	ClaimGeoIP = "geoip-claim"
	// ComponentGeoIP labels the GeoIP update Jobs.
	ComponentGeoIP = "maxmind-geoip"
	// AnnotationGeoIPUpdated on Arkime pod templates rolls them after updates.
	AnnotationGeoIPUpdated = "malcolm.idaholab.github.io/geoip-updated"

	geoipVolume = "geoip-volume"
	// Malcolm's container setup copies the contents of any "configmap"
	// directory into its parent at start-up, so mounting the volume here puts
	// GeoLite2-*.mmdb where Arkime's config.ini expects them (/opt/arkime/etc).
	arkimeGeoIPMountPath = "/opt/arkime/etc/configmap"
)

// geoipUpdateScript downloads the databases with Malcolm's own script into a
// staging directory on the volume, then renames them into place so readers
// never see partial files. Names starting with ".." are skipped by Malcolm's
// configmap copy.
const geoipUpdateScript = `set -euo pipefail
STAGE=/geoip/..staging
rm -rf "${STAGE}" && mkdir -p "${STAGE}"
/usr/local/bin/maxmind-mmdb-download.sh -o "${STAGE}"
shopt -s nullglob
FILES=("${STAGE}"/*.mmdb)
if (( ${#FILES[@]} == 0 )); then
  echo "no GeoIP databases were downloaded" >&2
  exit 1
fi
for f in "${FILES[@]}"; do
  chmod 0644 "${f}"
  mv -f "${f}" /geoip/
done
rm -rf "${STAGE}"
ls -l /geoip
`

func (r *renderer) geoip() *malcolmv1.GeoIPDatabaseSpec {
	if d := r.spec.MaxMind.Database; d != nil && d.Enabled {
		return d
	}
	return nil
}

func (r *renderer) geoipClaimName() string {
	if d := r.geoip(); d != nil && d.Storage.ExistingClaim != "" {
		return d.Storage.ExistingClaim
	}
	return ClaimGeoIP
}

func (r *renderer) renderGeoIP() {
	d := r.geoip()
	if d == nil {
		return
	}
	if d.Storage.ExistingClaim == "" {
		pvc := &corev1.PersistentVolumeClaim{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
			ObjectMeta: metav1.ObjectMeta{Name: ClaimGeoIP, Namespace: r.ns, Labels: r.labels(ComponentGeoIP)},
			Spec:       r.claimSpec(d.Storage, "1Gi", corev1.ReadWriteMany),
		}
		if r.retainOnDelete() {
			pvc.Annotations = map[string]string{AnnotationRetain: "true"}
		}
		r.add(pvc)
	}

	if !boolDefault(d.Updates, true) {
		return
	}
	pod := func() corev1.PodSpec {
		c := r.container("geoip-update", "arkime")
		c.TTY = false
		c.Command = []string{"/bin/bash", "-c", geoipUpdateScript}
		c.EnvFrom = r.envFrom("process-env", "ssl-env", "secret:"+SecretArkimeEnv)
		c.VolumeMounts = []corev1.VolumeMount{catrustMount(), mount(geoipVolume, "/geoip")}
		return corev1.PodSpec{
			Containers: []corev1.Container{c},
			Volumes: []corev1.Volume{
				r.catrustVolume(),
				{Name: geoipVolume, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: r.geoipClaimName(),
				}}},
			},
		}
	}

	// A one-off Job fills the volume right away; the CronJob keeps it current.
	// The Job's name follows its pod spec (and the download source), so it
	// runs again when either changes.
	spec := pod()
	b, _ := json.Marshal(spec)
	h := sha256.New()
	h.Write(b)
	h.Write([]byte(r.in.Secrets.MaxMindAccountID + "\x00" + r.in.Secrets.MaxMindLicenseKey + "\x00" + r.spec.MaxMind.AlternateURL))
	r.job(ComponentGeoIP, "maxmind-geoip-init", hex.EncodeToString(h.Sum(nil))[:10], spec)
	r.cronJob(ComponentGeoIP, "maxmind-geoip-update", strDefault(d.UpdateSchedule, "0 4 * * 3,6"), pod())
}

// attachGeoIP mounts the shared databases into an Arkime pod (its first
// container is Arkime) and stops Arkime from downloading them itself.
func (r *renderer) attachGeoIP(t *corev1.PodTemplateSpec) {
	d := r.geoip()
	if d == nil || len(t.Spec.Containers) == 0 {
		return
	}
	c := &t.Spec.Containers[0]
	c.VolumeMounts = append(c.VolumeMounts, mountRO(mount(geoipVolume, arkimeGeoIPMountPath)))
	// Explicit empty values override arkime-secret-env, so start-up skips the
	// Internet download (which would stall on capture nodes without access).
	c.Env = append(c.Env,
		envVal("MAXMIND_GEOIP_DB_ACCOUNT_ID", ""),
		envVal("MAXMIND_GEOIP_DB_LICENSE_KEY", ""),
		envVal("MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL", ""),
	)
	t.Spec.Volumes = append(t.Spec.Volumes, corev1.Volume{Name: geoipVolume, VolumeSource: corev1.VolumeSource{
		PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: r.geoipClaimName(), ReadOnly: true},
	}})
	if boolDefault(d.RolloutOnUpdate, true) && r.in.GeoIPUpdated != "" {
		if t.Annotations == nil {
			t.Annotations = map[string]string{}
		}
		t.Annotations[AnnotationGeoIPUpdated] = r.in.GeoIPUpdated
	}
}
