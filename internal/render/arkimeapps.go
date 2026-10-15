package render

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// arkimeApp describes an additional Arkime web application run from the
// Malcolm arkime image.
type arkimeApp struct {
	name     string // parliament | cont3xt (also the Arkime directory and Service name)
	port     int32
	basePath string
}

var (
	appParliament = arkimeApp{name: "parliament", port: 8008, basePath: "/parliament/"}
	appCont3xt    = arkimeApp{name: "cont3xt", port: 3218, basePath: "/cont3xt/"}
)

// arkimeAppScript writes the application's ini from Malcolm's own settings
// (the same OpenSearch, credentials, passwordSecret, header authentication and
// user auto-creation template as Arkime's viewer) and starts it.
const arkimeAppScript = `set -euo pipefail
cd "/opt/arkime/${ARKIME_APP}"
INI="/tmp/${ARKIME_APP}.ini"

OS_USER=""
OS_PASS=""
if [[ -r "${OPENSEARCH_CREDS_CONFIG_FILE:-}" ]]; then
  readarray -t CREDS < <(python3 - "${OPENSEARCH_CREDS_CONFIG_FILE}" <<'PY'
import sys
sys.path.insert(0, '/usr/local/bin')
import malcolm_utils
creds = malcolm_utils.ParseCurlFile(sys.argv[1])
print(creds['user'])
print(creds['password'])
PY
)
  OS_USER="${CREDS[0]:-}"
  OS_PASS="${CREDS[1]:-}"
fi

# Malcolm's nginx authenticates users and passes their name and roles in
# X-Forwarded-User / X-Forwarded-Roles; map roles as Malcolm does for Arkime.
if [[ "${ROLE_BASED_ACCESS:-false}" =~ ^([Tt]rue|1|yes|on)$ ]]; then
  ADMIN="(vals['x-forwarded-roles'] || '').split(',').map(s => s.trim()).includes('${ROLE_ARKIME_ADMIN:-admin}')"
else
  ADMIN="true"
fi

{
  echo "[${ARKIME_APP}]"
  echo "port=${ARKIME_APP_PORT}"
  echo "webBasePath=${ARKIME_APP_BASE_PATH}"
  echo "authMode=header"
  echo "userNameHeader=x-forwarded-user"
  echo "userAuthIps=::,0.0.0.0/0"
  echo "passwordSecret=${ARKIME_PASSWORD_SECRET}"
  echo "usersElasticsearch=${OPENSEARCH_URL}"
  [[ -n "${OS_USER}" ]] && echo "usersElasticsearchBasicAuth=${OS_USER}:${OS_PASS}"
  if [[ "${ARKIME_APP}" == "cont3xt" ]]; then
    echo "elasticsearch=${OPENSEARCH_URL}"
    [[ -n "${OS_USER}" ]] && echo "elasticsearchBasicAuth=${OS_USER}:${OS_PASS}"
  else
    echo "file=/data/parliament.json"
  fi
  [[ -n "${ARKIME_CA_TRUST_FILE:-}" ]] && echo "caTrustFile=${ARKIME_CA_TRUST_FILE}"
  grep -m1 '^userAutoCreateTmpl=' /opt/arkime/etc/config.ini || true
  echo
  echo "[user-role-mappings]"
  echo "arkimeUser=true"
  echo "${ARKIME_APP}User=true"
  echo "${ARKIME_APP}Admin=${ADMIN}"
} > "${INI}"
chmod 600 "${INI}"

ARGS=(-c "${INI}")
[[ "${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION:-false}" == "true" ]] || ARGS+=(--insecure)

if [[ "${ARKIME_APP}" == "parliament" ]] && [[ "${PARLIAMENT_SEED_CLUSTER:-false}" == "true" ]]; then
  # Once Parliament answers, add this Malcolm's Arkime if no groups exist yet.
  (
    BASE="http://127.0.0.1:${ARKIME_APP_PORT}/parliament/api"
    HDRS=(-H "X-Forwarded-User: ${MALCOLM_USERNAME}" -H "X-Forwarded-Roles: ${ROLE_ARKIME_ADMIN:-admin}")
    JAR="$(mktemp)"
    until curl -fsS -o /dev/null -c "${JAR}" "${HDRS[@]}" "${BASE}/auth"; do sleep 5; done
    NGROUPS="$(curl -fsS "${HDRS[@]}" "${BASE}/parliament" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("groups") or []))' || echo error)"
    if [[ "${NGROUPS}" == "0" ]]; then
      TOKEN="$(awk '$6 == "PARLIAMENT-COOKIE" {print $7}' "${JAR}")"
      GROUP_ID="$(curl -fsS -b "${JAR}" "${HDRS[@]}" -H "x-parliament-cookie: ${TOKEN}" -H 'Content-Type: application/json' \
        -d '{"title":"Malcolm","description":"Arkime in this Malcolm deployment"}' "${BASE}/groups" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["group"]["id"])')"
      curl -fsS -o /dev/null -b "${JAR}" "${HDRS[@]}" -H "x-parliament-cookie: ${TOKEN}" -H 'Content-Type: application/json' \
        -d "{\"title\":\"${PARLIAMENT_CLUSTER_TITLE}\",\"url\":\"/arkime\",\"localUrl\":\"${PARLIAMENT_CLUSTER_LOCAL_URL}\"}" \
        "${BASE}/groups/${GROUP_ID}/clusters" && echo "Parliament: added ${PARLIAMENT_CLUSTER_TITLE}"
    fi
    rm -f "${JAR}"
  ) &
fi

exec /opt/arkime/bin/node "${ARKIME_APP}.js" "${ARGS[@]}"
`

func (r *renderer) renderArkimeApps() {
	if r.spec.Arkime.Parliament.Enabled && r.componentEnabled("parliament") {
		r.renderArkimeApp(appParliament)
	}
	if r.spec.Arkime.Cont3xt.Enabled && r.componentEnabled("cont3xt") {
		r.renderArkimeApp(appCont3xt)
	}
}

func (r *renderer) renderArkimeApp(app arkimeApp) {
	r.service(app.name, app.name, app.name+"-deployment", svcPort{"http", app.port, 0})

	c := r.container(app.name+"-container", "arkime")
	c.TTY = false
	c.Command = []string{"/usr/bin/tini", "--", "/bin/bash", "-c", arkimeAppScript}
	uid, gid := int64Default(r.spec.Process.PUID, 1000), int64Default(r.spec.Process.PGID, 1000)
	c.SecurityContext = &corev1.SecurityContext{
		RunAsUser: ptr.To(uid), RunAsGroup: ptr.To(gid), RunAsNonRoot: ptr.To(true),
		AllowPrivilegeEscalation: ptr.To(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
	c.Ports = []corev1.ContainerPort{tcpPort("http", app.port)}
	c.EnvFrom = r.envFrom("opensearch-env", "auth-common-env", "secret:"+SecretArkimeEnv)
	c.Env = []corev1.EnvVar{
		envVal("ARKIME_APP", app.name),
		envVal("ARKIME_APP_PORT", strconv.Itoa(int(app.port))),
		envVal("ARKIME_APP_BASE_PATH", app.basePath),
		envVal("HOME", "/tmp"),
	}
	if len(r.in.CACertificate) > 0 {
		c.Env = append(c.Env, envVal("ARKIME_CA_TRUST_FILE", "/var/local/ca-trust/configmap/opensearch-remote-ca.crt"))
	}
	c.ReadinessProbe = &corev1.Probe{
		ProbeHandler:        corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(app.port)}},
		InitialDelaySeconds: 10, PeriodSeconds: 10,
	}
	c.LivenessProbe = &corev1.Probe{
		ProbeHandler:        corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(app.port)}},
		InitialDelaySeconds: 120, PeriodSeconds: 30, TimeoutSeconds: 10, FailureThreshold: 5,
	}
	c.VolumeMounts = []corev1.VolumeMount{
		catrustMount(),
		curlrcMount(app.name + "-opensearch-curlrc-secret-volume"),
		mount("tmp", "/tmp"),
	}
	spec := corev1.PodSpec{
		Containers: []corev1.Container{c},
		Volumes: []corev1.Volume{
			r.catrustVolume(),
			r.curlrcVolume(app.name + "-opensearch-curlrc-secret-volume"),
			emptyDirVolume("tmp", "100Mi"),
		},
	}
	if app.name == "parliament" {
		pc := &spec.Containers[0]
		pc.Env = append(pc.Env,
			r.adminUsernameEnv(),
			envVal("PARLIAMENT_SEED_CLUSTER", "true"),
			envVal("PARLIAMENT_CLUSTER_TITLE", r.m.Name),
			// Parliament polls <localUrl>/eshealth.json and <localUrl>/api/parliament.
			envVal("PARLIAMENT_CLUSTER_LOCAL_URL", "http://arkime:8005/arkime"),
		)
		// Parliament keeps its issues list next to its (legacy) JSON file.
		pc.VolumeMounts = append(pc.VolumeMounts, mountSub("parliament-data-volume", "/data", "parliament"))
		spec.Volumes = append(spec.Volumes, r.pvcVolume("parliament-data-volume", ClaimConfig))
		spec.InitContainers = []corev1.Container{r.dirinit("parliament-dirinit-container",
			[]corev1.EnvVar{mkdir("/data/config:parliament"), chown("/data/config/parliament")},
			mount("parliament-data-volume", "/data/config"))}
	}
	r.deployment(app.name, app.name+"-deployment", 1, spec)
}
