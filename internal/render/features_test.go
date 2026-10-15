package render

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

func podTemplateOf(o client.Object) *corev1.PodTemplateSpec {
	switch w := o.(type) {
	case *appsv1.Deployment:
		return &w.Spec.Template
	case *appsv1.StatefulSet:
		return &w.Spec.Template
	case *appsv1.DaemonSet:
		return &w.Spec.Template
	case *batchv1.Job:
		return &w.Spec.Template
	case *batchv1.CronJob:
		return &w.Spec.JobTemplate.Spec.Template
	}
	return nil
}

func TestServerPlacement(t *testing.T) {
	tol := corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "malcolm", Effect: corev1.TaintEffectNoSchedule}
	res := mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		s.Placement.Server = malcolmv1.ServerPlacementSpec{
			NodeSelector:      map[string]string{"cnaps.io/node-type": "Tier-1"},
			Tolerations:       []corev1.Toleration{tol},
			AvoidCaptureNodes: true,
		}
		s.MaxMind = malcolmv1.MaxMindSpec{CredentialsSecret: "mm", Database: &malcolmv1.GeoIPDatabaseSpec{Enabled: true}}
		s.Components = map[string]malcolmv1.ComponentSpec{
			"opensearch": {NodeSelector: map[string]string{"disk": "nvme"}},
			"freq":       {Affinity: &corev1.Affinity{}},
		}
	}))
	wantTerms := []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{
		{Key: "cnaps.io/arkime-capture", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"true"}},
		{Key: "cnaps.io/suricata-capture", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"true"}},
		{Key: "cnaps.io/zeek-capture", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"true"}},
		{Key: "cnaps.io/zeek-remote-capture", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"true"}},
	}}}
	server, capture := 0, 0
	for _, o := range res.Objects {
		tmpl := podTemplateOf(o)
		if tmpl == nil {
			continue
		}
		ps := tmpl.Spec
		if _, isDS := o.(*appsv1.DaemonSet); isDS {
			capture++
			if ps.NodeSelector["cnaps.io/node-type"] != "" || slicesContain(ps.Tolerations, tol) {
				t.Errorf("DaemonSet %s must not get server placement", o.GetName())
			}
			continue
		}
		server++
		if ps.NodeSelector["cnaps.io/node-type"] != "Tier-1" || !slicesContain(ps.Tolerations, tol) {
			t.Errorf("%T %s missing server placement: %v %v", o, o.GetName(), ps.NodeSelector, ps.Tolerations)
		}
		switch o.GetName() {
		case "freq-deployment":
			if ps.Affinity == nil || ps.Affinity.NodeAffinity != nil {
				t.Error("a component affinity must replace the capture-avoidance rule")
			}
		default:
			if ps.Affinity == nil || !reflect.DeepEqual(ps.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms, wantTerms) {
				t.Errorf("%s capture avoidance = %+v", o.GetName(), ps.Affinity)
			}
		}
		if o.GetName() == "opensearch" && ps.NodeSelector["disk"] != "nvme" {
			t.Error("component nodeSelector should merge with the server selector")
		}
	}
	if server != 24 || capture != 5 {
		t.Errorf("placed %d server and %d capture workloads, want 24 and 5", server, capture)
	}
}

func slicesContain(ts []corev1.Toleration, t corev1.Toleration) bool {
	for _, x := range ts {
		if reflect.DeepEqual(x, t) {
			return true
		}
	}
	return false
}

func TestCaptureExclusionTerms(t *testing.T) {
	r := newRenderer(Inputs{Malcolm: newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		s.Capture.Zeek.NodeSelector = map[string]string{"role": "sensor", "site": "a"}
		s.Capture.Suricata.NodeSelector = map[string]string{"role": "ids"}
		s.Capture.Arkime.Enabled = ptr.To(false)
		s.Capture.Zeek.RemoteSensor.Enabled = ptr.To(false)
	})})
	got := r.captureExclusionTerms()
	// not(role=sensor AND site=a) AND not(role=ids)
	want := []corev1.NodeSelectorTerm{
		{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "role", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"ids", "sensor"}}}},
		{MatchExpressions: []corev1.NodeSelectorRequirement{
			{Key: "role", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"ids"}},
			{Key: "site", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"a"}},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("terms = %+v\nwant %+v", got, want)
	}
}

func externalPostgres(bootstrap bool) func(*malcolmv1.MalcolmSpec) {
	return func(s *malcolmv1.MalcolmSpec) {
		s.Postgres.Mode = malcolmv1.PostgresModeExternal
		s.Postgres.External = &malcolmv1.PostgresExternalSpec{
			Host: "pg.example.org", Port: 6432, SSLMode: "verify-full",
			NetBox: malcolmv1.PostgresDatabaseSpec{Database: "nb", CredentialsSecret: "nb-creds"},
		}
		if bootstrap {
			s.Postgres.External.Bootstrap = &malcolmv1.PostgresBootstrapSpec{AdminCredentialsSecret: "pg-admin"}
		}
		s.Auth.Mode = malcolmv1.AuthModeKeycloak
	}
}

func TestExternalPostgres(t *testing.T) {
	logins := func(in *Inputs) {
		in.Secrets.PostgresNetBoxUser, in.Secrets.PostgresNetBoxPassword = "nbuser", "nbpw"
		in.Secrets.PostgresKeycloakUser, in.Secrets.PostgresKeycloakPassword = "keycloak", "kcpw"
	}
	res := mustRender(t, newMalcolm(externalPostgres(true)), logins)
	for _, w := range res.Workloads {
		if w.Component == "postgres" {
			t.Errorf("the PostgreSQL StatefulSet must not run in external mode: %s", w.Name)
		}
	}
	if find[*corev1.Service](res, "postgres") != nil {
		t.Error("postgres Service must not be rendered in external mode")
	}
	env := find[*corev1.Secret](res, SecretPostgresEnv).Data
	want := map[string]string{
		"POSTGRES_HOST": "pg.example.org", "DB_HOST": "pg.example.org", "PGPORT": "6432", "POSTGRES_DB": "postgres",
		"POSTGRES_NETBOX_DB": "nb", "POSTGRES_NETBOX_USER": "nbuser", "POSTGRES_NETBOX_PASSWORD": "nbpw",
		"POSTGRES_KEYCLOAK_DB": "keycloak", "POSTGRES_KEYCLOAK_PASSWORD": "kcpw",
		"DB_SSLMODE": "verify-full", "PGSSLMODE": "verify-full", "POSTGRES_PASSWORD": "", "POSTGRES_DISABLED": "true",
	}
	for k, v := range want {
		if string(env[k]) != v {
			t.Errorf("postgres-env[%s] = %q, want %q", k, env[k], v)
		}
	}
	if got := string(find[*corev1.Secret](res, SecretNetBoxEnv).Data["DB_USER"]); got != "nbuser" {
		t.Errorf("netbox DB_USER = %q", got)
	}

	var job *batchv1.Job
	for _, o := range res.Objects {
		if j, ok := o.(*batchv1.Job); ok && strings.HasPrefix(j.Name, "postgres-bootstrap-") {
			job = j
		}
	}
	if job == nil {
		t.Fatal("expected a bootstrap Job")
	}
	c := job.Spec.Template.Spec.Containers[0]
	envs := map[string]corev1.EnvVar{}
	for _, e := range c.Env {
		envs[e.Name] = e
	}
	if envs["PGHOST"].Value != "pg.example.org" || envs["PGUSER"].ValueFrom.SecretKeyRef.Name != "pg-admin" ||
		envs["BOOTSTRAP_NETBOX"].Value != "true" || envs["BOOTSTRAP_KEYCLOAK"].Value != "true" {
		t.Errorf("unexpected bootstrap env %+v", envs)
	}
	if !strings.Contains(c.Command[2], `CREATE DATABASE :"db" OWNER :"role"`) {
		t.Error("bootstrap script does not create databases")
	}
	// The Job is re-created (new name) when a login changes.
	res2 := mustRender(t, newMalcolm(externalPostgres(true)), logins, func(in *Inputs) { in.Secrets.PostgresNetBoxPassword = "rotated" })
	for _, o := range res2.Objects {
		if j, ok := o.(*batchv1.Job); ok && strings.HasPrefix(j.Name, "postgres-bootstrap-") && j.Name == job.Name {
			t.Error("bootstrap Job name should change when a password changes")
		}
	}
	// No bootstrap Job without admin credentials.
	res3 := mustRender(t, newMalcolm(externalPostgres(false)), logins)
	for _, o := range res3.Objects {
		if _, ok := o.(*batchv1.Job); ok {
			t.Errorf("unexpected Job %s", o.GetName())
		}
	}
}

func TestDeprecatedPostgresEnabled(t *testing.T) {
	res := mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) { s.Postgres.Enabled = ptr.To(false) }))
	if find[*appsv1.StatefulSet](res, "postgres-statefulset") != nil {
		t.Error("enabled=false should still disable PostgreSQL")
	}
	if got := string(find[*corev1.Secret](res, SecretPostgresEnv).Data["POSTGRES_DISABLED"]); got != "true" {
		t.Errorf("POSTGRES_DISABLED = %q", got)
	}
}

func TestGeoIPDatabase(t *testing.T) {
	spec := func(s *malcolmv1.MalcolmSpec) {
		s.MaxMind = malcolmv1.MaxMindSpec{CredentialsSecret: "mm", Database: &malcolmv1.GeoIPDatabaseSpec{Enabled: true}}
	}
	res := mustRender(t, newMalcolm(spec), func(in *Inputs) { in.GeoIPUpdated = "2026-10-14T04:00:00Z" })

	pvc := find[*corev1.PersistentVolumeClaim](res, ClaimGeoIP)
	if pvc == nil || pvc.Spec.AccessModes[0] != corev1.ReadWriteMany || pvc.Spec.Resources.Requests.Storage().String() != "1Gi" ||
		pvc.Annotations[AnnotationRetain] != "true" {
		t.Fatalf("unexpected GeoIP claim %+v", pvc)
	}
	cron := find[*batchv1.CronJob](res, "maxmind-geoip-update")
	if cron == nil || cron.Spec.Schedule != "0 4 * * 3,6" || cron.Spec.ConcurrencyPolicy != batchv1.ForbidConcurrent {
		t.Fatalf("unexpected CronJob %+v", cron)
	}
	if cron.Spec.JobTemplate.Labels[LabelComponent] != ComponentGeoIP {
		t.Error("CronJob's Jobs must carry the GeoIP component label (used to find the last update)")
	}
	initJobs := 0
	for _, o := range res.Objects {
		if j, ok := o.(*batchv1.Job); ok && strings.HasPrefix(j.Name, "maxmind-geoip-init-") {
			initJobs++
			c := j.Spec.Template.Spec.Containers[0]
			if !strings.Contains(c.Command[2], "maxmind-mmdb-download.sh") || c.VolumeMounts[1].MountPath != "/geoip" || c.VolumeMounts[1].ReadOnly {
				t.Errorf("unexpected update container %+v", c)
			}
		}
	}
	if initJobs != 1 {
		t.Errorf("want 1 initial GeoIP Job, got %d", initJobs)
	}

	for _, name := range []string{"arkime-deployment", "arkime-live-daemonset"} {
		var tmpl *corev1.PodTemplateSpec
		for _, o := range res.Objects {
			if o.GetName() == name {
				tmpl = podTemplateOf(o)
			}
		}
		c := tmpl.Spec.Containers[0]
		mounted := false
		for _, m := range c.VolumeMounts {
			if m.Name == geoipVolume && m.MountPath == "/opt/arkime/etc/configmap" && m.ReadOnly {
				mounted = true
			}
		}
		blanked := 0
		for _, e := range c.Env {
			if strings.HasPrefix(e.Name, "MAXMIND_GEOIP_DB_") && e.Value == "" {
				blanked++
			}
		}
		claimOK := false
		for _, v := range tmpl.Spec.Volumes {
			if v.Name == geoipVolume && v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == ClaimGeoIP {
				claimOK = true
			}
		}
		if !mounted || blanked != 3 || !claimOK {
			t.Errorf("%s: geoip mounted=%v blanked=%d claim=%v", name, mounted, blanked, claimOK)
		}
		if tmpl.Annotations[AnnotationGeoIPUpdated] != "2026-10-14T04:00:00Z" {
			t.Errorf("%s should roll after GeoIP updates", name)
		}
	}

	// rolloutOnUpdate=false keeps pods stable; existingClaim skips the PVC.
	res = mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		spec(s)
		s.MaxMind.Database.RolloutOnUpdate = ptr.To(false)
		s.MaxMind.Database.Storage.ExistingClaim = "shared-geoip"
		s.MaxMind.Database.Storage.Size = ptr.To(resource.MustParse("2Gi"))
	}), func(in *Inputs) { in.GeoIPUpdated = "2026-10-14T04:00:00Z" })
	if find[*corev1.PersistentVolumeClaim](res, ClaimGeoIP) != nil {
		t.Error("existingClaim must not create a PVC")
	}
	if a := find[*appsv1.DaemonSet](res, "arkime-live-daemonset").Spec.Template.Annotations[AnnotationGeoIPUpdated]; a != "" {
		t.Error("rolloutOnUpdate=false must not annotate pods")
	}
	// updates=false: the volume is mounted but no download Jobs run.
	res = mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		spec(s)
		s.MaxMind.Database.Updates = ptr.To(false)
	}))
	for _, o := range res.Objects {
		if _, ok := o.(*batchv1.Job); ok {
			t.Errorf("unexpected Job %s with updates disabled", o.GetName())
		}
		if _, ok := o.(*batchv1.CronJob); ok {
			t.Errorf("unexpected CronJob %s with updates disabled", o.GetName())
		}
	}
	if find[*corev1.PersistentVolumeClaim](res, ClaimGeoIP) == nil {
		t.Error("the GeoIP volume is still needed with updates disabled")
	}
	// Disabled: nothing GeoIP-related is rendered.
	res = mustRender(t, newMalcolm(nil))
	for _, o := range res.Objects {
		if strings.Contains(o.GetName(), "geoip") {
			t.Errorf("unexpected %s with GeoIP disabled", o.GetName())
		}
	}
}

func TestWiseGUISwitchReachesNginx(t *testing.T) {
	nginxEnv := func(res *Result) map[string]string {
		out := map[string]string{}
		for _, e := range find[*appsv1.Deployment](res, "nginx-proxy-deployment").Spec.Template.Spec.Containers[0].Env {
			out[e.Name] = e.Value
		}
		return out
	}
	res := mustRender(t, newMalcolm(nil))
	if got := find[*corev1.ConfigMap](res, "arkime-offline-env").Data["ARKIME_EXPOSE_WISE_GUI"]; got != "true" {
		t.Errorf("WISE GUI should be exposed by default, got %q", got)
	}
	if _, ok := nginxEnv(res)["ARKIME_EXPOSE_WISE_GUI"]; ok {
		t.Error("nginx already defaults to serving /wise; no override expected")
	}
	for _, spec := range []func(*malcolmv1.MalcolmSpec){
		func(s *malcolmv1.MalcolmSpec) { s.Arkime.ExposeWiseGUI = ptr.To(false) },
		func(s *malcolmv1.MalcolmSpec) {
			s.Config = map[string]map[string]string{"arkime-offline": {"ARKIME_EXPOSE_WISE_GUI": "false"}}
		},
	} {
		res = mustRender(t, newMalcolm(spec))
		if got := find[*corev1.ConfigMap](res, "arkime-offline-env").Data["ARKIME_EXPOSE_WISE_GUI"]; got != "false" {
			t.Errorf("arkime-offline-env ARKIME_EXPOSE_WISE_GUI = %q", got)
		}
		if got := nginxEnv(res)["ARKIME_EXPOSE_WISE_GUI"]; got != "false" {
			t.Errorf("nginx must stop routing /wise too, got %q", got)
		}
	}
	res = mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) { s.Arkime.AllowWiseGUIConfig = true }))
	if got := find[*corev1.ConfigMap](res, "arkime-offline-env").Data["ARKIME_ALLOW_WISE_GUI_CONFIG"]; got != "true" {
		t.Errorf("ARKIME_ALLOW_WISE_GUI_CONFIG = %q", got)
	}
}

func TestRemoteOpenSearchKeepsDashboardsAndTrustsCA(t *testing.T) {
	res := mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		s.OpenSearch = malcolmv1.OpenSearchSpec{
			Mode: malcolmv1.OpenSearchModeRemote, URL: "https://os.example.org:9200",
			CredentialsSecret: "os", SSLCertificateVerification: true,
			CACertificate: &malcolmv1.CrossNamespaceSecretKeyRef{Name: "os-ca"},
		}
	}), func(in *Inputs) {
		in.PrimaryCredentials = &Credentials{Username: "malcolm", Password: "pw"}
		in.CACertificate = []byte("-----BEGIN CERTIFICATE-----\n")
	})
	if find[*appsv1.Deployment](res, "dashboards-deployment") == nil {
		t.Error("Malcolm's Dashboards should run against a remote OpenSearch")
	}
	if find[*appsv1.StatefulSet](res, "opensearch") != nil {
		t.Error("no local OpenSearch in remote mode")
	}
	if got := find[*corev1.ConfigMap](res, "dashboards-env").Data["DASHBOARDS_URL"]; got != "http://dashboards:5601/dashboards" {
		t.Errorf("DASHBOARDS_URL = %q", got)
	}
	for _, o := range res.Objects {
		tmpl := podTemplateOf(o)
		if tmpl == nil {
			continue
		}
		for _, v := range tmpl.Spec.Volumes {
			if v.Name != "var-local-catrust-volume" {
				continue
			}
			if v.Projected == nil || v.Projected.Sources[1].Secret.Name != SecretRemoteCA {
				t.Errorf("%s does not trust the remote CA: %+v", o.GetName(), v.VolumeSource)
			}
		}
	}
}

func TestParliamentAndCont3xt(t *testing.T) {
	res := mustRender(t, newMalcolm(nil))
	for _, n := range []string{"parliament-deployment", "cont3xt-deployment"} {
		if find[*appsv1.Deployment](res, n) != nil {
			t.Errorf("%s must be opt-in", n)
		}
	}

	res = mustRender(t, newMalcolm(func(s *malcolmv1.MalcolmSpec) {
		s.Arkime.Parliament.Enabled = true
		s.Arkime.Cont3xt.Enabled = true
		s.Placement.Server.NodeSelector = map[string]string{"tier": "server"}
		s.OpenSearch = malcolmv1.OpenSearchSpec{Mode: malcolmv1.OpenSearchModeRemote, URL: "https://os:9200",
			SSLCertificateVerification: true, CACertificate: &malcolmv1.CrossNamespaceSecretKeyRef{Name: "os-ca"}}
	}), func(in *Inputs) { in.CACertificate = []byte("CA") })

	for _, app := range []struct {
		name, base string
		port       int32
	}{{"parliament", "/parliament/", 8008}, {"cont3xt", "/cont3xt/", 3218}} {
		svc := find[*corev1.Service](res, app.name)
		if svc == nil || svc.Spec.Ports[0].Port != app.port || svc.Spec.Selector[LabelPodName] != app.name+"-deployment" {
			t.Fatalf("%s Service = %+v", app.name, svc)
		}
		d := find[*appsv1.Deployment](res, app.name+"-deployment")
		ps := d.Spec.Template.Spec
		c := ps.Containers[0]
		env := map[string]string{}
		for _, e := range c.Env {
			env[e.Name] = e.Value
		}
		if env["ARKIME_APP"] != app.name || env["ARKIME_APP_BASE_PATH"] != app.base || env["ARKIME_APP_PORT"] != strconv.Itoa(int(app.port)) {
			t.Errorf("%s env = %v", app.name, env)
		}
		if env["ARKIME_CA_TRUST_FILE"] != "/var/local/ca-trust/configmap/opensearch-remote-ca.crt" {
			t.Errorf("%s should trust the imported CA", app.name)
		}
		if !strings.HasSuffix(c.Image, "/arkime:"+DefaultVersion) || c.Command[0] != "/usr/bin/tini" {
			t.Errorf("%s runs %s %v", app.name, c.Image, c.Command)
		}
		if sc := c.SecurityContext; sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || *sc.RunAsUser != 1000 {
			t.Errorf("%s should run as the unprivileged Malcolm user", app.name)
		}
		if ps.NodeSelector["tier"] != "server" {
			t.Errorf("%s should follow server placement", app.name)
		}
		// The URL Secret (credentials embedded in OPENSEARCH_URL) is not needed:
		// credentials come from the mounted curlrc.
		refs := strings.Join(PodConfigReferences(&ps), " ")
		for _, want := range []string{"configmap/opensearch-env", "configmap/auth-common-env", "secret/" + SecretArkimeEnv, "secret/" + SecretCurlrc} {
			if !strings.Contains(refs, want) {
				t.Errorf("%s does not consume %s", app.name, want)
			}
		}
	}
	p := find[*appsv1.Deployment](res, "parliament-deployment").Spec.Template.Spec
	if p.InitContainers[0].Name != "parliament-dirinit-container" || p.Containers[0].VolumeMounts[3].SubPath != "parliament" {
		t.Error("Parliament should keep its data on config-claim")
	}
	seed := false
	for _, e := range p.Containers[0].Env {
		if e.Name == "PARLIAMENT_CLUSTER_LOCAL_URL" && e.Value == "http://arkime:8005/arkime" {
			seed = true
		}
	}
	if !seed {
		t.Error("Parliament should be seeded with this Malcolm's Arkime viewer")
	}
	if c := find[*appsv1.Deployment](res, "cont3xt-deployment").Spec.Template.Spec; len(c.InitContainers) != 0 {
		t.Error("Cont3xt keeps no local data")
	}
}
