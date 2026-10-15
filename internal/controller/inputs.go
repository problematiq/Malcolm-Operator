package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
	"github.com/idaholab/malcolm-operator/internal/credentials"
	"github.com/idaholab/malcolm-operator/internal/render"
)

// Keys of the operator-generated credentials Secret (<name>-generated).
const (
	keyValkeyPassword          = "VALKEY_PASSWORD"
	keyValkeyRemotePassword    = "VALKEY_REMOTE_PASSWORD"
	keyNetBoxSecretKey         = "NETBOX_SECRET_KEY"
	keyNetBoxAPIToken          = "NETBOX_API_TOKEN"
	keyNetBoxSuperuserPassword = "NETBOX_SUPERUSER_PASSWORD"
	keyFilescanKey             = "FILESCAN_HTTP_SERVER_KEY"
	keyPostgresPassword        = "POSTGRES_PASSWORD"
	keyArkimePassword          = "ARKIME_PASSWORD_SECRET"
	keyKeycloakAdminPassword   = "KEYCLOAK_ADMIN_PASSWORD"
	keyAdminFingerprint        = "ADMIN_FINGERPRINT"
	keyAdminOpensslHash        = "ADMIN_OPENSSL_HASH"
	keyAdminHtpasswd           = "ADMIN_HTPASSWD"
)

// generatedSpec describes each generated value: its length and where a
// previous deployment (e.g. the Malcolm Helm chart's secret-init Job) may
// already have stored it, so existing data keeps working after migration.
var generatedSpec = []struct {
	key    string
	length int
	adopt  [][2]string // secret name, key
}{
	{keyValkeyPassword, 25, [][2]string{{render.SecretValkeyEnv, "VALKEY_PASSWORD"}, {render.SecretNetBoxEnv, "VALKEY_PASSWORD"}}},
	{keyValkeyRemotePassword, 25, [][2]string{{render.SecretValkeyRemoteEnv, "VALKEY_PASSWORD"}}},
	{keyNetBoxSecretKey, 50, [][2]string{{render.SecretNetBoxEnv, "SECRET_KEY"}}},
	{keyNetBoxAPIToken, 32, [][2]string{{render.SecretNetBoxEnv, "SUPERUSER_API_TOKEN"}}},
	{keyNetBoxSuperuserPassword, 25, [][2]string{{render.SecretNetBoxEnv, "SUPERUSER_PASSWORD"}}},
	{keyFilescanKey, 14, [][2]string{{render.SecretFilescanEnv, "FILESCAN_HTTP_SERVER_KEY"}}},
	{keyPostgresPassword, 32, [][2]string{{render.SecretPostgresEnv, "POSTGRES_PASSWORD"}}},
	{keyArkimePassword, 32, [][2]string{{render.SecretArkimeEnv, "ARKIME_PASSWORD_SECRET"}}},
	{keyKeycloakAdminPassword, 25, [][2]string{{render.SecretKeycloakEnv, "KC_BOOTSTRAP_ADMIN_PASSWORD"}}},
}

// GeneratedSecretName returns the name of the Secret that persists generated credentials.
func GeneratedSecretName(m *malcolmv1.Malcolm) string { return m.Name + "-generated" }

// AdminSecretName returns the name of the generated administrator credentials Secret.
func AdminSecretName(m *malcolmv1.Malcolm) string { return m.Name + "-admin-credentials" }

// errMissingInput indicates a user-referenced object or key is missing.
type errMissingInput struct{ msg string }

func (e *errMissingInput) Error() string { return e.msg }

func missing(format string, args ...any) error {
	return &errMissingInput{msg: fmt.Sprintf(format, args...)}
}

func isMissingInput(err error) bool {
	var m *errMissingInput
	return errors.As(err, &m)
}

func (r *MalcolmReconciler) secretData(ctx context.Context, ns, name string) (map[string][]byte, error) {
	s := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, s); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, missing("secret %s/%s not found", ns, name)
		}
		return nil, err
	}
	return s.Data, nil
}

func (r *MalcolmReconciler) secretKey(ctx context.Context, ns, name, key string) (string, error) {
	data, err := r.secretData(ctx, ns, name)
	if err != nil {
		return "", err
	}
	v, ok := data[key]
	if !ok {
		return "", missing("secret %s/%s has no key %q", ns, name, key)
	}
	return string(v), nil
}

func (r *MalcolmReconciler) optionalSecretKey(ctx context.Context, ns string, ref *malcolmv1.SecretKeyRef) (string, error) {
	if ref == nil || ref.Name == "" {
		return "", nil
	}
	return r.secretKey(ctx, ns, ref.Name, ref.Key)
}

func (r *MalcolmReconciler) credentialsFrom(ctx context.Context, ns, secret string) (*render.Credentials, error) {
	if secret == "" {
		return nil, nil
	}
	data, err := r.secretData(ctx, ns, secret)
	if err != nil {
		return nil, err
	}
	return &render.Credentials{Username: string(data["username"]), Password: string(data["password"])}, nil
}

// retainedMeta makes the ownership of an operator-created credentials Secret
// match storage.retainOnDelete: retained Secrets carry the retain annotation and
// no owner reference (so they survive deletion of the Malcolm resource);
// otherwise the Malcolm resource is their controller. It reports whether obj changed.
func (r *MalcolmReconciler) retainedMeta(m *malcolmv1.Malcolm, obj client.Object) (bool, error) {
	before := obj.DeepCopyObject().(client.Object)
	labels := obj.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	for k, v := range render.Labels(m.Name, "credentials", "") {
		labels[k] = v
	}
	obj.SetLabels(labels)
	ann := obj.GetAnnotations()
	if m.Spec.Storage.RetainOnDelete == nil || *m.Spec.Storage.RetainOnDelete {
		if ann == nil {
			ann = map[string]string{}
		}
		ann[render.AnnotationRetain] = "true"
		obj.SetAnnotations(ann)
		var refs []metav1.OwnerReference
		for _, ref := range obj.GetOwnerReferences() {
			if ref.UID != m.UID {
				refs = append(refs, ref)
			}
		}
		obj.SetOwnerReferences(refs)
	} else {
		if _, ok := ann[render.AnnotationRetain]; ok {
			delete(ann, render.AnnotationRetain)
			obj.SetAnnotations(ann)
		}
		if err := controllerutil.SetControllerReference(m, obj, r.Scheme); err != nil {
			return false, err
		}
	}
	return !apiequality.Semantic.DeepEqual(before.GetOwnerReferences(), obj.GetOwnerReferences()) ||
		!apiequality.Semantic.DeepEqual(before.GetAnnotations(), obj.GetAnnotations()) ||
		!apiequality.Semantic.DeepEqual(before.GetLabels(), obj.GetLabels()), nil
}

// ensureGenerated loads (creating or completing as necessary) the Secret that
// persists generated passwords, and returns its data.
func (r *MalcolmReconciler) ensureGenerated(ctx context.Context, m *malcolmv1.Malcolm) (*corev1.Secret, error) {
	s := &corev1.Secret{}
	key := types.NamespacedName{Namespace: m.Namespace, Name: GeneratedSecretName(m)}
	exists := true
	if err := r.Get(ctx, key, s); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, err
		}
		exists = false
		s = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}, Type: corev1.SecretTypeOpaque}
	}
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	changed := false
	for _, g := range generatedSpec {
		if len(s.Data[g.key]) > 0 {
			continue
		}
		val := ""
		for _, a := range g.adopt {
			if v, err := r.secretKey(ctx, m.Namespace, a[0], a[1]); err == nil && v != "" {
				val = v
				break
			}
		}
		if val == "" {
			var err error
			if val, err = credentials.Random(g.length); err != nil {
				return nil, err
			}
		}
		s.Data[g.key] = []byte(val)
		changed = true
	}
	metaChanged, err := r.retainedMeta(m, s)
	if err != nil {
		return nil, err
	}
	if !exists {
		return s, r.Create(ctx, s)
	}
	if changed || metaChanged {
		return s, r.Update(ctx, s)
	}
	return s, nil
}

// ensureAdmin resolves the administrator credentials and their hashes.
// It returns the name of the generated admin Secret when the operator created one.
func (r *MalcolmReconciler) ensureAdmin(ctx context.Context, m *malcolmv1.Malcolm, generated *corev1.Secret, out *render.Secrets) (string, error) {
	auth := m.Spec.Auth
	if auth.HashedCredentials != nil && auth.HashedCredentials.SecretName != "" {
		return "", nil
	}
	var username, password, generatedName string
	if auth.AdminSecret != "" {
		data, err := r.secretData(ctx, m.Namespace, auth.AdminSecret)
		if err != nil {
			return "", err
		}
		username, password = string(data["username"]), string(data["password"])
		if username == "" || password == "" {
			return "", missing("secret %s/%s must contain non-empty \"username\" and \"password\" keys", m.Namespace, auth.AdminSecret)
		}
	} else {
		generatedName = AdminSecretName(m)
		s := &corev1.Secret{}
		err := r.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: generatedName}, s)
		switch {
		case apierrors.IsNotFound(err):
			pw, err := credentials.Random(24)
			if err != nil {
				return "", err
			}
			s = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: generatedName, Namespace: m.Namespace},
				Type:       corev1.SecretTypeBasicAuth,
				Data: map[string][]byte{
					corev1.BasicAuthUsernameKey: []byte(render.DefaultAdminUsername),
					corev1.BasicAuthPasswordKey: []byte(pw),
				},
			}
			if _, err := r.retainedMeta(m, s); err != nil {
				return "", err
			}
			if err := r.Create(ctx, s); err != nil {
				return "", err
			}
		case err != nil:
			return "", err
		default:
			if changed, err := r.retainedMeta(m, s); err != nil {
				return "", err
			} else if changed {
				if err := r.Update(ctx, s); err != nil {
					return "", err
				}
			}
		}
		username, password = string(s.Data[corev1.BasicAuthUsernameKey]), string(s.Data[corev1.BasicAuthPasswordKey])
	}

	// Hashes are salted, so only recompute them when the credentials change;
	// otherwise every reconcile would roll the pods that consume them.
	sum := sha256.Sum256([]byte(username + "\x00" + password))
	fingerprint := hex.EncodeToString(sum[:])
	if string(generated.Data[keyAdminFingerprint]) != fingerprint ||
		len(generated.Data[keyAdminOpensslHash]) == 0 || len(generated.Data[keyAdminHtpasswd]) == 0 {
		md5, err := credentials.MD5Crypt(password, "")
		if err != nil {
			return "", err
		}
		ht, err := credentials.Htpasswd(username, password)
		if err != nil {
			return "", fmt.Errorf("administrator credentials: %w", err)
		}
		generated.Data[keyAdminFingerprint] = []byte(fingerprint)
		generated.Data[keyAdminOpensslHash] = []byte(md5)
		generated.Data[keyAdminHtpasswd] = []byte(ht)
		if err := r.Update(ctx, generated); err != nil {
			return "", err
		}
	}
	out.AdminUsername = username
	out.AdminOpensslHash = string(generated.Data[keyAdminOpensslHash])
	out.AdminHtpasswd = string(generated.Data[keyAdminHtpasswd])
	return generatedName, nil
}

// resolveInputs gathers everything render.Render needs from the cluster.
func (r *MalcolmReconciler) resolveInputs(ctx context.Context, m *malcolmv1.Malcolm) (*render.Inputs, string, error) {
	ns := m.Namespace
	spec := &m.Spec
	in := &render.Inputs{Malcolm: m}

	generated, err := r.ensureGenerated(ctx, m)
	if err != nil {
		return nil, "", fmt.Errorf("generated credentials: %w", err)
	}
	gen := func(k string) string { return string(generated.Data[k]) }
	s := &in.Secrets
	s.ValkeyPassword = gen(keyValkeyPassword)
	s.ValkeyRemotePassword = gen(keyValkeyRemotePassword)
	s.NetBoxSecretKey = gen(keyNetBoxSecretKey)
	s.NetBoxAPIToken = gen(keyNetBoxAPIToken)
	s.NetBoxSuperuserPassword = gen(keyNetBoxSuperuserPassword)

	adminSecret, err := r.ensureAdmin(ctx, m, generated, s)
	if err != nil {
		return nil, "", err
	}

	pick := func(ref *malcolmv1.SecretKeyRef, fallback string) (string, error) {
		if ref == nil || ref.Name == "" {
			return fallback, nil
		}
		return r.secretKey(ctx, ns, ref.Name, ref.Key)
	}
	if s.FilescanKey, err = pick(spec.FileScan.HTTPServerKeySecret, gen(keyFilescanKey)); err != nil {
		return nil, "", err
	}
	if s.PostgresPassword, err = pick(spec.Postgres.PasswordSecret, gen(keyPostgresPassword)); err != nil {
		return nil, "", err
	}
	if s.ArkimePassword, err = pick(spec.Arkime.PasswordSecret, gen(keyArkimePassword)); err != nil {
		return nil, "", err
	}
	if s.ArkimeWisePIN, err = pick(spec.Arkime.WisePINSecret, "WISE2019"); err != nil {
		return nil, "", err
	}
	if s.NetBoxRemoteToken, err = r.optionalSecretKey(ctx, ns, spec.NetBox.TokenSecret); err != nil {
		return nil, "", err
	}
	if spec.Logstash.OTKB != nil {
		if s.OTKBToken, err = r.optionalSecretKey(ctx, ns, spec.Logstash.OTKB.TokenSecret); err != nil {
			return nil, "", err
		}
	}
	if s.KeycloakClientSecret, err = r.optionalSecretKey(ctx, ns, spec.Keycloak.ClientSecret); err != nil {
		return nil, "", err
	}
	s.KeycloakAdminUsername, s.KeycloakAdminPassword = "admin", gen(keyKeycloakAdminPassword)
	if spec.Keycloak.BootstrapAdminSecret != "" {
		c, err := r.credentialsFrom(ctx, ns, spec.Keycloak.BootstrapAdminSecret)
		if err != nil {
			return nil, "", err
		}
		s.KeycloakAdminUsername, s.KeycloakAdminPassword = c.Username, c.Password
	}
	if spec.MaxMind.CredentialsSecret != "" {
		data, err := r.secretData(ctx, ns, spec.MaxMind.CredentialsSecret)
		if err != nil {
			return nil, "", err
		}
		s.MaxMindAccountID, s.MaxMindLicenseKey = string(data["accountID"]), string(data["licenseKey"])
	}
	if spec.Auth.LDAPConfigSecret != "" {
		if s.LDAPConfig, err = r.secretKey(ctx, ns, spec.Auth.LDAPConfigSecret, "nginx_ldap.conf"); err != nil {
			return nil, "", err
		}
	}

	if in.PrimaryCredentials, err = r.credentialsFrom(ctx, ns, spec.OpenSearch.CredentialsSecret); err != nil {
		return nil, "", err
	}
	if sec := spec.OpenSearch.Secondary; sec != nil {
		if in.SecondaryCredentials, err = r.credentialsFrom(ctx, ns, sec.CredentialsSecret); err != nil {
			return nil, "", err
		}
	}
	if ca := spec.OpenSearch.CACertificate; ca != nil && ca.Name != "" {
		caNS := ca.Namespace
		if caNS == "" {
			caNS = ns
		}
		key := ca.Key
		if key == "" {
			key = "ca.crt"
		}
		caSecret := &corev1.Secret{}
		if err := r.reader().Get(ctx, types.NamespacedName{Namespace: caNS, Name: ca.Name}, caSecret); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, "", missing("secret %s/%s not found", caNS, ca.Name)
			}
			return nil, "", err
		}
		v, ok := caSecret.Data[key]
		if !ok {
			return nil, "", missing("secret %s/%s has no key %q", caNS, ca.Name, key)
		}
		in.CACertificate = v
	}

	if err := r.resolvePostgresLogins(ctx, m, s); err != nil {
		return nil, "", err
	}
	if db := spec.MaxMind.Database; db != nil && db.Enabled && (db.Updates == nil || *db.Updates) {
		updated, err := r.geoipLastUpdated(ctx, m)
		if err != nil {
			return nil, "", err
		}
		if !updated.IsZero() {
			in.GeoIPUpdated = updated.UTC().Format(time.RFC3339)
		}
	}

	if spec.Logstash.Replicas == nil {
		n, err := r.countNodes(ctx, spec.Logstash.NodeCountLabel)
		if err != nil {
			return nil, "", err
		}
		in.LogstashReplicas = render.LogstashReplicas(n)
	}

	if spec.NetworkPolicy.Enabled {
		if in.KubernetesAPIAddresses, err = r.kubernetesAPIAddresses(ctx); err != nil {
			return nil, "", err
		}
	}
	if spec.Istio.Enabled {
		in.IstioAvailable = r.hasKind(schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1beta1", Kind: "VirtualService"})
	}
	return in, adminSecret, nil
}

func (r *MalcolmReconciler) countNodes(ctx context.Context, label *malcolmv1.NodeLabel) (int, error) {
	l := malcolmv1.NodeLabel{Key: "cnaps.io/node-type", Value: "Tier-1"}
	if label != nil && label.Key != "" {
		l = *label
	}
	nodes := &corev1.NodeList{}
	if err := r.List(ctx, nodes, client.MatchingLabels{l.Key: l.Value}); err != nil {
		return 0, fmt.Errorf("listing nodes: %w", err)
	}
	return len(nodes.Items), nil
}

func (r *MalcolmReconciler) kubernetesAPIAddresses(ctx context.Context) ([]string, error) {
	set := map[string]struct{}{}
	svc := &corev1.Service{}
	if err := r.reader().Get(ctx, types.NamespacedName{Namespace: metav1.NamespaceDefault, Name: "kubernetes"}, svc); err == nil {
		for _, ip := range svc.Spec.ClusterIPs {
			set[ip] = struct{}{}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}
	slices := &discoveryv1.EndpointSliceList{}
	if err := r.reader().List(ctx, slices, client.InNamespace(metav1.NamespaceDefault),
		client.MatchingLabels{discoveryv1.LabelServiceName: "kubernetes"}); err != nil {
		return nil, err
	}
	for _, sl := range slices.Items {
		for _, ep := range sl.Endpoints {
			for _, a := range ep.Addresses {
				set[a] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

func (r *MalcolmReconciler) hasKind(gvk schema.GroupVersionKind) bool {
	_, err := r.RESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
	return err == nil && !meta.IsNoMatchError(err)
}

// externalHashes hashes user-provided ConfigMaps/Secrets that rendered pods
// consume, so edits to them roll the consuming pods.
func (r *MalcolmReconciler) externalHashes(ctx context.Context, ns string, res *render.Result) map[string]string {
	desired := map[string]struct{}{}
	for _, o := range res.Objects {
		switch o.(type) {
		case *corev1.ConfigMap:
			desired["configmap/"+o.GetName()] = struct{}{}
		case *corev1.Secret:
			desired["secret/"+o.GetName()] = struct{}{}
		}
	}
	out := map[string]string{}
	for _, o := range res.Objects {
		ps := podSpecOf(o)
		if ps == nil {
			continue
		}
		for _, ref := range render.PodConfigReferences(ps) {
			if _, ok := desired[ref]; ok {
				continue
			}
			if _, ok := out[ref]; ok {
				continue
			}
			out[ref] = r.hashObject(ctx, ns, ref)
		}
	}
	return out
}

func (r *MalcolmReconciler) hashObject(ctx context.Context, ns, ref string) string {
	kind, name, _ := cutString(ref, "/")
	h := sha256.New()
	switch kind {
	case "configmap":
		cm := &corev1.ConfigMap{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, cm); err != nil {
			return ""
		}
		for _, k := range sortedKeys(cm.Data) {
			h.Write([]byte(k + "\x00" + cm.Data[k] + "\x00"))
		}
		for _, k := range sortedByteKeys(cm.BinaryData) {
			h.Write([]byte(k + "\x00"))
			h.Write(cm.BinaryData[k])
		}
	case "secret":
		s := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, s); err != nil {
			return ""
		}
		for _, k := range sortedByteKeys(s.Data) {
			h.Write([]byte(k + "\x00"))
			h.Write(s.Data[k])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// resolvePostgresLogins fills the NetBox/Keycloak database logins for an
// external PostgreSQL server and checks that every login Malcolm needs can be
// provided: from a credentials Secret, or created by the bootstrap Job.
func (r *MalcolmReconciler) resolvePostgresLogins(ctx context.Context, m *malcolmv1.Malcolm, s *render.Secrets) error {
	pg := m.Spec.Postgres
	if pg.Mode != malcolmv1.PostgresModeExternal || pg.External == nil {
		return nil
	}
	ext := pg.External
	bootstrap := ext.Bootstrap != nil && ext.Bootstrap.AdminCredentialsSecret != ""
	if bootstrap {
		data, err := r.secretData(ctx, m.Namespace, ext.Bootstrap.AdminCredentialsSecret)
		if err != nil {
			return err
		}
		if len(data["username"]) == 0 || len(data["password"]) == 0 {
			return missing("secret %s/%s must contain non-empty \"username\" and \"password\" keys", m.Namespace, ext.Bootstrap.AdminCredentialsSecret)
		}
	}
	netboxNeeded := m.Spec.NetBox.Mode == "" || m.Spec.NetBox.Mode == malcolmv1.NetBoxModeLocal
	keycloakNeeded := m.Spec.Auth.Mode == malcolmv1.AuthModeKeycloak
	login := func(app string, db malcolmv1.PostgresDatabaseSpec, needed bool) (string, string, error) {
		if db.CredentialsSecret != "" {
			c, err := r.credentialsFrom(ctx, m.Namespace, db.CredentialsSecret)
			if err != nil {
				return "", "", err
			}
			if c.Username == "" || c.Password == "" {
				return "", "", missing("secret %s/%s must contain non-empty \"username\" and \"password\" keys", m.Namespace, db.CredentialsSecret)
			}
			return c.Username, c.Password, nil
		}
		if needed && !bootstrap {
			return "", "", missing("postgres.external.%s.credentialsSecret is required unless postgres.external.bootstrap creates the login", app)
		}
		return app, s.PostgresPassword, nil
	}
	var err error
	if s.PostgresNetBoxUser, s.PostgresNetBoxPassword, err = login("netbox", ext.NetBox, netboxNeeded); err != nil {
		return err
	}
	s.PostgresKeycloakUser, s.PostgresKeycloakPassword, err = login("keycloak", ext.Keycloak, keycloakNeeded)
	return err
}

// geoipLastUpdated returns when a GeoIP update Job (the initial one or one
// started by the CronJob) last completed successfully.
func (r *MalcolmReconciler) geoipLastUpdated(ctx context.Context, m *malcolmv1.Malcolm) (time.Time, error) {
	jobs := &batchv1.JobList{}
	sel := render.SelectorLabels(m.Name)
	sel[render.LabelComponent] = render.ComponentGeoIP
	if err := r.List(ctx, jobs, client.InNamespace(m.Namespace), client.MatchingLabels(sel)); err != nil {
		return time.Time{}, err
	}
	var latest time.Time
	for _, j := range jobs.Items {
		if j.Status.CompletionTime == nil {
			continue
		}
		for _, c := range j.Status.Conditions {
			if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue && j.Status.CompletionTime.After(latest) {
				latest = j.Status.CompletionTime.Time
			}
		}
	}
	return latest, nil
}
