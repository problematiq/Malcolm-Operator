package render

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	corev1 "k8s.io/api/core/v1"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

// postgresMode resolves spec.postgres.mode, honoring the deprecated enabled flag.
func (r *renderer) postgresMode() malcolmv1.PostgresMode {
	if m := r.spec.Postgres.Mode; m != "" {
		return m
	}
	if !boolDefault(r.spec.Postgres.Enabled, true) {
		return malcolmv1.PostgresModeDisabled
	}
	return malcolmv1.PostgresModeLocal
}

// postgresEnabled reports whether the in-cluster PostgreSQL StatefulSet runs.
func (r *renderer) postgresEnabled() bool { return r.postgresMode() == malcolmv1.PostgresModeLocal }

func (r *renderer) postgresExternal() *malcolmv1.PostgresExternalSpec {
	if r.postgresMode() != malcolmv1.PostgresModeExternal {
		return nil
	}
	if ext := r.spec.Postgres.External; ext != nil {
		return ext
	}
	return &malcolmv1.PostgresExternalSpec{}
}

// postgresLogins returns the NetBox and Keycloak database names and logins.
func (r *renderer) postgresLogins() (nbDB, nbUser, nbPass, kcDB, kcUser, kcPass string) {
	s, pg := r.in.Secrets, r.spec.Postgres
	nbDB, kcDB = strDefault(pg.NetBoxDatabase, "netbox"), strDefault(pg.KeycloakDatabase, "keycloak")
	if ext := r.postgresExternal(); ext != nil {
		nbDB = strDefault(ext.NetBox.Database, nbDB)
		kcDB = strDefault(ext.Keycloak.Database, kcDB)
	}
	nbUser, nbPass = strDefault(s.PostgresNetBoxUser, "netbox"), strDefault(s.PostgresNetBoxPassword, s.PostgresPassword)
	kcUser, kcPass = strDefault(s.PostgresKeycloakUser, "keycloak"), strDefault(s.PostgresKeycloakPassword, s.PostgresPassword)
	return
}

// postgresEnv is the content of the postgres-env Secret.
func (r *renderer) postgresEnv() map[string]string {
	nbDB, nbUser, nbPass, kcDB, kcUser, kcPass := r.postgresLogins()
	env := map[string]string{
		"POSTGRES_NETBOX_DB":         nbDB,
		"POSTGRES_NETBOX_USER":       nbUser,
		"POSTGRES_NETBOX_PASSWORD":   nbPass,
		"POSTGRES_KEYCLOAK_DB":       kcDB,
		"POSTGRES_KEYCLOAK_USER":     kcUser,
		"POSTGRES_KEYCLOAK_PASSWORD": kcPass,
		"POSTGRES_DISABLED":          btoa(!r.postgresEnabled()),
	}
	if ext := r.postgresExternal(); ext != nil {
		port := ext.Port
		if port == 0 {
			port = 5432
		}
		sslMode := strDefault(ext.SSLMode, "prefer")
		env["DB_HOST"] = ext.Host
		env["POSTGRES_HOST"] = ext.Host
		env["PGPORT"] = strconv.Itoa(int(port))
		env["POSTGRES_DB"] = strDefault(ext.MaintenanceDatabase, "postgres")
		// No superuser credentials are handed to NetBox/Keycloak for an external server.
		env["POSTGRES_USER"] = ""
		env["POSTGRES_PASSWORD"] = ""
		env["DB_SSLMODE"] = sslMode // NetBox (Django) connection option
		env["PGSSLMODE"] = sslMode  // libpq: NetBox init and Keycloak readiness checks
		return env
	}
	host := strDefault(r.spec.Postgres.Host, "postgres")
	env["DB_HOST"] = host
	env["POSTGRES_HOST"] = host
	env["PGPORT"] = "5432"
	env["POSTGRES_DB"] = "postgres"
	env["POSTGRES_USER"] = "postgres"
	env["POSTGRES_PASSWORD"] = r.in.Secrets.PostgresPassword
	return env
}

// postgresBootstrapScript creates (or updates the password of) each
// application role and creates its database, mirroring Malcolm's
// postgresql image (postgres-scripts/docker-entrypoint-startdb.d).
const postgresBootstrapScript = `set -euo pipefail
until pg_isready -q; do echo "waiting for PostgreSQL at ${PGHOST}:${PGPORT}..."; sleep 5; done

ensure() {
  local role="$1" password="$2" db="$3"
  echo "ensuring role ${role} and database ${db}"
  psql -X -v ON_ERROR_STOP=1 -v role="${role}" -v pw="${password}" -v db="${db}" <<'SQL'
SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = :'role') AS role_exists \gset
\if :role_exists
  ALTER ROLE :"role" WITH LOGIN PASSWORD :'pw';
\else
  CREATE ROLE :"role" WITH LOGIN PASSWORD :'pw';
\endif
SELECT pg_has_role(current_user, :'role', 'MEMBER') AS is_member \gset
\if :is_member
\else
  GRANT :"role" TO CURRENT_USER;
\endif
SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = :'db') AS db_exists \gset
\if :db_exists
  ALTER DATABASE :"db" OWNER TO :"role";
\else
  CREATE DATABASE :"db" OWNER :"role";
\endif
GRANT ALL PRIVILEGES ON DATABASE :"db" TO :"role";
SQL
  psql -X -v ON_ERROR_STOP=1 -v role="${role}" -d "${db}" <<'SQL'
GRANT ALL PRIVILEGES ON SCHEMA public TO :"role";
SQL
}

[[ "${BOOTSTRAP_NETBOX}" == "true" ]] && ensure "${POSTGRES_NETBOX_USER}" "${POSTGRES_NETBOX_PASSWORD}" "${POSTGRES_NETBOX_DB}"
[[ "${BOOTSTRAP_KEYCLOAK}" == "true" ]] && ensure "${POSTGRES_KEYCLOAK_USER}" "${POSTGRES_KEYCLOAK_PASSWORD}" "${POSTGRES_KEYCLOAK_DB}"
echo "PostgreSQL bootstrap complete"
`

// renderPostgresBootstrap renders the Job that prepares an external server.
func (r *renderer) renderPostgresBootstrap() {
	ext := r.postgresExternal()
	if ext == nil || ext.Bootstrap == nil || ext.Bootstrap.AdminCredentialsSecret == "" {
		return
	}
	netbox := r.netboxMode() == malcolmv1.NetBoxModeLocal
	keycloak := r.keycloakLocal()
	if !netbox && !keycloak {
		return
	}
	env := r.postgresEnv()
	admin := ext.Bootstrap.AdminCredentialsSecret
	c := r.container("postgres-bootstrap", "postgresql")
	c.SecurityContext = nil
	c.TTY = false
	c.Command = []string{"/bin/bash", "-c", postgresBootstrapScript}
	c.EnvFrom = r.envFrom("secret:" + SecretPostgresEnv)
	c.Env = []corev1.EnvVar{
		envVal("PGHOST", env["POSTGRES_HOST"]),
		envVal("PGPORT", env["PGPORT"]),
		envVal("PGDATABASE", env["POSTGRES_DB"]),
		envVal("PGSSLMODE", env["PGSSLMODE"]),
		envSecretKey("PGUSER", admin, "username"),
		envSecretKey("PGPASSWORD", admin, "password"),
		envVal("BOOTSTRAP_NETBOX", btoa(netbox)),
		envVal("BOOTSTRAP_KEYCLOAK", btoa(keycloak)),
	}
	// Re-run when the logins change: the name carries a digest of them.
	h := sha256.New()
	for _, k := range []string{"POSTGRES_HOST", "PGPORT", "POSTGRES_NETBOX_DB", "POSTGRES_NETBOX_USER", "POSTGRES_NETBOX_PASSWORD",
		"POSTGRES_KEYCLOAK_DB", "POSTGRES_KEYCLOAK_USER", "POSTGRES_KEYCLOAK_PASSWORD"} {
		h.Write([]byte(env[k] + "\x00"))
	}
	h.Write([]byte(admin + btoa(netbox) + btoa(keycloak)))
	r.job("postgres-bootstrap", "postgres-bootstrap", hex.EncodeToString(h.Sum(nil))[:10], corev1.PodSpec{Containers: []corev1.Container{c}})
}
