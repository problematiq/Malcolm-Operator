# Malcolm Operator

A Kubernetes operator that deploys and manages [Malcolm](https://github.com/idaholab/Malcolm), the network traffic analysis tool suite, from a single `Malcolm` custom resource.

It deploys the same workloads as the [Malcolm Helm chart](https://github.com/idaholab/Malcolm-Helm), and a parity test checks that against `helm template`. Being an operator, it also keeps managing the deployment after install:

| | Helm chart | Operator |
|---|---|---|
| Internal passwords (Valkey, NetBox, PostgreSQL, Arkime, …) | `pre-install` hook Job running `kubectl` | Generated in-process, stored in a retained Secret, and taken over from an existing Helm install |
| Admin login | You pre-compute `openssl passwd -1` and `htpasswd -B` hashes | You supply a plaintext Secret (or let the operator generate one) and the operator computes both hashes |
| Config changes | `envFrom` changes are not picked up until pods are restarted by hand | Each pod template carries a hash of the ConfigMaps/Secrets it consumes, so only affected pods roll |
| Logstash replicas | `lookup` of node labels at install time (always 1 with `helm template`/Argo CD) | Recomputed as nodes are labeled, added or removed |
| Remote Elasticsearch credentials | Embedded in URLs inside a ConfigMap | Kept only in Secrets |
| Drift | Fixed on the next `helm upgrade` | Server-side apply on every reconcile; objects no longer wanted are pruned |
| Health | `kubectl get pods` | `kubectl get malcolm` shows phase and ready components (`-o wide` adds the URL); conditions per resource |

## Quick start

```bash
# 1. Install the CRD and the operator (the image must be built and pushed first, see "Development").
make deploy IMG=<registry>/malcolm-operator:<tag>

# 2. Create a namespace that allows Malcolm's privileged capture pods.
kubectl create namespace malcolm
kubectl label namespace malcolm pod-security.kubernetes.io/enforce=privileged

# 3. Create a Malcolm.
kubectl apply -f config/samples/malcolm_v1alpha1_malcolm.yaml

# 4. Watch it come up (OpenSearch and Logstash take several minutes).
kubectl -n malcolm get malcolm -w

# 5. Read the generated administrator login.
kubectl -n malcolm get secret malcolm-admin-credentials -o jsonpath='{.data.password}' | base64 -d
```

```
NAME      PROFILE       VERSION   PHASE         READY   AGE
malcolm   development   26.09.0   Progressing   19/27   4m
```

Cluster prerequisites are the same as for the Helm chart:

* A StorageClass that supports `ReadWriteMany` for the shared claims (pcap, zeek, suricata, config, runtime-logs).
* An ingress controller (Traefik by default) or Istio, unless you expose `nginx-proxy` as a `LoadBalancer`.
* Node labels for scheduling: `cnaps.io/node-type=Tier-1` on server nodes (sizes Logstash, and is the usual `placement.server.nodeSelector`), and `cnaps.io/{zeek,suricata,arkime,pcap}-capture=true` / `cnaps.io/zeek-remote-capture=true` on sensor nodes. All label selectors can be changed in the spec.
* Host settings OpenSearch needs (`vm.max_map_count=262144`, memlock/nofile limits), as described in the [Malcolm Kubernetes docs](https://idaholab.github.io/Malcolm/docs/kubernetes.html).

## The `Malcolm` resource

Every field is optional. An empty `spec` gives the same deployment as `helm install` with the chart's default `values.yaml`. Run `kubectl explain malcolm.spec` for the full reference. The main sections:

| Field | Purpose |
|---|---|
| `profile` | `development` (default) or `production`: heap sizes, worker counts, Suricata memcaps, volume sizes (Helm `is_production`) |
| `version`, `image` | Malcolm release used as image tag; registry, tag, pull policy, pull secrets, per-image overrides (see [Custom images](#custom-images)) |
| `auth` | `basic`, `ldap`, `keycloak`, `keycloak_remote` or `no_authentication`; admin credentials; required groups/roles |
| `opensearch` | `opensearch-local` (StatefulSet, 1..n nodes), `opensearch-remote` or `elasticsearch-remote`; secondary store; CA certificate import |
| `placement` | Node selector, tolerations and capture-node avoidance for all central services |
| `storage` | Size, StorageClass, access modes or an `existingClaim` per volume; `retainOnDelete` (default `true`) |
| `capture` | Interfaces, BPF filter, home networks, tolerations, host paths, and the Zeek / Suricata / Arkime / PCAP / remote-sensor DaemonSets with their node selectors |
| `zeek`, `suricata`, `arkime`, `filescan` | Analysis settings, plus ConfigMaps holding custom scripts, rules, YARA, Lua and wise.ini; Arkime's WISE GUI, Parliament and Cont3xt |
| `netbox`, `postgres`, `keycloak` | Embedded vs remote NetBox; local, external or no PostgreSQL; identity provider |
| `maxmind` | GeoIP credentials, and a shared, centrally updated GeoLite2 database volume for Arkime |
| `logstash` | Replicas (or automatic sizing by node label), JVM and pipeline tuning, OTKB enrichment |
| `ingress`, `istio`, `nginx`, `networkPolicy` | How Malcolm is exposed and isolated |
| `indexLifecycle` | ILM/ISM rollover output and index templates (Helm `siem_env.logstash_override`) |
| `config` | Any Malcolm environment variable, keyed by its env file (see below) |
| `components` | Per-workload resources, scheduling, replicas, extra env/volumes, sidecars, init containers, or `enabled: false` |

### `config`: every Malcolm environment variable

Malcolm is configured through environment files (`config/<name>.env` in the Malcolm repository), and its documentation refers to those variable names. `spec.config` sets any of them directly:

```yaml
spec:
  config:
    zeek:                      # config/zeek.env
      ZEEK_DISABLE_ICS_BACNET: "true"
      ZEEK_INTEL_FEED_SINCE: "30 days ago"
    filebeat:                  # config/filebeat.env
      FILEBEAT_SYSLOG_UDP_LISTEN: "true"
      FILEBEAT_SYSLOG_UDP_PORT: "514"
    dashboards-helper:
      OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT: "500G"
```

Supported groups: `arkime`, `arkime-live`, `arkime-offline`, `auth-common`, `beats-common`, `dashboards`, `dashboards-helper`, `filebeat`, `filescan`, `kafka`, `keycloak`, `logstash`, `lookup-common`, `netbox`, `netbox-common`, `nginx`, `opensearch`, `pcap-capture`, `pipeline`, `process`, `ssl`, `suricata`, `suricata-live`, `suricata-offline`, `upload-common`, `zeek`, `zeek-live`, `zeek-offline`.

Values are resolved in this order, and later sources win: built-in defaults (the chart's `values.yaml`), then the `production` profile, then typed spec fields, then `spec.config`. Pods consuming a changed group are restarted automatically.

### `components`: per-workload customization

```yaml
spec:
  components:
    opensearch:
      resources:
        requests: {cpu: "8", memory: 48Gi}
      nodeSelector: {storage: nvme}
    zeek-live-remotesensor:
      containerResources:            # other containers of a multi-container pod
        filebeat-container: {requests: {cpu: 500m}}
    suricata-live:
      sidecars:
        - name: exporter
          image: registry.example.com/suricata-exporter:1.2
    strelka-backend:
      replicas: 3
    freq:
      enabled: false
```

Component names: `api`, `arkime`, `arkime-live`, `cont3xt`, `dashboards`, `dashboards-helper`, `filebeat`, `filebeat-offline`, `filescan`, `freq`, `htadmin`, `keycloak`, `logstash`, `maxmind-geoip` (GeoIP update Jobs), `netbox`, `nginx-proxy`, `opensearch`, `parliament`, `pcap-capture`, `pcap-monitor`, `postgres`, `postgres-bootstrap`, `strelka-backend`, `strelka-frontend`, `strelka-manager`, `suricata-live`, `suricata-offline`, `upload`, `valkey`, `valkey-cache`, `zeek-live`, `zeek-live-remotesensor`, `zeek-offline`. The CRD rejects unknown names and unknown config groups. Sidecars, init containers and extra volumes are decoded strictly, so a misspelled field is reported in the resource's status.

### Custom images

Images are resolved per container. The first setting that applies wins:

1. `components.<name>.containerImages.<container>`: one container, by name. This includes init containers such as `zeek-offline-dirinit-container`.
2. `components.<name>.image`: the main container of one workload.
3. `image.overrides.<image>`: every container that uses that Malcolm image. Keys are image names (`zeek`, `arkime`, `nginx-proxy`, `logstash-oss`, `dirinit`, ...), and unknown keys are rejected.
4. `<image.repository>/<image>:<image.tag>`. The tag defaults to `version`.

```yaml
spec:
  image:
    repository: registry.example.com/malcolm   # mirror of ghcr.io/idaholab/malcolm
    tag: 26.10.0-site1                          # instead of spec.version
    pullSecrets: [{name: registry-creds}]
    overrides:
      nginx-proxy: registry.example.com/malcolm/nginx-proxy:26.10.0-parliament
  components:
    parliament:                                 # only Parliament, not every arkime container
      image: registry.example.com/arkime-parliament:5.8
      imagePullPolicy: Always
    zeek-live:
      containerImages:
        zeek-live-dirinit-container: registry.example.com/malcolm/dirinit:26.10.0
```

`components.<name>.imagePullPolicy` overrides `image.pullPolicy` for that workload's containers. The operator does not change your `sidecars` and `initContainers`. A `containerImages` key that names no container produces a warning in `status.conditions`. Changing an image rolls the affected pods. Custom images must keep the entrypoints, users and paths of the Malcolm image they replace.

### Node placement: capture nodes run only capture DaemonSets

Each capture DaemonSet is placed by its own selector (`capture.zeek.nodeSelector`, `capture.zeek.remoteSensor.nodeSelector`, `capture.suricata.nodeSelector`, `capture.arkime.nodeSelector`, `capture.pcap.nodeSelector`, plus `capture.tolerations`). Everything else (Deployments, StatefulSets and the operator's Jobs) is placed by `placement.server`:

```yaml
spec:
  placement:
    server:
      nodeSelector:
        cnaps.io/node-type: Tier-1
      avoidCaptureNodes: true   # never schedule central services on a capture node
      tolerations: []
```

`avoidCaptureNodes` adds a required node affinity that excludes every node matched by an *enabled* capture selector, even if that node also carries the server label. It is off by default because single-node labs put every label on one node. A component's own `affinity` replaces the rule; its `nodeSelector` and `tolerations` are added to the server ones. For a hard guarantee that nothing else lands on capture nodes, also taint them (for example `cnaps.io/capture=true:NoSchedule`) and add the matching toleration to `capture.tolerations`.

### External OpenSearch

```yaml
spec:
  opensearch:
    mode: opensearch-remote          # or elasticsearch-remote
    url: https://opensearch.example.org:9200
    credentialsSecret: opensearch-credentials   # keys: username, password
    sslCertificateVerification: true
    caCertificate:                   # optional: CA that signed the server certificate
      name: opensearch-ca
      namespace: security            # any namespace; copied into Malcolm's
```

No OpenSearch StatefulSet is deployed. Malcolm's OpenSearch Dashboards still runs and connects to the remote cluster; with `elasticsearch-remote` it is skipped and `dashboardsURL`/`externalDashboardsURL` point at your Kibana. The CA certificate is added to every Malcolm container's trust store, so verified TLS works for Logstash, Filebeat, Arkime, the API and Dashboards alike. Credentials are kept in Secrets only. A complete example is in `config/samples/malcolm_external_services.yaml`.

### External PostgreSQL

NetBox and Keycloak (when embedded) need PostgreSQL. To use an existing server:

```yaml
spec:
  postgres:
    mode: external
    external:
      host: postgres.example.org
      port: 5432
      sslMode: require               # libpq sslmode for NetBox and readiness checks
      netbox:
        database: netbox
        credentialsSecret: netbox-db     # keys: username, password
      keycloak:
        database: keycloak
        credentialsSecret: keycloak-db
      bootstrap:                     # optional
        adminCredentialsSecret: postgres-admin
```

* Without `bootstrap`, the roles and databases must already exist, and each application in use needs its `credentialsSecret`.
* With `bootstrap`, a Job (`postgres-bootstrap-<digest>`) logs in with the admin credentials. It creates any missing role and database, sets the role's password, and grants it ownership, as Malcolm's own PostgreSQL image does. It runs again whenever a login changes. Applications without a `credentialsSecret` then get the role `netbox`/`keycloak` with a generated password.
* The admin credentials go only to the bootstrap Job, never to NetBox or Keycloak.
* Keycloak builds its own JDBC URL, so `sslMode` does not reach it. The PostgreSQL JDBC driver defaults to `prefer`: it uses TLS when the server offers it, without verifying the certificate.

`mode: disabled` runs no PostgreSQL (with NetBox `remote`/`disabled` and Keycloak unused). The older `postgres.enabled: false` means the same.

### Shared MaxMind GeoIP database

```yaml
spec:
  maxmind:
    credentialsSecret: maxmind       # keys: accountID, licenseKey  (or alternateURL for a mirror)
    database:
      enabled: true
      updateSchedule: "0 4 * * 3,6"  # MaxMind publishes on Tuesdays and Fridays
      storage:
        size: 1Gi
        storageClassName: nfs-client # must be ReadWriteMany and reachable from capture nodes
      rolloutOnUpdate: true
```

The operator creates a ReadWriteMany claim, `geoip-claim`, and two downloaders that write `GeoLite2-{ASN,Country,City}.mmdb` to it: a Job that fills it right away, and the CronJob `maxmind-geoip-update` that keeps it current. Both use Malcolm's own download script, run on server nodes (see placement), and replace files atomically. The claim is mounted read-only into Arkime and into every `arkime-live` capture pod, at `/opt/arkime/etc/configmap`, which Malcolm's start-up copies into place. The pods' own Internet download is turned off, so capture nodes need no outbound access for GeoIP.

Arkime loads the databases when it starts. With `rolloutOnUpdate` (the default), a successful update restarts the Arkime pods (capture pods one node at a time). `status.geoIPUpdated` shows the time of the last update. Set `rolloutOnUpdate: false` to pick up new databases only on the next restart. On an isolated network, either set `alternateURL` to an internal mirror of the MaxMind tarballs, or set `updates: false` and put the `.mmdb` files on the volume yourself (`storage.existingClaim` can point at a pre-filled claim). After a manual update, restart the Arkime pods.

If `networkPolicy.enabled` is set, add `additionalEgress` rules for the external OpenSearch and PostgreSQL servers and for MaxMind (or your mirror).

### WISE, Parliament and Cont3xt

All three are Arkime web applications served under Malcolm's nginx proxy, behind Malcolm's login, with no landing-page buttons.

| | Path | Runs in | Setting |
|---|---|---|---|
| WISE | `/wise/` | the `arkime` pod (port 8081) | `arkime.exposeWiseGUI` (default `true`), `arkime.allowWiseGUIConfig` (editable, PIN-protected) |
| Parliament | `/parliament/` | Deployment `parliament-deployment`, Service `parliament:8008` | `arkime.parliament.enabled` |
| Cont3xt | `/cont3xt/` | Deployment `cont3xt-deployment`, Service `cont3xt:3218` | `arkime.cont3xt.enabled` |

```yaml
spec:
  arkime:
    parliament:
      enabled: true
    cont3xt:
      enabled: true
```

* Parliament and Cont3xt run from Malcolm's `arkime` image (Arkime ships both), as the unprivileged Malcolm user, on server nodes.
* At start-up each writes its configuration from Malcolm's own settings, so it shares Arkime's view of users and data:
  * the same OpenSearch (or remote store) and credentials file
  * the same `passwordSecret`
  * header authentication from nginx's `X-Forwarded-User`
  * the viewer's user auto-create template
* Roles follow Malcolm's role-based-access setting: with `auth.roleBasedAccess` off, every Malcolm user may use and administer them. With it on, administration requires Malcolm's `ROLE_ARKIME_ADMIN` role (`parliamentAdmin`/`cont3xtAdmin`). Every user gets `parliamentUser`/`cont3xtUser`.
* Parliament starts with a "Malcolm" group holding this instance's Arkime (`http://arkime:8005/arkime`), added only if Parliament has no groups. Further clusters, such as other Malcolm instances, are added in Parliament's settings. Its issues list is kept on `config-claim`.
* Malcolm's stock nginx image routes neither application. Add the `/parliament/` location from [docs/nginx-parliament.conf](docs/nginx-parliament.conf) to your nginx image, and route `/cont3xt/` to `cont3xt:3218`. Cont3xt strips its own `webBasePath`, so the path can be passed through unchanged. nginx resolves these upstream names when it starts, so enable the applications before deploying an nginx image that references them. Point `image.overrides.nginx-proxy` at your image.

### Credentials

| Secret | Contents | Lifecycle |
|---|---|---|
| `<name>-admin-credentials` | `username`/`password` for the Malcolm web UI, generated when `auth.adminSecret` and `auth.hashedCredentials` are unset | Retained |
| `<name>-generated` | Generated internal passwords and the admin password hashes | Retained |
| `auth.adminSecret` (yours) | Plaintext `username`/`password`; the operator derives MD5-crypt and bcrypt hashes and re-hashes when it changes | Yours |
| `auth.hashedCredentials` (yours) | A Helm-style `auth.existingSecret` with pre-hashed values | Yours |

Other secrets are referenced as `{name, key}` pairs: `postgres.passwordSecret`, `arkime.passwordSecret`, `arkime.wisePINSecret`, `netbox.tokenSecret`, `keycloak.clientSecret`, `keycloak.bootstrapAdminSecret`, `maxmind.credentialsSecret`, `logstash.otkb.tokenSecret`, `opensearch.credentialsSecret`, `filescan.httpServerKeySecret`, and `auth.ldapConfigSecret`. Edits to any of them are picked up and the consuming pods roll.

"Retained" objects have no owner reference, so deleting the `Malcolm` resource keeps them. A re-created instance then reuses the same volumes and passwords. Set `storage.retainOnDelete: false` to have PVCs, StatefulSet claims and generated credentials deleted with the resource.

### Status

```bash
kubectl -n malcolm get malcolm malcolm -o yaml
```

`status.phase` is `Progressing`, `Ready`, `Degraded` (some objects failed to apply) or `Error` (for example a referenced Secret is missing, or another `Malcolm` already owns the namespace). `status.components` lists each workload with its desired and available pods. `status.conditions` holds `Ready`, `Progressing`, `Degraded` and `ConfigurationWarning`.

### Upgrading Malcolm

Change `spec.version` (or upgrade the operator, whose built-in default tracks a Malcolm release). Images are retagged and pods roll. Before upgrading, read the Malcolm release notes for new or renamed environment variables. New variables can be set through `spec.config` without waiting for an operator release.

## Design notes

* **One Malcolm per namespace.** Malcolm's containers address each other by fixed service names (`opensearch`, `logstash:5044`, `strelka-frontend`, …), so object names are fixed as in the Helm chart. The oldest `Malcolm` in a namespace wins; any later one reports `DuplicateInstance`. To run several instances, use separate namespaces and distinct capture node labels and host paths (see the chart's *Multiple Malcolms Cohabitating* notes).
* **Helm-compatible object names and selectors.** Deployments, Services and PVCs keep the chart's names and `name=<workload>` pod selectors. That allows an in-place takeover of an existing Helm release (see [docs/helm-migration.md](docs/helm-migration.md)).
* **Server-side apply** with field manager `malcolm-operator`. Immutable fields of existing PVCs and StatefulSet claim templates are preserved. A larger `size` is applied only to a bound claim whose StorageClass allows expansion. Shrinking, unbound claims, and claim-template changes are reported as a `ConfigurationWarning` and do not fail reconciliation.
* **Pruning** deletes only objects that carry this instance's labels *and* a controller reference to it, so PVCs, retained Secrets and anything you created are left alone.
* `internal/render` is a pure function from the spec (plus a few resolved values) to objects. It holds the Helm-equivalent logic and is what the unit and parity tests exercise.

## Development

```bash
make test           # regenerate CRD/RBAC/deepcopy, fmt, vet, unit tests
make build          # bin/manager
make run            # run against the current kubeconfig
make docker-build docker-push IMG=...
make build-installer IMG=...   # dist/install.yaml
```

Test suites:

* `internal/render`: rendered objects per configuration. Every volume mount and ConfigMap/Secret reference resolves, every Service selects a workload, env values match the chart for both profiles, and override precedence holds.
* `internal/controller`: reconciles against controller-runtime's fake client (server-side apply). Covers secret generation and stability, adoption of Helm-generated passwords, admin re-hashing, missing inputs, the single-instance rule, pruning, Logstash node-label sizing, and PVC immutability.
* `internal/credentials`: MD5-crypt checked against `openssl passwd -1` vectors, and bcrypt checked against the chart's `htpasswd` hash.
* `test/crd`: the generated CRD validated with the API server's own validation, the behaviour of each CEL rule, and every sample.
* `test/envtest` (`make test-envtest`): runs against a real kube-apiserver and etcd (no kubelet).
  * Five configurations must be accepted by API-server validation and reconcile idempotently.
  * Covers CEL enforcement, spec updates with pruning and scoped rollouts, blocked resizes, and taking over Helm-created objects.
  * Runs the real manager (watches, caches, predicates) through node labeling, admin password edits, drift correction and the transition to `Ready`.
  * Applies the kustomize install bundle and runs the manager impersonating the operator's ServiceAccount, so missing RBAC fails the test.
* `test/parity` (`make test-parity`): diffs the operator against `helm template` of the chart in 12 scenarios (profiles, Keycloak, pre-hashed auth, ILM, PCAP capture, Istio, NetBox disabled, multi-node OpenSearch, sidecars/coverage, …). Intentional differences are listed in the test with reasons. One of them is a chart bug: in production, `SURICATA_AF_PACKET_BLOCK_SIZE` renders as `1.048576e+06`.

Integration suites skip themselves when their tools (`KUBEBUILDER_ASSETS`, or `HELM_BIN` plus `HELM_CHART`) are not configured.

## License

Malcolm and the Malcolm Helm chart are licensed under the Apache License 2.0. See [NOTICE](NOTICE) for the files derived from them.
