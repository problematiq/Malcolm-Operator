# Migrating from the Malcolm Helm chart

## Mapping `values.yaml` to the `Malcolm` spec

Development/production pairs in `values.yaml` (`foo.development.x` / `foo.production.x`) become a single field. Its default depends on `spec.profile`. "config[g].VAR" means `spec.config.<g>.<VAR>`, i.e. the Malcolm environment variable of that name.

| Helm value | Malcolm spec |
|---|---|
| `is_production` | `profile: production` |
| `enable_network_policies`, `cluster.node_cidr` | `networkPolicy.enabled`, `networkPolicy.nodeCIDR` |
| `node_count_label.{key,value}` | `logstash.nodeCountLabel.{key,value}` |
| `ca_trust_configmap_name` | `caTrustConfigMap` |
| `storage_class_name` | `storage.storageClassName` |
| `storage.*.<claim>.size` / `.classNameOverride` | `storage.<pcap\|zeek\|suricata\|config\|runtimeLogs\|opensearch\|opensearchBackup\|postgres>.size` / `.storageClassName` |
| `image.repository`, `image.pullPolicy` | `image.repository`, `image.pullPolicy` |
| `image.<name>_container_override` | `image.overrides.<image name>` (e.g. `zeek`, `logstash-oss`, `nginx-proxy`), or `components.<workload>.image` / `.containerImages.<container>` for a single workload |
| `secret_init.*` | not needed (the operator generates secrets itself) |
| `auth.username`, `auth.openssl_password`, `auth.htpass_cred` | `auth.adminSecret` (plaintext `username`/`password`; hashes are derived) |
| `auth.existingSecret`, `usernameKey`, `opensslPassKey`, `htpassCredKey` | `auth.hashedCredentials.{secretName,usernameKey,opensslPasswordKey,htpasswdKey}` |
| `auth.mode`, `require_group`, `require_role`, `role_based_access` | `auth.mode`, `auth.requireGroups`, `auth.requireRoles`, `auth.roleBasedAccess` |
| `auth.role_*` | `config["auth-common"].ROLE_*` |
| `auth.arkime_password` | `arkime.passwordSecret` |
| `auth.arkime_wise_pin`, `auth.arkime_wise_service_url` | `arkime.wisePINSecret`, `arkime.wiseServiceURL` |
| `opensearch.enabled: true` | `opensearch.mode: opensearch-local` (default) |
| `opensearch.url`, `ssl_certificate_verification`, `dashboards_url` | `opensearch.url`, `opensearch.sslCertificateVerification`, `opensearch.dashboardsURL` |
| `opensearch.max_locked_memory` | `opensearch.local.maxLockedMemory` |
| `opensearch.*.java_memory`, `cluster_max_shards_per_node` | `opensearch.local.javaMemory`, `opensearch.local.maxShardsPerNode` |
| `opensearch.singleNode`, `replicas` | `opensearch.local.replicas` (1 = single node) |
| `opensearch.defaultReplicaCount`, `existingCASecretName` | `opensearch.local.defaultReplicaCount`, `opensearch.local.transportCASecret` |
| `opensearch.secondary`, `secondary_url`, `secondary_ssl_certificate_verification` | `opensearch.secondary.{mode,url,sslCertificateVerification,credentialsSecret}` |
| `external_elasticsearch.enabled` | `opensearch.mode: elasticsearch-remote` |
| `external_elasticsearch.url`, `dashboards_url`, `external_dashboards_url` | `opensearch.url`, `opensearch.dashboardsURL`, `opensearch.externalDashboardsURL` |
| `external_elasticsearch.username`/`password`/`elastic_secret_name` | `opensearch.credentialsSecret` (keys `username`, `password`) |
| `external_elasticsearch.elastic_cert_name`/`elastic_cert_namespace` | `opensearch.caCertificate.{name,namespace}` |
| `external_elasticsearch.matchLabels`, `es_port`, `kibana_port`, `namespace` | `networkPolicy.additionalEgress` (see `config/samples/malcolm_remote_elasticsearch.yaml`) |
| `siem_env.logstash_override.enabled` and its keys | `indexLifecycle: {...}` (present = enabled) |
| `siem_env.malcolm_*`, `siem_env.arkime_*` index settings | `config["opensearch"].MALCOLM_NETWORK_INDEX_PATTERN`, etc. |
| `beats_common.ssl` | `config["beats-common"].BEATS_SSL` |
| `lookup_common.sensitive_country_codes` | `lookup.sensitiveCountryCodes` |
| `lookup_common.*` (others) | `config["lookup-common"].FREQ_LOOKUP`, etc. |
| `logstash.oui_lookup`, `reverse_dns`, `severity_scoring` | `config["logstash"].LOGSTASH_OUI_LOOKUP`, etc. |
| `logstash.otkb.{enrichment,url,token}` | `logstash.otkb.{enabled,url,tokenSecret}` |
| `logstash.otkb.*` (others) | `config["logstash"].OTKB_*` |
| `logstash.*.{java_memory,workers,batch_delay,batch_size}` | `logstash.{javaMemory,workers,batchDelay,batchSize}` |
| `logstash.*.ordered` | `config["logstash"]["pipeline.ordered"]` |
| (Logstash replica count) | `logstash.replicas`, or unset for automatic sizing |
| `netbox.mode`, `url`, `netbox_remote_token` | `netbox.mode`, `netbox.url`, `netbox.tokenSecret` |
| `netbox.enrichment`, `logstash_netbox_enrichment_datasets`, `netbox_default_site`, `netbox_auto_populate`, `netbox_auto_populate_subnets`, `csrf_trusted_origins` | `netbox.enrichment`, `enrichmentDatasets`, `defaultSite`, `autoPopulate`, `autoPopulateSubnets`, `csrfTrustedOrigins` |
| `netbox.netbox_auto_create_prefix`, `*_lookup_service`, `*_autocreate_manufacturer`, `*_fuzzy_threshold`, `netbox_cache_*` | `config["netbox-common"].NETBOX_*` |
| `netbox.email_*`, `webhooks_enabled`, `redis_*` | `config["netbox"].EMAIL_*`, `WEBHOOKS_ENABLED`, `REDIS_*` |
| `postgres.enabled`, `host`, `netbox_db_name`, `keycloak_db_name` | `postgres.mode` (`local`/`external`/`disabled`), `host`, `netboxDatabase`, `keycloakDatabase`; an existing server goes under `postgres.external` |
| `postgres.password` | `postgres.passwordSecret` |
| `postgres.is_custom`, `extra_secrets` | `postgres.extraSecrets: [{name, data}]` |
| `ingress.enabled`, `className`, `nginxProxyBufferBypass`, `additionalAnnotations` | `ingress.enabled`, `className`, `nginxProxyBufferBypass`, `annotations` |
| `ingress.specRules`, `specTls` | `ingress.host` + `ingress.tlsSecretName`, or `ingress.rules` / `ingress.tls` |
| `istio.enabled`, `gateway`, `istio_namespace` | `istio.enabled`, `istio.gateway`, `istio.namespace` |
| `istio.virtualservicename` + `istio.domain` | `istio.host` (e.g. `malcolm.vp.bigbang.dev`) |
| `suricata_env.custom_rules_only`, `update_rules`, `update_enable_sources`, `disable_sids` | `suricata.customRulesOnly`, `updateRules`, `enableSources`, `disableSIDs` |
| `suricata_env.*` (others, incl. memcaps) | `config["suricata"].SURICATA_*` |
| `suricata_live.nodeSelector`, `hostpath` | `capture.suricata.nodeSelector`, `capture.hostPaths.suricataLogs` |
| `suricata_live.*` (runmode, stats, af-packet tuning) | `config["suricata-live"].SURICATA_*` |
| `suricata_offline.auto_analyze_pcap_files` | `suricata.autoAnalyzeUploads` |
| `suricata_offline.*` (threads, processes) | `config["suricata-offline"].SURICATA_AUTO_ANALYZE_PCAP_*` |
| `dashboards_helper_env.*` | `config["dashboards-helper"].*` (`MALCOLM_URL` defaults to the ingress/Istio URL) |
| `zeek_env.extract_mode` | `zeek.extractMode` |
| `zeek_env.*` (others) | `config["zeek"].ZEEK_*` / `EXTRACTED_FILE_MAX_BYTES` |
| `zeek_live.nodeSelector`, `remoteNodeSelector` | `capture.zeek.nodeSelector`, `capture.zeek.remoteSensor.nodeSelector` |
| `zeek_live.hostpath.{logs,extracted}` | `capture.hostPaths.{zeekLogs,zeekExtractedFiles}` |
| `zeek_live.extra_env`, `extra_envFrom` | `components["zeek-live"]` and `components["zeek-live-remotesensor"]` `.extraEnv` / `.extraEnvFrom` |
| `zeek_live.*` (stats, intel, ZAM, load balancing) | `config["zeek-live"].ZEEK_*` |
| `zeek_offline.auto_analyze_pcap_files` | `zeek.autoAnalyzeUploads` |
| `zeek_offline.*` (others) | `config["zeek-offline"].ZEEK_*` |
| `filescan_env.disable`, `scanners` | `filescan.disabled`, `filescan.scanners` |
| `filescan_env.extracted_file_http_server_encrypt_password` | `filescan.httpServerKeySecret` |
| `filescan_env.*.remote` | `filescan.remoteSensorHTTPServer`, `filescan.remoteSensorPreservation` |
| `filescan_env.*.local` and HTTP server/prune settings | `config["filescan"].FILESCAN_*` |
| `filescan_env.rules_update_enabled`, `yara_custom_rules_only`, `clamd_*`, `backend_procs` | `config["pipeline"].RULES_UPDATE_ENABLED`, …, `STRELKA_BACKEND_PROCS` |
| `filescan_env.hostpath` | `capture.hostPaths.filescanLogs` |
| `valkey_env.ports`, `hostpath` | `valkey.ports`, `capture.hostPaths.valkeyAOF` |
| `valkey_env.*.{max_memory,max_memory_policy,cache_*,auto_aof_rewrite_min_size}` | `valkey.{maxMemory,maxMemoryPolicy,cacheMaxMemory,cacheMaxMemoryPolicy,autoAOFRewriteMinSize}` |
| `maxmind.account_id`, `license_key` | `maxmind.credentialsSecret` (keys `accountID`, `licenseKey`) |
| `maxmind.alternate_url` | `maxmind.alternateURL` |
| (none) | `maxmind.database`: shared GeoIP volume for Arkime, updated by a CronJob |
| (none: each workload's own `nodeSelector`) | `placement.server.nodeSelector`, `.tolerations`, `.avoidCaptureNodes` |
| `arkime_env.*.arkime_init_*` | `config["opensearch"].ARKIME_INIT_*` |
| `arkime_env.*` (others) | `config["arkime"].*` |
| `arkime_live.enabled`, `nodeSelector`, `hostpath`, `arkime_live_node_host` | `capture.arkime.enabled`, `capture.arkime.nodeSelector`, `capture.hostPaths.arkimePCAP`, `capture.arkime.nodeHost` |
| `arkime_live.*` (magic mode, read/write methods, tuning) | `config["arkime-live"].ARKIME_*` |
| `arkime_offline.auto_analyze_pcap_files` | `arkime.autoAnalyzeUploads` |
| `arkime_offline.*` (others) | `config["arkime-offline"].ARKIME_*` |
| `pcap_live.enabled`, `nodeSelector` | `capture.pcap.enabled`, `capture.pcap.nodeSelector` |
| `pcap_capture_env.*` | `capture.{interfaces,filter,netsniff,tcpdump,rotateMegabytes,rotateMinutes,homeNet,interfaceTweak,statsCronExpression}` |
| `live_capture.tolerations` | `capture.tolerations` |
| `upload_common_env.extra_tags`, `pcap_upload_max_file_gb` | `upload.extraTags`, `upload.maxFileGB` |
| `upload_common_env.*` (others) | `config["upload-common"].*` |
| `filebeat.daemonsetNodeAffinity` | `filebeat.daemonSetNodeAffinity` (by default derived from the capture node selectors) |
| `filebeat.*` (others) | `config["filebeat"].FILEBEAT_*` |
| `process_env.{puid,pgid,tini_verbosity}` | `process.{puid,pgid,tiniVerbosity}` |
| `rule_mount_override.enabled` | `suricata.configsConfigMap` / `suricata.rulesConfigMap` pointing at your ConfigMaps |
| `zeek_chart_overrides.serviceAccountName`, `sideCars`, `extra_init_containers` | `components["zeek-offline"\|"zeek-live"\|"zeek-live-remotesensor"].serviceAccountName`, `.sidecars`, `.initContainers` |
| `zeek_chart_overrides.*_volumes`, `*_volumeMounts` | `zeek.customConfigMap`, or `components[...].extraVolumes` / `.extraVolumeMounts` |
| `suricata_chart_overrides.*` | `components["suricata-offline"\|"suricata-live"].*`, `suricata.rulesConfigMap`, `suricata.configsConfigMap` |
| `kafka.{enabled,brokers,topic}` | `kafka.{enabled,brokers,topic}` |
| `keycloak.keycloak_*` | `keycloak.{authRealm,authRedirectURI,authURL,clientID,clientSecret,sslVerify}` |
| `keycloak.kc_hostname`, `kc_bootstrap_admin_*` | `keycloak.hostname`, `keycloak.bootstrapAdminSecret` (generated when unset) |
| `keycloak.kc_*` (others) | `config["keycloak"].KC_*` |
| `nginx.type`, `x_forwarded_proto_override`, `csp_form_action_extra` | `nginx.serviceType`, `nginx.xForwardedProtoOverride`, `nginx.cspFormActionExtra` |
| `nginx.*` (log level, LDAP stunnel, resolver) | `config["nginx"].NGINX_*` |
| `enable_coverage`, `coveragerc` | `coverage.enabled`, `coverage.rc` |

Defaults that differ from the chart:

* The admin login is generated (`<name>-admin-credentials`) instead of defaulting to `malcolm`/`malcolm`.
* The embedded Keycloak bootstrap administrator gets a generated password instead of `vagrant`/`vagrant`.
* `CSRF_TRUSTED_ORIGINS` and `MALCOLM_URL` follow the ingress/Istio host when one is set. Without a host, CSRF accepts any origin rather than the chart's placeholder `https://malcolm.vp.bigbang.dev`.
* Remote data-store credentials are kept out of ConfigMaps.

## Taking over an existing Helm release in place

The operator uses the chart's object names and pod selectors, so it can adopt a running release without moving data.

1. Install the operator (`make deploy IMG=...`).
2. Write a `Malcolm` resource equivalent to your values (table above). Use the Helm release's namespace, and keep volume sizes at least as large as the existing claims. If you used `auth.existingSecret`, set `auth.hashedCredentials`.
3. Make Helm forget the release *without* deleting its objects by removing only Helm's release records:

   ```bash
   kubectl -n malcolm get secret -l owner=helm,name=<release>
   kubectl -n malcolm delete secret -l owner=helm,name=<release>
   ```

4. Apply the `Malcolm` resource. The operator then:
   * Copies the passwords from the chart's `valkey-env`, `valkey-remotesensor-env`, `netbox-secret-env`, `postgres-env`, `arkime-secret-env`, `filescan-secret-env` and `keycloak-env` Secrets into `<name>-generated`, so databases and sessions keep working.
   * Takes over every same-named object with server-side apply and adds owner references.
   * Reuses `pcap-claim`, `zeek-claim`, …, and the StatefulSet claims (`opensearch-claim-opensearch-0`, `postgres-claim-postgres-statefulset-0`) as they are.
   * Rolls each pod once, because the pod templates gain the operator's labels and config-hash annotation.
5. Delete any chart objects whose names the operator does not use, such as `coverage-config-<release>` or an ingress from a previous `className`. The operator never deletes objects it does not own.

Alternatively, `helm uninstall` the release and create the `Malcolm` resource afterwards. The StatefulSet claims and the chart's generated Secrets survive an uninstall. Annotate the five shared PVCs with `helm.sh/resource-policy=keep` first, or they will be deleted.
