# malcolm-operator Helm chart

Installs the [Malcolm operator](../../README.md): its CRD, RBAC and the controller Deployment. The operator then deploys Malcolm for every `Malcolm` resource you create.

## Install

From the published chart (each `v*` release tag publishes one):

```bash
helm install malcolm-operator oci://ghcr.io/problematiq/charts/malcolm-operator \
  --version <version> --namespace malcolm-operator-system --create-namespace
```

From a checkout:

```bash
helm install malcolm-operator charts/malcolm-operator \
  --namespace malcolm-operator-system --create-namespace
```

The operator's own pod meets the `restricted` Pod Security Standard, so its namespace can enforce it:

```bash
kubectl label namespace malcolm-operator-system pod-security.kubernetes.io/enforce=restricted
```

The namespaces Malcolm runs in need `privileged` instead, for the capture DaemonSets.

## Upgrade and uninstall

`helm upgrade` also upgrades the CRD. Unlike charts that ship their CRD in `crds/`, this chart renders it from `templates/`, so new API fields arrive with the operator that understands them.

`helm uninstall` removes the operator but keeps the CRD (`helm.sh/resource-policy: keep`). It therefore also keeps every `Malcolm` resource and the workloads they own; nothing is reconciled until the operator is reinstalled. To remove everything, first delete the `Malcolm` resources and wait for them to go, then:

```bash
kubectl delete crd malcolms.malcolm.idaholab.github.io
```

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/problematiq/malcolm-operator` | Operator image |
| `image.tag` | chart `appVersion` | Image tag |
| `image.digest` | `""` | Pin by digest (`sha256:...`); overrides `tag` |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | Secrets for a private registry |
| `replicaCount` | `1` | More than one runs hot standbys; leader election is then always on |
| `leaderElection` | `true` | |
| `watchNamespaces` | `[]` (all) | Namespaces the operator manages |
| `crds.install` | `true` | Install and upgrade the CRD with the chart |
| `crds.keep` | `true` | Keep the CRD (and all Malcolm resources) on uninstall |
| `rbac.create` | `true` | Operator ClusterRole/Binding and leader-election Role |
| `rbac.userRoles` | `true` | `malcolm-editor`/`malcolm-viewer` ClusterRoles, aggregated into `admin`/`edit`/`view` |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / `<fullname>-controller-manager` / `{}` | |
| `metrics.enabled` | `true` | Metrics endpoint and the `<fullname>-metrics` Service |
| `metrics.port` | `8443` | |
| `metrics.secure` | `true` | HTTPS with TokenReview/SubjectAccessReview; grant `<fullname>-metrics-reader` to scrapers |
| `healthProbePort` | `8081` | |
| `extraArgs` / `extraEnv` | `[]` | e.g. `--zap-log-level=debug` |
| `resources` | 50m/128Mi requests, 512Mi limit | |
| `podAnnotations`, `podLabels`, `podSecurityContext`, `securityContext` | restricted defaults | |
| `priorityClassName`, `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints` | unset | Scheduling of the operator pod |

With the default release name `malcolm-operator`, the chart creates the same objects with the same names as the kustomize bundle in `config/default`. Switching between the two installation methods therefore takes over the existing objects. The only exception is the metrics Service, named `<fullname>-metrics` here.

`files/crd.yaml` and `files/manager-role.yaml` are generated. `make manifests` copies them from `config/`; do not edit them by hand.
