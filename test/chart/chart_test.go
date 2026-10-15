// Package chart checks the operator's Helm chart with `helm template`.
//
// It runs only when HELM_BIN is set:
//
//	HELM_BIN=$(command -v helm) go test ./test/chart/ -v
package chart

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

var chartDir = filepath.Join("..", "..", "charts", "malcolm-operator")

func render(t *testing.T, args ...string) map[string]*unstructured.Unstructured {
	t.Helper()
	helm := os.Getenv("HELM_BIN")
	if helm == "" {
		t.Skip("HELM_BIN is not set")
	}
	cmd := exec.Command(helm, append([]string{"template", "malcolm-operator", chartDir, "--namespace", "malcolm-operator-system"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, stderr.String())
	}
	objs := map[string]*unstructured.Unstructured{}
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(out)))
	for {
		doc, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return objs
		}
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(doc, &u.Object); err != nil {
			t.Fatal(err)
		}
		if len(u.Object) > 0 {
			objs[u.GetKind()+"/"+u.GetName()] = u
		}
	}
}

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestGeneratedFilesMatch guards against a stale chart: the CRD and operator
// rules must equal what controller-gen wrote to config/.
func TestGeneratedFilesMatch(t *testing.T) {
	objs := render(t)

	crd := objs["CustomResourceDefinition/malcolms.malcolm.idaholab.github.io"]
	want := readYAML(t, filepath.Join("..", "..", "config", "crd", "bases", "malcolm.idaholab.github.io_malcolms.yaml"))
	if crd == nil || !reflect.DeepEqual(crd.Object["spec"], want["spec"]) {
		t.Error("chart CRD differs from config/crd/bases; run `make manifests`")
	}
	if crd.GetAnnotations()["helm.sh/resource-policy"] != "keep" {
		t.Error("the CRD should be kept on uninstall by default")
	}

	role := objs["ClusterRole/malcolm-operator-manager-role"]
	wantRole := readYAML(t, filepath.Join("..", "..", "config", "rbac", "role.yaml"))
	if role == nil || !reflect.DeepEqual(role.Object["rules"], wantRole["rules"]) {
		t.Error("chart manager role differs from config/rbac/role.yaml; run `make manifests`")
	}
}

// TestMatchesKustomizeBundle checks that a release named malcolm-operator
// creates the same objects as config/default, so either install method
// produces the same cluster state.
func TestMatchesKustomizeBundle(t *testing.T) {
	objs := render(t)
	var got []string
	for k := range objs {
		got = append(got, k)
	}
	slices.Sort(got)
	want := []string{
		"ClusterRole/malcolm-operator-malcolm-editor-role",
		"ClusterRole/malcolm-operator-malcolm-viewer-role",
		"ClusterRole/malcolm-operator-manager-role",
		"ClusterRole/malcolm-operator-metrics-auth-role",
		"ClusterRole/malcolm-operator-metrics-reader",
		"ClusterRoleBinding/malcolm-operator-manager-rolebinding",
		"ClusterRoleBinding/malcolm-operator-metrics-auth-rolebinding",
		"CustomResourceDefinition/malcolms.malcolm.idaholab.github.io",
		"Deployment/malcolm-operator-controller-manager",
		"Role/malcolm-operator-leader-election-role",
		"RoleBinding/malcolm-operator-leader-election-rolebinding",
		"Service/malcolm-operator-metrics",
		"ServiceAccount/malcolm-operator-controller-manager",
	}
	if !slices.Equal(got, want) {
		t.Errorf("objects:\n got %v\nwant %v", got, want)
	}
}

func manager(t *testing.T, objs map[string]*unstructured.Unstructured, name string) map[string]any {
	t.Helper()
	d := objs["Deployment/"+name]
	if d == nil {
		t.Fatalf("no Deployment %s", name)
	}
	containers, _, _ := unstructured.NestedSlice(d.Object, "spec", "template", "spec", "containers")
	return containers[0].(map[string]any)
}

func TestValues(t *testing.T) {
	objs := render(t,
		"--set", "image.tag=1.2.3",
		"--set", "watchNamespaces={malcolm,sensors}",
		"--set", "metrics.enabled=false",
		"--set", "leaderElection=false",
		"--set", "crds.install=false",
		"--set", "rbac.userRoles=false",
		"--set", "extraArgs={--zap-log-level=debug}",
	)
	c := manager(t, objs, "malcolm-operator-controller-manager")
	if c["image"] != "ghcr.io/problematiq/malcolm-operator:1.2.3" {
		t.Errorf("image = %v", c["image"])
	}
	args := strings.Join(toStrings(c["args"]), " ")
	if strings.Contains(args, "--leader-elect") || !strings.Contains(args, "--metrics-bind-address=0") || !strings.Contains(args, "--zap-log-level=debug") {
		t.Errorf("args = %s", args)
	}
	env := c["env"].([]any)[0].(map[string]any)
	if env["name"] != "WATCH_NAMESPACES" || env["value"] != "malcolm,sensors" {
		t.Errorf("env = %v", env)
	}
	for k := range objs {
		if strings.HasPrefix(k, "CustomResourceDefinition/") || strings.HasPrefix(k, "Service/") ||
			strings.Contains(k, "metrics") || strings.Contains(k, "editor") || strings.Contains(k, "viewer") {
			t.Errorf("%s should not be rendered", k)
		}
	}

	// Several replicas need leader election even when it was turned off.
	c = manager(t, render(t, "--set", "replicaCount=2", "--set", "leaderElection=false",
		"--set", "image.digest=sha256:abc"), "malcolm-operator-controller-manager")
	if !slices.Contains(toStrings(c["args"]), "--leader-elect") {
		t.Error("replicaCount > 1 must enable leader election")
	}
	if c["image"] != "ghcr.io/problematiq/malcolm-operator@sha256:abc" {
		t.Errorf("digest image = %v", c["image"])
	}

	// Another release name prefixes every name, so releases do not collide.
	objs = render(t, "--set", "fullnameOverride=mo")
	if objs["ClusterRoleBinding/mo-manager-rolebinding"] == nil || objs["Deployment/mo-controller-manager"] == nil {
		t.Error("fullnameOverride is not applied")
	}
}

func toStrings(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}
