// Package crd validates the generated CustomResourceDefinition with the same
// code the Kubernetes API server uses, including compilation of the CEL
// validation rules, and checks those rules against sample resources.
package crd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	apiservervalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	celconfigapi "k8s.io/apiserver/pkg/apis/cel"
	"sigs.k8s.io/yaml"
)

func loadCRD(t *testing.T) *apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "config", "crd", "bases", "malcolm.idaholab.github.io_malcolms.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.UnmarshalStrict(b, crd); err != nil {
		t.Fatal(err)
	}
	return crd
}

func internalCRD(t *testing.T, crd *apiextensionsv1.CustomResourceDefinition) *apiextensions.CustomResourceDefinition {
	t.Helper()
	out := &apiextensions.CustomResourceDefinition{}
	if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(crd, out, nil); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCRDPassesAPIServerValidation(t *testing.T) {
	crd := internalCRD(t, loadCRD(t))
	// storedVersions is set by the API server on creation.
	crd.Status.StoredVersions = []string{"v1alpha1"}
	if errs := validation.ValidateCustomResourceDefinition(context.Background(), crd); len(errs) > 0 {
		for _, e := range errs {
			t.Error(e)
		}
	}
}

func celValidator(t *testing.T) (*cel.Validator, *structuralschema.Structural) {
	t.Helper()
	crd := internalCRD(t, loadCRD(t))
	// The internal form lifts a schema shared by all versions to spec.validation.
	schema := crd.Spec.Validation
	if schema == nil {
		schema = crd.Spec.Versions[0].Schema
	}
	s, err := structuralschema.NewStructural(schema.OpenAPIV3Schema)
	if err != nil {
		t.Fatal(err)
	}
	v := cel.NewValidator(s, true, celconfigapi.PerCallLimit)
	if v == nil {
		t.Fatal("no CEL validator built for the schema")
	}
	return v, s
}

func validate(t *testing.T, doc string) field.ErrorList {
	t.Helper()
	v, s := celValidator(t)
	obj := map[string]any{}
	if err := utilyaml.Unmarshal([]byte(doc), &obj); err != nil {
		t.Fatal(err)
	}
	defaulting.Default(obj, s)
	// OpenAPI checks (patterns, enums, lengths), then the CEL rules.
	crd := internalCRD(t, loadCRD(t))
	schema := crd.Spec.Validation
	if schema == nil {
		schema = crd.Spec.Versions[0].Schema
	}
	sv, _, err := apiservervalidation.NewSchemaValidator(schema.OpenAPIV3Schema)
	if err != nil {
		t.Fatal(err)
	}
	errs := apiservervalidation.ValidateCustomResource(nil, obj, sv)
	celErrs, _ := v.Validate(context.Background(), field.NewPath(""), s, obj, nil, celconfigapi.RuntimeCELCostBudget)
	return append(errs, celErrs...)
}

func TestCELRules(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{"empty spec", `{"spec": {}}`, ""},
		{"netsniff with default tcpdump", `{"spec": {"capture": {"netsniff": true}}}`, "cannot both be enabled"},
		{"netsniff without tcpdump", `{"spec": {"capture": {"netsniff": true, "tcpdump": false}}}`, ""},
		{"remote netbox without url", `{"spec": {"netbox": {"mode": "remote"}}}`, "netbox.url is required"},
		{"remote netbox with url", `{"spec": {"netbox": {"mode": "remote", "url": "https://nb"}}}`, ""},
		{"remote opensearch without url", `{"spec": {"opensearch": {"mode": "opensearch-remote"}}}`, "opensearch.url is required"},
		{"keycloak_remote without url", `{"spec": {"auth": {"mode": "keycloak_remote"}}}`, "keycloak.authURL is required"},
		{"istio without host", `{"spec": {"istio": {"enabled": true}}}`, "istio.host is required"},
		{"unknown config group", `{"spec": {"config": {"zeeek": {"A": "b"}}}}`, "unknown config group"},
		{"known config group", `{"spec": {"config": {"zeek": {"A": "b"}}}}`, ""},
		{"geoip without source", `{"spec": {"maxmind": {"database": {"enabled": true}}}}`, "maxmind.database requires"},
		{"geoip manual files", `{"spec": {"maxmind": {"database": {"enabled": true, "updates": false}}}}`, ""},
		{"geoip with mirror", `{"spec": {"maxmind": {"alternateURL": "https://m", "database": {"enabled": true}}}}`, ""},
		{"external postgres without host", `{"spec": {"postgres": {"mode": "external"}}}`, "postgres.external.host is required"},
		{"unknown component", `{"spec": {"components": {"logstsh": {}}}}`, "unknown component"},
		{"known component", `{"spec": {"components": {"logstash": {"replicas": 2}}}}`, ""},
		{"unknown image override", `{"spec": {"image": {"overrides": {"zeeek": "r/z:1"}}}}`, "unknown Malcolm image"},
		{"known image override", `{"spec": {"image": {"overrides": {"zeek": "r/z:1"}, "tag": "26.10.0"}}}`, ""},
		{"image with whitespace", `{"spec": {"components": {"zeek-offline": {"image": "r/z 1"}}}}`, "spec.components.zeek-offline.image"},
		{"bad tag", `{"spec": {"image": {"tag": "a:b"}}}`, "spec.image.tag"},
		{"component images", `{"spec": {"components": {"arkime": {"image": "r/a:1", "imagePullPolicy": "Always", "containerImages": {"arkime-container": "r/a:2"}}}}}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := validate(t, c.doc)
			if c.wantErr == "" {
				if len(errs) > 0 {
					t.Errorf("unexpected errors: %v", errs)
				}
				return
			}
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.wantErr) {
				t.Errorf("expected %q, got %v", c.wantErr, errs)
			}
		})
	}
}

// TestSamplesAreValid checks every sample Malcolm resource against the schema rules.
func TestSamplesAreValid(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "config", "samples", "malcolm_*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no samples found: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(b), "\n---") {
			if !strings.Contains(doc, "kind: Malcolm") {
				continue
			}
			if errs := validate(t, doc); len(errs) > 0 {
				t.Errorf("%s: %v", filepath.Base(f), errs)
			}
		}
	}
}
