package render

import (
	"encoding/json"
	"fmt"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

var ecsNetworkComponents = []string{
	"ecs_base", "ecs_ecs", "ecs_event", "ecs_agent", "ecs_client", "ecs_destination", "ecs_error",
	"ecs_file", "ecs_host", "ecs_http", "ecs_log", "ecs_network", "ecs_process", "ecs_related",
	"ecs_rule", "ecs_server", "ecs_source", "ecs_threat", "ecs_url", "ecs_vulnerability",
	"ecs_user_agent", "custom_arkime", "custom_suricata", "custom_zeek", "custom_zeek_ot",
	"custom_malcolm_common",
}

var ecsBeatsComponents = []string{
	"ecs_base", "ecs_ecs", "ecs_event", "ecs_agent", "ecs_client", "ecs_destination", "ecs_error",
	"ecs_file", "ecs_host", "ecs_http", "ecs_log", "ecs_network", "ecs_process", "ecs_related",
	"ecs_server", "ecs_source", "ecs_threat", "ecs_url", "ecs_user", "ecs_user_agent",
	"custom_miscbeat", "custom_suricata_stats", "custom_winlog", "custom_zeek_diagnostic",
}

type ilmSettings struct {
	policy, zeek, suricata, beats, beatsPipeline, beatsPolicy, searchAlias, shards, replicas string
}

func ilmFromSpec(il *malcolmv1.IndexLifecycleSpec) ilmSettings {
	return ilmSettings{
		policy:        strDefault(il.ILMPolicy, "nta"),
		zeek:          strDefault(il.RolloverAliasZeek, "malcolm_network_zeek"),
		suricata:      strDefault(il.RolloverAliasSuricata, "malcolm_network_suricata"),
		beats:         strDefault(il.RolloverAliasBeats, "malcolm_beats"),
		beatsPipeline: strDefault(il.DefaultBeatsPipeline, "sensor-status"),
		beatsPolicy:   strDefault(il.ILMBeatsPolicy, "logs"),
		searchAlias:   strDefault(il.SearchAlias, "malcolm_network"),
		shards:        strDefault(il.NumberOfShards, "2"),
		replicas:      strDefault(il.NumberOfReplicas, "1"),
	}
}

func ecsTemplate(rolloverAlias string, s ilmSettings) string {
	t := map[string]any{
		"index_patterns": []string{rolloverAlias + "-*"},
		"composed_of":    ecsNetworkComponents,
		"template": map[string]any{
			"aliases": map[string]any{s.searchAlias: map[string]any{}},
			"settings": map[string]any{
				"index": map[string]any{
					"lifecycle.name":              s.policy,
					"lifecycle.rollover_alias":    rolloverAlias,
					"mapping.total_fields.limit":  "6000",
					"mapping.nested_fields.limit": "250",
					"max_docvalue_fields_search":  "200",
					"number_of_shards":            s.shards,
					"number_of_replicas":          s.replicas,
				},
			},
		},
	}
	b, _ := json.MarshalIndent(t, "", "  ")
	return string(b) + "\n"
}

func beatsTemplate(s ilmSettings) string {
	t := map[string]any{
		"index_patterns": []string{s.beats + "-*"},
		"composed_of":    ecsBeatsComponents,
		"template": map[string]any{
			"settings": map[string]any{
				"index": map[string]any{
					"lifecycle.name":              s.beatsPolicy,
					"lifecycle.rollover_alias":    s.beats,
					"mapping.total_fields.limit":  "6000",
					"mapping.nested_fields.limit": "250",
					"max_docvalue_fields_search":  "200",
					"default_pipeline":            s.beatsPipeline,
				},
			},
			"mappings": map[string]any{
				"properties": map[string]any{
					"timestamp":    map[string]string{"type": "date"},
					"node":         map[string]string{"type": "keyword"},
					"event.result": map[string]string{"type": "keyword"},
					"os.family":    map[string]string{"type": "keyword"},
					"os.type":      map[string]string{"type": "keyword"},
				},
			},
		},
	}
	b, _ := json.MarshalIndent(t, "", "  ")
	return string(b) + "\n"
}

const ilmOutputTemplate = `output {
  if [event][kind] == "metric" {
    elasticsearch {
      id => "output_opensearch_malcolm_metrics"
      hosts => "${OPENSEARCH_URL:https://opensearch:9200}"
      ssl_verification_mode => "none"
      manage_template => false
      document_id => "%%{+YYMMdd}-%%{[event][hash]}"
      ilm_rollover_alias => "%[1]s"
      ilm_pattern => "000001"
      ilm_policy => "%[2]s"
    }
  } else if [event][provider] == "suricata" {
    elasticsearch {
      id => "output_opensearch_malcolm_suricata"
      hosts => "${OPENSEARCH_URL:https://opensearch:9200}"
      ssl_verification_mode => "none"
      manage_template => false
      document_id => "%%{+YYMMdd}-%%{[event][hash]}"
      ilm_rollover_alias => "%[3]s"
      ilm_pattern => "000001"
      ilm_policy => "%[4]s"
    }
  } else {
    elasticsearch {
      id => "output_opensearch_malcolm_zeek"
      hosts => "${OPENSEARCH_URL:https://opensearch:9200}"
      ssl_verification_mode => "none"
      manage_template => false
      document_id => "%%{+YYMMdd}-%%{[event][hash]}"
      ilm_rollover_alias => "%[5]s"
      ilm_pattern => "000001"
      ilm_policy => "%[4]s"
    }
  }
}
`

func (r *renderer) renderIndexLifecycle(il *malcolmv1.IndexLifecycleSpec) {
	s := ilmFromSpec(il)
	r.add(r.configMap("elastic-output-override", "logstash", map[string]string{
		"99_opensearch_output.conf": fmt.Sprintf(ilmOutputTemplate, s.beats, s.beatsPolicy, s.suricata, s.policy, s.zeek),
	}))
	r.add(r.configMap("malcolm-template-override", "dashboards-helper", map[string]string{
		"malcolm_template.json":          ecsTemplate(s.zeek, s),
		"malcolm_template_suricata.json": ecsTemplate(s.suricata, s),
		"malcolm_beats_template.json":    beatsTemplate(s),
	}))
}
