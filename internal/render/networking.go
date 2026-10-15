package render

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// VirtualServiceAPIVersion is the Istio API version used for VirtualServices.
const VirtualServiceAPIVersion = "networking.istio.io/v1beta1"

func (r *renderer) renderNetworking() {
	r.renderIngress()
	r.renderIstio()
	if r.spec.NetworkPolicy.Enabled {
		r.renderNetworkPolicies()
	}
}

func (r *renderer) renderIngress() {
	ing := r.spec.Ingress
	if !boolDefault(ing.Enabled, true) {
		return
	}
	className := "traefik"
	if ing.ClassName != nil {
		className = *ing.ClassName
	}
	annotations := map[string]string{}
	switch className {
	case "traefik":
		annotations["traefik.ingress.kubernetes.io/service.serversscheme"] = "http"
	case "nginx":
		annotations["nginx.ingress.kubernetes.io/backend-protocol"] = "http"
		annotations["nginx.ingress.kubernetes.io/preserve-trailing-slash"] = "false"
		annotations["nginx.ingress.kubernetes.io/ssl-passthrough"] = "false"
		annotations["nginx.ingress.kubernetes.io/client-body-buffer-size"] = "512k"
		if boolDefault(ing.NginxProxyBufferBypass, true) {
			annotations["nginx.ingress.kubernetes.io/proxy-body-size"] = "0"
			annotations["nginx.ingress.kubernetes.io/proxy-max-temp-file-size"] = "0"
			annotations["nginx.ingress.kubernetes.io/proxy-buffer-size"] = "512k"
			annotations["nginx.ingress.kubernetes.io/proxy-buffering"] = "off"
			annotations["nginx.ingress.kubernetes.io/proxy-request-buffering"] = "off"
			annotations["nginx.ingress.kubernetes.io/proxy-connect-timeout"] = "75"
			annotations["nginx.ingress.kubernetes.io/proxy-read-timeout"] = "600"
			annotations["nginx.ingress.kubernetes.io/proxy-send-timeout"] = "600"
		}
	}
	for k, v := range ing.Annotations {
		annotations[k] = v
	}

	rules := ing.Rules
	if len(rules) == 0 {
		pathType := networkingv1.PathTypePrefix
		rules = []networkingv1.IngressRule{{
			Host: ing.Host,
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path:     "/",
					PathType: &pathType,
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
						Name: "nginx-proxy",
						Port: networkingv1.ServiceBackendPort{Number: 80},
					}},
				}},
			}},
		}}
	}
	tls := ing.TLS
	if len(tls) == 0 && ing.TLSSecretName != "" {
		t := networkingv1.IngressTLS{SecretName: ing.TLSSecretName}
		if ing.Host != "" {
			t.Hosts = []string{ing.Host}
		}
		tls = []networkingv1.IngressTLS{t}
	}

	name := "malcolm-ingress"
	if className != "" {
		name = className + "-ingress"
	}
	obj := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "Ingress"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: r.ns, Labels: r.labels("ingress"), Annotations: annotations,
		},
		Spec: networkingv1.IngressSpec{Rules: rules, TLS: tls},
	}
	if className != "" {
		obj.Spec.IngressClassName = ptr.To(className)
	}
	r.add(obj)

	if !r.spec.Istio.Enabled {
		r.url = r.externalURL()
	}
}

// externalURL is the browser-facing URL of Malcolm when a hostname is known
// from the Istio or Ingress configuration.
func (r *renderer) externalURL() string {
	if is := r.spec.Istio; is.Enabled && is.Host != "" {
		return "https://" + is.Host
	}
	ing := r.spec.Ingress
	if !boolDefault(ing.Enabled, true) || ing.Host == "" {
		return ""
	}
	if ing.TLSSecretName != "" || len(ing.TLS) > 0 {
		return "https://" + ing.Host
	}
	return "http://" + ing.Host
}

func (r *renderer) renderIstio() {
	is := r.spec.Istio
	if !is.Enabled {
		return
	}
	if !r.in.IstioAvailable {
		r.warn("istio.enabled is true but the VirtualService CRD (networking.istio.io) is not installed")
		return
	}
	vs := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": VirtualServiceAPIVersion,
		"kind":       "VirtualService",
		"metadata": map[string]any{
			"name":      "malcolm",
			"namespace": r.ns,
			"labels":    toAnyMap(r.labels("ingress")),
		},
		"spec": map[string]any{
			"gateways": []any{strDefault(is.Gateway, "istio-system/tenant")},
			"hosts":    []any{is.Host},
			"http": []any{map[string]any{
				"route": []any{map[string]any{
					"destination": map[string]any{
						"host": "nginx-proxy." + r.ns + ".svc.cluster.local",
						"port": map[string]any{"number": int64(80)},
					},
				}},
			}},
		},
	}}
	r.add(vs)
	r.url = r.externalURL()
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (r *renderer) networkPolicy(name string, spec networkingv1.NetworkPolicySpec) {
	r.add(&networkingv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.ns, Labels: r.labels("network-policy")},
		Spec:       spec,
	})
}

func nsSelector(ns string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": ns}}
}

func port(proto corev1.Protocol, p int32) networkingv1.NetworkPolicyPort {
	return networkingv1.NetworkPolicyPort{Protocol: ptr.To(proto), Port: ptr.To(intstr.FromInt32(p))}
}

func (r *renderer) renderNetworkPolicies() {
	np := r.spec.NetworkPolicy
	both := []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}
	egressOnly := []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
	dns := []networkingv1.NetworkPolicyPort{port(corev1.ProtocolTCP, 53), port(corev1.ProtocolUDP, 53)}

	r.networkPolicy("allow-internal-block-external", networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: both,
		Ingress: append([]networkingv1.NetworkPolicyIngressRule{
			{Ports: dns},
			{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: nsSelector(r.ns)}}},
		}, np.AdditionalIngress...),
		Egress: append([]networkingv1.NetworkPolicyEgressRule{
			{Ports: dns},
			{To: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: nsSelector(r.ns)}}},
		}, np.AdditionalEgress...),
	})

	if r.spec.Istio.Enabled {
		istioNS := strDefault(r.spec.Istio.Namespace, "istio-system")
		r.networkPolicy("allow-istio-ingress-egress", networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: both,
			Ingress:     []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: nsSelector(istioNS)}}}},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: nsSelector(istioNS)}}}},
		})
	}

	// Allow reaching the Kubernetes API server (service IP and endpoints).
	var apiPeers []networkingv1.NetworkPolicyPeer
	for _, ip := range r.in.KubernetesAPIAddresses {
		apiPeers = append(apiPeers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: hostCIDR(ip)}})
	}
	if len(apiPeers) > 0 {
		r.networkPolicy("dynamic-endpoint-policy", networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: egressOnly,
			Egress:      []networkingv1.NetworkPolicyEgressRule{{To: apiPeers}},
		})
	}

	// Arkime retrieves PCAP from arkime-live capture nodes on port 8005.
	r.networkPolicy("arkime-pcap-download", networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{LabelPodName: "arkime-deployment"}},
		PolicyTypes: egressOnly,
		Egress: []networkingv1.NetworkPolicyEgressRule{{
			To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: strDefault(np.NodeCIDR, "10.0.0.0/8")}}},
			Ports: []networkingv1.NetworkPolicyPort{port(corev1.ProtocolTCP, 8005)},
		}},
	})

	r.networkPolicy("allow-all-to-ingress-proxy", networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{LabelPodName: "nginx-proxy-deployment"}},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{port(corev1.ProtocolTCP, 443)}}},
	})
}

func hostCIDR(ip string) string {
	for i := 0; i < len(ip); i++ {
		if ip[i] == ':' {
			return ip + "/128"
		}
	}
	return ip + "/32"
}
