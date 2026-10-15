package render

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
)

// Shared claim identifiers.
const (
	ClaimPCAP        = "pcap-claim"
	ClaimZeek        = "zeek-claim"
	ClaimSuricata    = "suricata-claim-offline"
	ClaimConfig      = "config-claim"
	ClaimRuntimeLogs = "runtime-logs-claim"
)

type sharedClaim struct {
	name string
	spec malcolmv1.VolumeClaimSpec
	size string
}

func (r *renderer) sharedClaims() []sharedClaim {
	st := r.spec.Storage
	return []sharedClaim{
		{ClaimPCAP, st.PCAP, r.tun.StoragePCAP},
		{ClaimZeek, st.Zeek, r.tun.StorageZeek},
		{ClaimSuricata, st.Suricata, r.tun.StorageSuricata},
		{ClaimConfig, st.Config, r.tun.StorageConfig},
		{ClaimRuntimeLogs, st.RuntimeLogs, r.tun.StorageRuntimeLogs},
	}
}

// claimName returns the PVC name actually mounted for a shared claim.
func (r *renderer) claimName(name string) string {
	for _, c := range r.sharedClaims() {
		if c.name == name && c.spec.ExistingClaim != "" {
			return c.spec.ExistingClaim
		}
	}
	return name
}

func (r *renderer) storageClass(override *string) *string {
	if override != nil {
		if *override == "" {
			return nil
		}
		return override
	}
	if r.spec.Storage.StorageClassName != nil && *r.spec.Storage.StorageClassName != "" {
		return r.spec.Storage.StorageClassName
	}
	return nil
}

func (r *renderer) claimSpec(c malcolmv1.VolumeClaimSpec, defaultSize string, defaultMode corev1.PersistentVolumeAccessMode) corev1.PersistentVolumeClaimSpec {
	size := mustQuantity(defaultSize)
	if c.Size != nil {
		size = *c.Size
	}
	modes := c.AccessModes
	if len(modes) == 0 {
		modes = []corev1.PersistentVolumeAccessMode{defaultMode}
	}
	fs := corev1.PersistentVolumeFilesystem
	return corev1.PersistentVolumeClaimSpec{
		StorageClassName: r.storageClass(c.StorageClassName),
		AccessModes:      modes,
		VolumeMode:       &fs,
		Selector:         c.Selector,
		Resources: corev1.VolumeResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceStorage: size},
		},
	}
}

func (r *renderer) renderStorage() {
	for _, c := range r.sharedClaims() {
		if c.spec.ExistingClaim != "" {
			continue
		}
		pvc := &corev1.PersistentVolumeClaim{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      c.name,
				Namespace: r.ns,
				Labels:    r.labels("storage"),
			},
			Spec: r.claimSpec(c.spec, c.size, corev1.ReadWriteMany),
		}
		if r.retainOnDelete() {
			pvc.Annotations = map[string]string{AnnotationRetain: "true"}
		}
		r.add(pvc)
	}
}

// claimTemplate is a StatefulSet volumeClaimTemplate.
func (r *renderer) claimTemplate(name string, c malcolmv1.VolumeClaimSpec, defaultSize string) corev1.PersistentVolumeClaim {
	return corev1.PersistentVolumeClaim{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       r.claimSpec(c, defaultSize, corev1.ReadWriteOnce),
	}
}
