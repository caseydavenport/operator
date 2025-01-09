// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This renderer is responsible for all resources related to a Guardian Deployment in a
// multicluster setup.
package render

import (
	"fmt"
	"net"
	"net/url"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/ptr"
	operatorurl "github.com/tigera/operator/pkg/url"
	"golang.org/x/net/http/httpproxy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/api/pkg/lib/numorstring"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rcomponents "github.com/tigera/operator/pkg/render/common/components"
	"github.com/tigera/operator/pkg/render/common/meta"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/securitycontextconstraints"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	GuardianName                   = "tigera-guardian"
	GuardianServiceAccountName     = GuardianName
	GuardianClusterRoleName        = GuardianName
	GuardianClusterRoleBindingName = GuardianName
	GuardianDeploymentName         = GuardianName
	GuardianServiceName            = "tigera-guardian"
	GuardianVolumeName             = "tigera-guardian-certs"
	GuardianSecretName             = "tigera-managed-cluster-connection"
	GuardianTargetPort             = 8080
	GuardianPolicyName             = networkpolicy.TigeraComponentPolicyPrefix + "guardian-access"
)

func GuardianEntityRule(variant operatorv1.ProductVariant) v3.EntityRule {
	ns := GuardianNamespace(variant)
	return networkpolicy.CreateEntityRule(ns, GuardianDeploymentName, GuardianTargetPort)
}

func GuardianSourceEntityRule(variant operatorv1.ProductVariant) v3.EntityRule {
	ns := GuardianNamespace(variant)
	return networkpolicy.CreateSourceEntityRule(ns, GuardianDeploymentName)
}

func GuardianServiceSelectorEntityRule(variant operatorv1.ProductVariant) v3.EntityRule {
	ns := GuardianNamespace(variant)
	return networkpolicy.CreateServiceSelectorEntityRule(ns, GuardianName)
}

func GuardianNamespace(_ operatorv1.ProductVariant) string {
	return common.CalicoNamespace
}

func Guardian(cfg *GuardianConfiguration) Component {
	return &GuardianComponent{
		cfg: cfg,
	}
}

func GuardianPolicy(cfg *GuardianConfiguration) (Component, error) {
	guardianAccessPolicy, err := guardianAllowTigeraPolicy(cfg)
	if err != nil {
		return nil, err
	}

	return NewPassthrough(
		guardianAccessPolicy,
		networkpolicy.AllowTigeraDefaultDeny(GuardianNamespace(cfg.Installation.Variant)),
	), nil
}

// GuardianConfiguration contains all the config information needed to render the component.
type GuardianConfiguration struct {
	Namespace                   string
	URL                         string
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	Installation                *operatorv1.InstallationSpec
	TunnelSecret                *corev1.Secret
	TrustedCertBundle           certificatemanagement.TrustedBundleRO
	TunnelCAType                operatorv1.CAType
	ManagementClusterConnection *operatorv1.ManagementClusterConnection

	// PodProxies represents the resolved proxy configuration for each Guardian pod.
	// If this slice is empty, then resolution has not yet occurred. Pods with no proxy
	// configured are represented with a nil value.
	PodProxies []*httpproxy.Config
}

type GuardianComponent struct {
	cfg   *GuardianConfiguration
	image string
}

func (c *GuardianComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	c.image, err = components.GetReference(components.ComponentGuardian, reg, path, prefix, is)
	return err
}

func (c *GuardianComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *GuardianComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(GuardianNamespace(c.cfg.Installation.Variant), c.cfg.PullSecrets...)...)...)
	objs = append(objs,
		c.serviceAccount(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.deployment(),
		c.service(),
		c.aggregatorService(),
		c.aggregatorNetworkPolicy(),
		// c.cfg.TrustedCertBundle.ConfigMap(GuardianNamespace(c.cfg.Installation.Variant)), // TODO: We still need to create this if not running in calico-system.

		// Add tigera-manager service account for impersonation. In managed clusters, the tigera-manager
		// service account is always within the tigera-manager namespace - regardless of (multi)tenancy mode.
		CreateNamespace(ManagerNamespace, c.cfg.Installation.KubernetesProvider, PSSRestricted, c.cfg.Installation.Azure),
		managerServiceAccount(ManagerNamespace),
		managerClusterRole(true, c.cfg.Installation.KubernetesProvider, nil),
		managerClusterRoleBinding([]string{ManagerNamespace}),
	)

	if c.cfg.TunnelSecret != nil {
		objs = append(
			objs,
			secret.CopyToNamespace(GuardianNamespace(c.cfg.Installation.Variant), c.cfg.TunnelSecret)[0],
		)
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// Install default UI settings for this managed cluster.
		objs = append(objs,
			managerClusterWideSettingsGroup(),
			managerUserSpecificSettingsGroup(),
			managerClusterWideTigeraLayer(),
			managerClusterWideDefaultView(),
		)
	}

	return objs, nil
}

func (c *GuardianComponent) Ready() bool {
	return true
}

func (c *GuardianComponent) service() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianServiceName,
			Namespace: GuardianNamespace(c.cfg.Installation.Variant),
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": GuardianName,
			},
			Ports: []corev1.ServicePort{
				{
					Name: "linseed",
					Port: 443,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
					Protocol: corev1.ProtocolTCP,
				},
				{
					Name: "elasticsearch",
					Port: 9200,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
					Protocol: corev1.ProtocolTCP,
				},
				{
					Name: "kibana",
					Port: 5601,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (c *GuardianComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GuardianServiceAccountName, Namespace: GuardianNamespace(c.cfg.Installation.Variant)},
	}
}

func (c *GuardianComponent) clusterRole() *rbacv1.ClusterRole {
	if true {
		return c.clusterRoleNoImpersonate()
	}
	return c.clusterRoleImpersonate()
}

func (c *GuardianComponent) clusterRoleNoImpersonate() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			// Baseline ability to GET everything. This should be limited specifically to required resources though.
			{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"get", "list", "watch"},
			},
			// Some create permissions we should remove the need for.
			// SubjectAccessReview (sent by ui-apis)
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			// Service graph needs to get felixconfig.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"felixconfigurations"},
				Verbs:     []string{"get"},
			},
			// TODO: Remove. Useful for debugging.
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}
}

func (c *GuardianComponent) clusterRoleImpersonate() *rbacv1.ClusterRole {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"users", "groups", "serviceaccounts"},
			Verbs:     []string{"impersonate"},
		},
	}

	if c.cfg.OpenShift {
		policyRules = append(policyRules, rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{securitycontextconstraints.NonRootV2},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleName,
		},
		Rules: policyRules,
	}
}

func (c *GuardianComponent) aggregatorService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "goldmane",
			Namespace: common.CalicoNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": GuardianName},
			Ports:    []corev1.ServicePort{{Port: 7443}},
		},
	}
}

func (c *GuardianComponent) aggregatorContainer() corev1.Container {
	return corev1.Container{
		Name:            "goldmane",
		Image:           "caseydavenport/goldmane:latest",
		ImagePullPolicy: ImagePullPolicy(),
		VolumeMounts:    c.cfg.TrustedCertBundle.VolumeMounts(meta.OSTypeLinux),
		Env: []corev1.EnvVar{
			{
				Name:  "PUSH_URL",
				Value: fmt.Sprintf("https://%s.%s.svc/api/v1/flows/bulk", GuardianServiceName, GuardianNamespace("")),
			},
			{
				Name:  "CA_CERT_PATH",
				Value: c.cfg.TrustedCertBundle.MountPath(),
			},
			{
				Name:  "PORT",
				Value: "7443",
			},
		},
	}
}

func (c *GuardianComponent) clusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: GuardianClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     GuardianClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      GuardianServiceAccountName,
				Namespace: GuardianNamespace(c.cfg.Installation.Variant),
			},
		},
	}
}

func (c *GuardianComponent) deployment() *appsv1.Deployment {
	var replicas int32 = 1

	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianDeploymentName,
			Namespace: GuardianNamespace(c.cfg.Installation.Variant),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:        GuardianDeploymentName,
					Namespace:   GuardianNamespace(c.cfg.Installation.Variant),
					Annotations: c.annotations(),
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: GuardianServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers: []corev1.Container{
						c.container(),
						c.aggregatorContainer(),
					},
					Volumes: c.volumes(),
				},
			},
		},
	}

	if c.cfg.ManagementClusterConnection != nil {
		if overrides := c.cfg.ManagementClusterConnection.Spec.GuardianDeployment; overrides != nil {
			rcomponents.ApplyDeploymentOverrides(d, overrides)
		}
	}
	return d
}

func (c *GuardianComponent) volumes() []corev1.Volume {
	return []corev1.Volume{
		c.cfg.TrustedCertBundle.Volume(),

		{
			Name: GuardianVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: GuardianSecretName,

					// This is marked optional, since we only need this when actually establishing
					// a tunnel to the remote cluster, and we don't want to have to reinstall
					// the pod as part of connection flow.
					Optional: ptr.BoolToPtr(true),
				},
			},
		},
	}
}

func (c *GuardianComponent) container() corev1.Container {
	return corev1.Container{
		Name:            GuardianDeploymentName,
		Image:           c.image,
		ImagePullPolicy: ImagePullPolicy(),
		Env: []corev1.EnvVar{
			{Name: "GUARDIAN_PORT", Value: "9443"},
			{Name: "GUARDIAN_LOGLEVEL", Value: "INFO"},
			{Name: "GUARDIAN_VOLTRON_URL", Value: c.cfg.URL},
			{Name: "GUARDIAN_VOLTRON_CA_TYPE", Value: string(c.cfg.TunnelCAType)},
			{Name: "GUARDIAN_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
			{Name: "GUARDIAN_PROMETHEUS_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
			{Name: "GUARDIAN_QUERYSERVER_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		},
		VolumeMounts: c.volumeMounts(),
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/health",
					Port: intstr.FromInt(9080),
				},
			},
			InitialDelaySeconds: 90,
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/health",
					Port: intstr.FromInt(9080),
				},
			},
			InitialDelaySeconds: 10,
		},
		SecurityContext: securitycontext.NewNonRootContext(),
	}
}

func (c *GuardianComponent) volumeMounts() []corev1.VolumeMount {
	return append(
		// Add the volume mounts for the trusted CA bundle, which contains the full set of CA certificates to
		// trust for all containers in the pod.
		c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),

		// Add the volume mount for the secret containing the tunnel secret.
		corev1.VolumeMount{
			Name:      GuardianVolumeName,
			MountPath: "/certs/",
			ReadOnly:  true,
		},
	)
}

func (c *GuardianComponent) annotations() map[string]string {
	annotations := c.cfg.TrustedCertBundle.HashAnnotations()

	if c.cfg.TunnelSecret != nil {
		// TODO: Make Guardian capable of reloading the secret without a restart.
		annotations["hash.operator.tigera.io/tigera-managed-cluster-connection"] = rmeta.AnnotationHash(c.cfg.TunnelSecret.Data)
	}
	return annotations
}

func (c *GuardianComponent) aggregatorNetworkPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Installation.KubernetesProvider.IsOpenShift())
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(443, 6443, 12388),
			},
		},
	}...)

	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: GuardianEntityRule(c.cfg.Installation.Variant),
	})

	ingressRules := []v3.Rule{
		{
			Action: v3.Allow,
		},
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-tigera.goldmane",
			Namespace: common.CalicoNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(GuardianName),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress, v3.PolicyTypeIngress},
			Egress:   egressRules,
			Ingress:  ingressRules,
		},
	}
}

func guardianAllowTigeraPolicy(cfg *GuardianConfiguration) (*v3.NetworkPolicy, error) {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: PacketCaptureEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.PrometheusEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: TigeraAPIServerEntityRule,
		},
	}...)

	// The loop below creates an egress rule for each unique destination that the Guardian pods connect to. If there are
	// multiple guardian pods and their proxy  settings differ, then there are multiple destinations that must have egress allowed.
	allowedDestinations := map[string]bool{}
	processedPodProxies := ProcessPodProxies(cfg.PodProxies)
	for _, podProxyConfig := range processedPodProxies {
		var proxyURL *url.URL
		var err error
		if podProxyConfig != nil && podProxyConfig.HTTPSProxy != "" {
			targetURL := &url.URL{
				// The scheme should be HTTPS, as we are establishing an mTLS session with the target.
				Scheme: "https",

				// We expect `target` to be of the form host:port.
				Host: cfg.URL,
			}

			proxyURL, err = podProxyConfig.ProxyFunc()(targetURL)
			if err != nil {
				return nil, err
			}
		}

		var tunnelDestinationHostPort string
		if proxyURL != nil {
			proxyHostPort, err := operatorurl.ParseHostPortFromHTTPProxyURL(proxyURL)
			if err != nil {
				return nil, err
			}

			tunnelDestinationHostPort = proxyHostPort
		} else {
			// cfg.URL has host:port form
			tunnelDestinationHostPort = cfg.URL
		}

		// Check if we've already created an egress rule for this destination.
		if allowedDestinations[tunnelDestinationHostPort] {
			continue
		}

		host, port, err := net.SplitHostPort(tunnelDestinationHostPort)
		if err != nil {
			return nil, err
		}
		parsedPort, err := numorstring.PortFromString(port)
		if err != nil {
			return nil, err
		}
		parsedIp := net.ParseIP(host)
		if parsedIp == nil {
			// Assume host is a valid hostname.
			egressRules = append(egressRules, v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Domains: []string{host},
					Ports:   []numorstring.Port{parsedPort},
				},
			})
			allowedDestinations[tunnelDestinationHostPort] = true

		} else {
			var netSuffix string
			if parsedIp.To4() != nil {
				netSuffix = "/32"
			} else {
				netSuffix = "/128"
			}

			egressRules = append(egressRules, v3.Rule{
				Action:   v3.Allow,
				Protocol: &networkpolicy.TCPProtocol,
				Destination: v3.EntityRule{
					Nets:  []string{parsedIp.String() + netSuffix},
					Ports: []numorstring.Port{parsedPort},
				},
			})
			allowedDestinations[tunnelDestinationHostPort] = true
		}
	}

	egressRules = append(egressRules, v3.Rule{Action: v3.Pass})

	guardianIngressDestinationEntityRule := v3.EntityRule{Ports: networkpolicy.Ports(8080)}
	networkpolicyHelper := networkpolicy.DefaultHelper()
	ingressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      FluentdSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ComplianceBenchmarkerSourceEntityRule(),
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ComplianceReporterSourceEntityRule(),
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ComplianceSnapshotterSourceEntityRule(),
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      networkpolicyHelper.ComplianceControllerSourceEntityRule(),
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      IntrusionDetectionSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      IntrusionDetectionInstallerSourceEntityRule,
			Destination: guardianIngressDestinationEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: guardianIngressDestinationEntityRule,
		},
	}

	policy := &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GuardianPolicyName,
			Namespace: GuardianNamespace(cfg.Installation.Variant),
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(GuardianName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}

	return policy, nil
}

func ProcessPodProxies(podProxies []*httpproxy.Config) []*httpproxy.Config {
	// If pod proxies are empty, then pod proxy resolution has not yet occurred.
	// Assume that a single Guardian pod is running without a proxy.
	if len(podProxies) == 0 {
		return []*httpproxy.Config{nil}
	}

	return podProxies
}
