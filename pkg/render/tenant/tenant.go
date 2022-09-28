// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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

package tenant

import (
	"fmt"
	"strconv"

	ocsv1 "github.com/openshift/api/security/v1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/configmap"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rkibana "github.com/tigera/operator/pkg/render/common/kibana"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	managerPort       = 9443
	VoltronPolicyName = networkpolicy.TigeraComponentPolicyPrefix + "voltron-access"

	ElasticsearchManagerUserSecret = "tigera-ee-manager-elasticsearch-access"

	VoltronName             = "tigera-voltron"
	VoltronTunnelSecretName = "tigera-management-cluster-connection"
	defaultVoltronPort      = 9443
	tunnelPort              = 9449
)

var (
	ManagerEntityRule       = networkpolicy.CreateEntityRule(render.ManagerNamespace, render.ManagerDeploymentName, managerPort)
	ManagerSourceEntityRule = networkpolicy.CreateSourceEntityRule(render.ManagerNamespace, render.ManagerDeploymentName)
)

func Tenant(cfg *Configuration) (render.Component, error) {
	var tlsSecrets []*corev1.Secret
	tlsAnnotations := cfg.TrustedCertBundle.HashAnnotations()
	tlsAnnotations[cfg.TLSKeyPair.HashAnnotationKey()] = cfg.TLSKeyPair.HashAnnotationValue()

	if cfg.KeyValidatorConfig != nil {
		tlsSecrets = append(tlsSecrets, cfg.KeyValidatorConfig.RequiredSecrets(render.ManagerNamespace)...)
		for key, value := range cfg.KeyValidatorConfig.RequiredAnnotations() {
			tlsAnnotations[key] = value
		}
	}
	tlsAnnotations[cfg.InternalTrafficSecret.HashAnnotationKey()] = cfg.InternalTrafficSecret.HashAnnotationValue()
	tlsAnnotations[cfg.TunnelSecret.HashAnnotationKey()] = cfg.InternalTrafficSecret.HashAnnotationValue()

	return &component{
		cfg:            cfg,
		tlsSecrets:     tlsSecrets,
		tlsAnnotations: tlsAnnotations,
	}, nil
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	// CRs.
	Tenant            *operatorv1.Tenant
	Installation      *operatorv1.InstallationSpec
	ManagementCluster *operatorv1.ManagementCluster
	Compliance        *operatorv1.Compliance

	// Platform config
	Openshift     bool
	ClusterDomain string

	// Secrets
	PullSecrets           []*corev1.Secret
	ESSecrets             []*corev1.Secret
	KeyValidatorConfig    authentication.KeyValidatorConfig
	TrustedCertBundle     certificatemanagement.TrustedBundle
	TLSKeyPair            certificatemanagement.KeyPairInterface
	TunnelSecret          certificatemanagement.KeyPairInterface
	InternalTrafficSecret certificatemanagement.KeyPairInterface

	// Other
	ESClusterConfig         *relasticsearch.ClusterConfig
	Replicas                *int32
	ComplianceLicenseActive bool

	// Whether or not the cluster supports pod security policies.
	UsePSP bool
}

type component struct {
	cfg            *Configuration
	tlsSecrets     []*corev1.Secret
	tlsAnnotations map[string]string

	// Image for Voltron. Used in management clusters only to
	// maintain HTTPS tunnels to managed clusters.
	voltronImage string
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error

	c.voltronImage, err = components.GetReference(components.ComponentManagerProxy, reg, path, prefix, is)
	if err != nil {
		return err
	}

	// c.voltronImage = "gcr.io/unique-caldron-775/casey/voltron:latest"

	return nil
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) namespace() *corev1.Namespace {
	name := fmt.Sprintf("tenant-%s", c.cfg.Tenant.Name)
	ns := render.CreateNamespace(name, c.cfg.Installation.KubernetesProvider, render.PSSBaseline)
	ns.Labels["operator.tigera.io/tenant"] = c.cfg.Tenant.Name
	return ns
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	ns := c.namespace()
	objs := []client.Object{ns, networkpolicy.AllowTigeraDefaultDeny(ns.Name)}
	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(ns.Name, c.cfg.PullSecrets...)...)...)
	objs = append(objs, c.getTLSObjects()...)

	// If we're running on openshift, we need to add in an SCC.
	if c.cfg.Openshift {
		objs = append(objs, c.securityContextConstraints(ns.Name))
	} else if c.cfg.UsePSP {
		// If we're not running openshift, we need to add pod security policies.
		objs = append(objs, c.podSecurityPolicy())
	}

	// Include a Voltron deployment and service as well.
	objs = append(objs, c.voltronNetworkPolicy(ns.Name))
	objs = append(objs, voltronServiceAccount(ns.Name))
	objs = append(objs, voltronClusterRole(c.cfg.Openshift))
	objs = append(objs, roleBinding(ns.Name))
	objs = append(objs, c.voltronDeployment(ns.Name))
	objs = append(objs, c.voltronService(ns.Name))

	if c.cfg.KeyValidatorConfig != nil {
		objs = append(objs, configmap.ToRuntimeObjects(c.cfg.KeyValidatorConfig.RequiredConfigMaps(ns.Name)...)...)
	}

	return objs, nil
}

func (c *component) Ready() bool {
	return true
}

// voltronDeployment creates a deployment for voltron.
// TODO: Split voltron into separate component.
// TODO: Use a separate service account.
func (c *component) voltronDeployment(ns string) *appsv1.Deployment {
	podTemplate := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:        VoltronName,
			Namespace:   ns,
			Annotations: c.tlsAnnotations,
		},
		Spec: corev1.PodSpec{
			NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
			ServiceAccountName: VoltronName,
			Tolerations:        c.voltronTolerations(),
			ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
			Containers:         []corev1.Container{c.voltronContainer(ns)},
			Volumes:            c.voltronVolumes(),
		},
	}, c.cfg.ESClusterConfig, c.cfg.ESSecrets).(*corev1.PodTemplateSpec)

	if c.cfg.Replicas != nil && *c.cfg.Replicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity("tigera-voltron", ns)
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      VoltronName,
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: *podTemplate,
		},
	}
	return d
}

func (c *component) voltronVolumes() []corev1.Volume {
	v := []corev1.Volume{
		c.cfg.TLSKeyPair.Volume(),
		c.cfg.TrustedCertBundle.Volume(),
	}
	v = append(v,
		c.cfg.InternalTrafficSecret.Volume(),
		c.cfg.TunnelSecret.Volume(),
	)
	if c.cfg.KeyValidatorConfig != nil {
		v = append(v, c.cfg.KeyValidatorConfig.RequiredVolumes()...)
	}

	return v
}

// voltronProbe returns the probe for the proxy container.
// func (c *component) voltronProbe() *corev1.Probe {
// 	return &corev1.Probe{
// 		ProbeHandler: corev1.ProbeHandler{
// 			HTTPGet: &corev1.HTTPGetAction{
// 				Path:   "/voltron/api/health",
// 				Port:   intstr.FromInt(voltronPort),
// 				Scheme: corev1.URISchemeHTTPS,
// 			},
// 		},
// 		InitialDelaySeconds: 90,
// 		PeriodSeconds:       10,
// 	}
// }

// voltronContainer returns the container for the voltron container.
func (c *component) voltronContainer(ns string) corev1.Container {
	var keyPath, certPath, intKeyPath, intCertPath, tunnelKeyPath, tunnelCertPath string
	if c.cfg.TLSKeyPair != nil {
		keyPath, certPath = c.cfg.TLSKeyPair.VolumeMountKeyFilePath(), c.cfg.TLSKeyPair.VolumeMountCertificateFilePath()
	}
	if c.cfg.InternalTrafficSecret != nil {
		intKeyPath, intCertPath = c.cfg.InternalTrafficSecret.VolumeMountKeyFilePath(), c.cfg.InternalTrafficSecret.VolumeMountCertificateFilePath()
	}
	if c.cfg.TunnelSecret != nil {
		tunnelKeyPath, tunnelCertPath = c.cfg.TunnelSecret.VolumeMountKeyFilePath(), c.cfg.TunnelSecret.VolumeMountCertificateFilePath()
	}
	env := []corev1.EnvVar{
		{Name: "VOLTRON_TENANT", Value: c.cfg.Tenant.Name},

		{Name: "VOLTRON_PORT", Value: fmt.Sprintf("%d", defaultVoltronPort)},
		{Name: "VOLTRON_COMPLIANCE_ENDPOINT", Value: fmt.Sprintf("https://compliance.%s.svc.%s", render.ComplianceNamespace, c.cfg.ClusterDomain)},
		{Name: "VOLTRON_LOGLEVEL", Value: "Debug"},

		{Name: "VOLTRON_KIBANA_ENDPOINT", Value: rkibana.HTTPSEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain)},
		{Name: "VOLTRON_KIBANA_BASE_PATH", Value: fmt.Sprintf("/%s/", render.KibanaBasePath)},
		{Name: "VOLTRON_KIBANA_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},

		{Name: "VOLTRON_PACKET_CAPTURE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_PROMETHEUS_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_COMPLIANCE_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_DEX_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_QUERYSERVER_ENDPOINT", Value: fmt.Sprintf("https://%s.%s.svc:%d", render.QueryserverServiceName, render.QueryserverNamespace, render.QueryServerPort)},
		{Name: "VOLTRON_QUERYSERVER_BASE_PATH", Value: fmt.Sprintf("/api/v1/namespaces/%s/services/https:%s:%d/proxy/", render.QueryserverNamespace, render.QueryserverServiceName, render.QueryServerPort)},
		{Name: "VOLTRON_QUERYSERVER_CA_BUNDLE_PATH", Value: c.cfg.TrustedCertBundle.MountPath()},
		{Name: "VOLTRON_HTTPS_KEY", Value: keyPath},
		{Name: "VOLTRON_HTTPS_CERT", Value: certPath},
		{Name: "VOLTRON_TUNNEL_KEY", Value: tunnelKeyPath},
		{Name: "VOLTRON_TUNNEL_CERT", Value: tunnelCertPath},
		{Name: "VOLTRON_INTERNAL_HTTPS_KEY", Value: intKeyPath},
		{Name: "VOLTRON_INTERNAL_HTTPS_CERT", Value: intCertPath},
		{Name: "VOLTRON_ENABLE_MULTI_CLUSTER_MANAGEMENT", Value: "true"},
		{Name: "VOLTRON_TUNNEL_PORT", Value: fmt.Sprintf("%d", tunnelPort)},
		{Name: "VOLTRON_DEFAULT_FORWARD_SERVER", Value: "tigera-secure-es-gateway-http.tigera-elasticsearch.svc:9200"},
		{Name: "VOLTRON_ENABLE_COMPLIANCE", Value: strconv.FormatBool(c.cfg.Compliance != nil && c.cfg.ComplianceLicenseActive)},
		{Name: "VOLTRON_FIPS_MODE_ENABLED", Value: operatorv1.IsFIPSModeEnabledString(c.cfg.Installation.FIPSMode)},

		// NGINX_ENDPOINT is the location of the Manager UI. It's default config is to listen on localhost:8080. Since we're splitting, we
		// need it to bind to an externally reachable address.
		{Name: "VOLTRON_NGINX_ENDPOINT", Value: fmt.Sprintf("http://tigera-manager.%s.svc.%s:8080", ns, c.cfg.ClusterDomain)},
		{Name: "VOLTRON_ELASTIC_ENDPOINT", Value: fmt.Sprintf("https://tigera-es-proxy.%s.svc.%s:8443", ns, c.cfg.ClusterDomain)},
	}

	if c.cfg.ManagementCluster != nil {
		env = append(env, corev1.EnvVar{Name: "VOLTRON_USE_HTTPS_CERT_ON_TUNNEL", Value: strconv.FormatBool(c.cfg.ManagementCluster.Spec.TLS != nil && c.cfg.ManagementCluster.Spec.TLS.SecretName == render.ManagerTLSSecretName)})
	}

	if c.cfg.KeyValidatorConfig != nil {
		env = append(env, c.cfg.KeyValidatorConfig.RequiredEnv("VOLTRON_")...)
	}

	return corev1.Container{
		Name:            VoltronName,
		Image:           c.voltronImage,
		ImagePullPolicy: corev1.PullAlways,
		Env:             env,
		VolumeMounts:    c.volumeMountsForVoltron(),
		// LivenessProbe: c.voltronProbe(),
		// UID 1001 is used in the voltron Dockerfile.
		SecurityContext: securitycontext.NewBaseContext(1001, 0),
	}
}

func (c *component) volumeMountsForVoltron() []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{Name: render.ManagerTLSSecretName, MountPath: "/manager-tls", ReadOnly: true},
		c.cfg.TrustedCertBundle.VolumeMount(c.SupportedOSType()),
	}

	mounts = append(mounts, c.cfg.InternalTrafficSecret.VolumeMount(c.SupportedOSType()))
	mounts = append(mounts, c.cfg.TunnelSecret.VolumeMount(c.SupportedOSType()))

	return mounts
}

func (c *component) voltronTolerations() []corev1.Toleration {
	return append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
}

// voltronService returns the service exposing the Tigera Secure web app.
func (c *component) voltronService(ns string) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      VoltronName,
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       int32(defaultVoltronPort),
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(defaultVoltronPort),
					Name:       "https",
				},
				{
					Port:       int32(tunnelPort),
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(tunnelPort),
					Name:       "tunnel",
				},
			},
			Selector: map[string]string{
				"k8s-app": VoltronName,
			},
		},
	}
}

func voltronServiceAccount(ns string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: VoltronName, Namespace: ns},
	}
}

// voltronClusterRole returns a clusterrole that allows authn/authz review requests.
func voltronClusterRole(openshift bool) *rbacv1.ClusterRole {
	cr := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: VoltronName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			// When a request is made in the manager UI, they are proxied through the Voltron backend server. If the
			// request is targeting a k8s api or when it is targeting a managed cluster, Voltron will authenticate the
			// user based on the auth header and then impersonate the user.
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},

			// For listing managed clusters. TODO: Should be a namespaced resource.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "get", "watch", "update"},
			},
		},
	}

	if !openshift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		cr.Rules = append(cr.Rules,
			rbacv1.PolicyRule{
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"tigera-voltron"},
			},
		)
	}

	return cr
}

func roleBinding(ns string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: VoltronName, Namespace: ns},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     VoltronName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      VoltronName,
				Namespace: ns,
			},
		},
	}
}

func (c *component) securityContextConstraints(ns string) *ocsv1.SecurityContextConstraints {
	privilegeEscalation := false
	return &ocsv1.SecurityContextConstraints{
		TypeMeta:                 metav1.TypeMeta{Kind: "SecurityContextConstraints", APIVersion: "security.openshift.io/v1"},
		ObjectMeta:               metav1.ObjectMeta{Name: ns},
		AllowHostDirVolumePlugin: true,
		AllowHostIPC:             false,
		AllowHostNetwork:         false,
		AllowHostPID:             true,
		AllowHostPorts:           false,
		AllowPrivilegeEscalation: &privilegeEscalation,
		AllowPrivilegedContainer: false,
		FSGroup:                  ocsv1.FSGroupStrategyOptions{Type: ocsv1.FSGroupStrategyRunAsAny},
		RunAsUser:                ocsv1.RunAsUserStrategyOptions{Type: ocsv1.RunAsUserStrategyRunAsAny},
		ReadOnlyRootFilesystem:   false,
		SELinuxContext:           ocsv1.SELinuxContextStrategyOptions{Type: ocsv1.SELinuxStrategyMustRunAs},
		SupplementalGroups:       ocsv1.SupplementalGroupsStrategyOptions{Type: ocsv1.SupplementalGroupsStrategyRunAsAny},
		Users:                    []string{fmt.Sprintf("system:serviceaccount:%s:tigera-voltron", ns)},
		Volumes:                  []ocsv1.FSType{"*"},
	}
}

func (c *component) getTLSObjects() []client.Object {
	objs := []client.Object{}
	for _, s := range c.tlsSecrets {
		objs = append(objs, s)
	}

	return objs
}

func (c *component) podSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName("tigera-voltron")
	return psp
}

// NetworkPolicy to apply to Voltron. Voltron is run as its own service, and accepts connections
// from outside of the cluster in the form of tunnel connects, as well as for access to the manager UI.
// It needs to allow ingress from all sources, and access to the complete set of services it proxies to.
func (c *component) voltronNetworkPolicy(ns string) *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.CreateServiceSelectorEntityRule(ns, render.ManagerDeploymentName),
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.TigeraAPIServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Source:      v3.EntityRule{},
			Destination: networkpolicy.ESGatewayEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.ComplianceServerEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.DexEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.PacketCaptureEntityRule,
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerServiceSelectorEntityRule,
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, c.cfg.Openshift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.PrometheusEntityRule,
	})

	ingressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				// This policy allows access to Voltron from anywhere
				Nets: []string{"0.0.0.0/0"},
			},
			Destination: v3.EntityRule{
				// By default, Calico Enterprise Voltron is accessed over https via voltron.
				Ports: networkpolicy.Ports(defaultVoltronPort),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Source: v3.EntityRule{
				// This policy allows access to Calico Enterprise Voltron from anywhere
				Nets: []string{"::/0"},
			},
			Destination: v3.EntityRule{
				// By default, Calico Enterprise Voltron is accessed over https
				Ports: networkpolicy.Ports(defaultVoltronPort),
			},
		},
	}

	ingressRules = append(ingressRules, v3.Rule{
		Action:   v3.Allow,
		Protocol: &networkpolicy.TCPProtocol,
		Source:   v3.EntityRule{},
		Destination: v3.EntityRule{
			// This policy is used for multi-cluster management to establish a tunnel from another cluster.
			Ports: networkpolicy.Ports(uint16(tunnelPort)),
		},
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      VoltronPolicyName,
			Namespace: ns,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector(VoltronName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  ingressRules,
			Egress:   egressRules,
		},
	}
}
