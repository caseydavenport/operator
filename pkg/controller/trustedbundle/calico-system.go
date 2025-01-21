// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package trustedbundle

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/stringsutil"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/logstorage"

	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operator "github.com/tigera/operator/api/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/resourcequota"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("controller_calico-system_bundle")

type CalicoSystemBundleController struct {
	client        client.Client
	scheme        *runtime.Scheme
	status        status.StatusManager
	clusterDomain string
	log           logr.Logger
}

func AddCalicoSystem(mgr manager.Manager, opts options.AddOptions) error {
	r := &CalicoSystemBundleController{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		clusterDomain: opts.ClusterDomain,
		status:        status.New(mgr.GetClient(), "secrets", opts.KubernetesVersion),
		log:           logf.Log.WithName("controller_tenant_secrets"),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("calico-system-trusted-bundle", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	if err = c.WatchObject(&operatorv1.Installation{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tenant-controller failed to watch Installation resource: %w", err)
	}
	if err = utils.AddSecretsWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("tenant-controller failed to watch cluster scoped CA secret %s: %w", certificatemanagement.CASecretName, err)
	}

	if err = utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapName, "", &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tenant-controller failed to watch ConfigMap resource: %w", err)
	}
	if err = utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapNamePublic, "", &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tenant-controller failed to watch ConfigMap resource: %w", err)
	}
	return nil
}

func (r *CalicoSystemBundleController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Calico System Trusted Bundle")

	instance := &operator.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, &instance.Spec, r.clusterDomain, common.OperatorNamespace(), certificatemanager.WithLogger(reqLogger))
	if err != nil {
		r.status.SetDegraded(operator.ResourceCreateError, "Unable to create certificate manager", err, reqLogger)
		return reconcile.Result{}, err
	}

	typhaNodeTLS, err := GetOrCreateTyphaNodeTLSConfig(r.client, certificateManager)
	if err != nil {
		log.Error(err, "Error with Typha/Felix secrets")
		r.status.SetDegraded(operator.CertificateError, "Error with Typha/Felix secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	if instance.Spec.Variant == operator.TigeraSecureEnterprise {
		managerInternalTLSSecret, err := certificateManager.GetCertificate(r.client, render.ManagerInternalTLSSecretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, fmt.Sprintf("Error fetching TLS secret %s in namespace %s", render.ManagerInternalTLSSecretName, common.OperatorNamespace()), err, reqLogger)
			return reconcile.Result{}, nil
		} else if managerInternalTLSSecret != nil {
			// It may seem odd to add the manager internal TLS secret to the trusted bundle for Typha / calico-node, but this bundle is also used
			// for other components in this namespace such as es-kube-controllers, who communicates with Voltron and thus needs to trust this certificate.
			typhaNodeTLS.TrustedBundle.AddCertificates(managerInternalTLSSecret)
		}
	}

	birdTemplates, err := getBirdTemplates(r.client)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error retrieving confd templates", err, reqLogger)
		return reconcile.Result{}, err
	}

	bgpLayout, err := getConfigMap(r.client, render.BGPLayoutConfigMapName)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error retrieving BGP layout ConfigMap", err, reqLogger)
		return reconcile.Result{}, err
	}

	if bgpLayout != nil {
		// Validate that BGP layout ConfigMap has the expected key.
		if _, ok := bgpLayout.Data[render.BGPLayoutConfigMapKey]; !ok {
			err = fmt.Errorf("BGP layout ConfigMap does not have %v key", render.BGPLayoutConfigMapKey)
			r.status.SetDegraded(operator.ResourceValidationError, "Error in BGP layout ConfigMap", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	err = utils.PopulateK8sServiceEndPoint(r.client)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error reading services endpoint configmap", err, reqLogger)
		return reconcile.Result{}, err
	}

	openShiftOnAws := false
	if instance.Spec.KubernetesProvider.IsOpenShift() {
		openShiftOnAws, err = isOpenshiftOnAws(instance, ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error checking if OpenShift is on AWS", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Determine if we need to migrate resources from the kube-system namespace. If
	// we do then we'll render the Calico components with additional node selectors to
	// prevent scheduling, later we will run a migration that migrates nodes one by one
	// to mimic a 'normal' rolling update.
	needNsMigration, err := r.namespaceMigration.NeedsCoreNamespaceMigration(ctx)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error checking if namespace migration is needed", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Set any non-default FelixConfiguration values that we need.
	felixConfiguration, err := utils.PatchFelixConfiguration(ctx, r.client, func(fc *crdv1.FelixConfiguration) (bool, error) {
		// Configure defaults.
		u, err := r.setDefaultsOnFelixConfiguration(ctx, instance, fc, reqLogger)
		if err != nil {
			return false, err
		}

		// Configure nftables mode.
		u2, err := r.setNftablesMode(ctx, instance, fc, reqLogger)
		if err != nil {
			return false, err
		}
		return u || u2, nil
	})
	if err != nil {
		return reconcile.Result{}, err
	}

	// nodeReporterMetricsPort is a port used in Enterprise to host internal metrics.
	// Operator is responsible for creating a service which maps to that port.
	// Here, we'll check the default felixconfiguration to see if the user is specifying
	// a non-default port, and use that value if they are.
	nodeReporterMetricsPort := defaultNodeReporterPort
	var nodePrometheusTLS certificatemanagement.KeyPairInterface
	calicoVersion := components.CalicoRelease

	felixPrometheusMetricsPort := defaultFelixMetricsDefaultPort

	if instance.Spec.Variant == operator.TigeraSecureEnterprise {

		// Determine the port to use for nodeReporter metrics.
		if felixConfiguration.Spec.PrometheusReporterPort != nil {
			nodeReporterMetricsPort = *felixConfiguration.Spec.PrometheusReporterPort
		}
		if nodeReporterMetricsPort == 0 {
			err := errors.New("felixConfiguration prometheusReporterPort=0 not supported")
			r.status.SetDegraded(operator.InvalidConfigurationError, "invalid metrics port", err, reqLogger)
			return reconcile.Result{}, err
		}

		if felixConfiguration.Spec.PrometheusMetricsPort != nil {
			felixPrometheusMetricsPort = *felixConfiguration.Spec.PrometheusMetricsPort
		}

		nodePrometheusTLS, err = certificateManager.GetOrCreateKeyPair(r.client, render.NodePrometheusTLSServerSecret, common.OperatorNamespace(), dns.GetServiceDNSNames(render.CalicoNodeMetricsService, common.CalicoNamespace, r.clusterDomain))
		if err != nil {
			r.status.SetDegraded(operator.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}
		if nodePrometheusTLS != nil {
			typhaNodeTLS.TrustedBundle.AddCertificates(nodePrometheusTLS)
		}
		prometheusClientCert, err := certificateManager.GetCertificate(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operator.CertificateError, "Unable to fetch prometheus certificate", err, reqLogger)
			return reconcile.Result{}, err
		}
		if prometheusClientCert != nil {
			typhaNodeTLS.TrustedBundle.AddCertificates(prometheusClientCert)
		}

		// es-kube-controllers needs to trust the ESGW certificate. We'll fetch it here and add it to the trusted bundle.
		// Note that although we're adding this to the typhaNodeTLS trusted bundle, it will be used by es-kube-controllers. This is because
		// all components within this namespace share a trusted CA bundle. This is necessary because prior to v3.13 secrets were not signed by
		// a single CA so we need to include each individually.
		esgwCertificate, err := certificateManager.GetCertificate(r.client, relasticsearch.PublicCertSecret, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operator.CertificateError, fmt.Sprintf("Failed to retrieve / validate  %s", relasticsearch.PublicCertSecret), err, reqLogger)
			return reconcile.Result{}, err
		}
		if esgwCertificate != nil {
			typhaNodeTLS.TrustedBundle.AddCertificates(esgwCertificate)
		}

		calicoVersion = components.EnterpriseRelease
	}

	kubeControllersMetricsPort, err := utils.GetKubeControllerMetricsPort(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Unable to read KubeControllersConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Secure calico kube controller metrics.
	var kubeControllerTLS certificatemanagement.KeyPairInterface
	if instance.Spec.Variant == operator.TigeraSecureEnterprise {
		// Create or Get TLS certificates for kube controller.
		kubeControllerTLS, err = certificateManager.GetOrCreateKeyPair(
			r.client,
			kubecontrollers.KubeControllerPrometheusTLSSecret,
			common.OperatorNamespace(),
			dns.GetServiceDNSNames(kubecontrollers.KubeControllerMetrics, common.CalicoNamespace, r.clusterDomain))
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error finding or creating TLS certificate kube controllers metric", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Add prometheus client certificate to Trusted bundle.
		kubecontrollerprometheusTLS, err := certificateManager.GetCertificate(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Failed to get certificate for kube controllers", err, reqLogger)
			return reconcile.Result{}, err
		} else if kubecontrollerprometheusTLS != nil {
			typhaNodeTLS.TrustedBundle.AddCertificates(kubeControllerTLS, kubecontrollerprometheusTLS)
		}
	}

	// If configured to connect to Calico Cloud, ensure the trusted bundle includes the Calico Cloud CA.
	// TODO: make this conditional on whether we are configured to connect to CC.
	// TODO: trusted bundle managed in both this controller and guardian controller???
	linseedCertName := render.VoltronLinseedPublicCert
	linseedCertNamespace := common.OperatorNamespace()
	linseedCertificate, err := certificateManager.GetCertificate(r.client, linseedCertName, linseedCertNamespace)
	if err != nil && !apierrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("Failed to retrieve / validate  %s/%s", linseedCertNamespace, linseedCertName), err, reqLogger)
		return reconcile.Result{}, err
	}
	if linseedCertificate != nil {
		log.Info("Adding Linseed certificate to trusted bundle")
		typhaNodeTLS.TrustedBundle.AddCertificates(linseedCertificate)
	}

	nodeAppArmorProfile := ""
	a := instance.GetObjectMeta().GetAnnotations()
	if val, ok := a[techPreviewFeatureSeccompApparmor]; ok {
		nodeAppArmorProfile = val
	}

	components := []render.Component{}

	namespaceCfg := &render.NamespaceConfiguration{
		Installation: &instance.Spec,
		PullSecrets:  pullSecrets,
	}
	// Render namespaces for Calico.
	components = append(components, render.Namespaces(namespaceCfg))

	if newActiveCM != nil && !installationMarkedForDeletion {
		log.Info("adding active configmap")
		components = append(components, render.NewPassthrough(newActiveCM))
	}

	// If we're on OpenShift on AWS render a Job (and needed resources) to
	// setup the security groups we need for IPIP, BGP, and Typha communication.
	if openShiftOnAws {
		// Detect if this cluster is an OpenShift HPC hosted cluster, as AWS
		// security group setup is different in this case.
		hostedOpenShift, err := isHostedOpenShift(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error checking if in a hosted OpenShift HCP cluster on AWS", err, reqLogger)
			return reconcile.Result{}, err
		}
		awsSGSetupCfg := &render.AWSSGSetupConfiguration{
			PullSecrets:     instance.Spec.ImagePullSecrets,
			Installation:    &instance.Spec,
			HostedOpenShift: hostedOpenShift,
		}
		awsSetup, err := render.AWSSecurityGroupSetup(awsSGSetupCfg)
		if err != nil {
			// If there is a problem rendering this do not degrade or stop rendering
			// anything else.
			log.Info(err.Error())
		} else {
			components = append(components, awsSetup)
		}
	}

	if instance.Spec.KubernetesProvider.IsGKE() {
		// We do this only for GKE as other providers don't (yet?)
		// automatically add resource quota that constrains whether
		// Calico components that are marked cluster or node critical
		// can be scheduled.
		criticalPriorityClasses := []string{render.NodePriorityClassName, render.ClusterPriorityClassName}
		resourceQuotaObj := resourcequota.ResourceQuotaForPriorityClassScope(resourcequota.CalicoCriticalResourceQuotaName,
			common.CalicoNamespace, criticalPriorityClasses)
		resourceQuotaComponent := render.NewPassthrough(resourceQuotaObj)
		components = append(components, resourceQuotaComponent)

	}

	components = append(components,
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       common.CalicoNamespace,
			ServiceAccounts: []string{render.CalicoNodeObjectName, render.TyphaServiceAccountName, kubecontrollers.KubeControllerServiceAccount},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(typhaNodeTLS.NodeSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(nodePrometheusTLS, true, true),
				rcertificatemanagement.NewKeyPairOption(typhaNodeTLS.TyphaSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(kubeControllerTLS, true, true),
			},
			TrustedBundle: typhaNodeTLS.TrustedBundle,
		}))

	// Build a configuration for rendering calico/typha.
	typhaCfg := render.TyphaConfiguration{
		K8sServiceEp:      k8sapi.Endpoint,
		Installation:      &instance.Spec,
		TLS:               typhaNodeTLS,
		MigrateNamespaces: needNsMigration,
		ClusterDomain:     r.clusterDomain,
		FelixHealthPort:   *felixConfiguration.Spec.HealthPort,
	}
	components = append(components, render.Typha(&typhaCfg))

	// See the section 'Use of Finalizers for graceful termination' at the top of this file for terminating details.
	canRemoveCNI := false
	if installationMarkedForDeletion {
		// Wait for other controllers to complete their finalizer teardown before removing the CNI plugin.
		canRemoveCNI = true
		for _, f := range instance.Finalizers {
			if f != render.OperatorCompleteFinalizer {
				reqLogger.Info("Waiting for finalization to complete before removing CNI resources", "finalizer", f)
				canRemoveCNI = false
			}
		}
	} else {
		// In some rare scenarios, we can hit a deadlock where resources have been marked with a deletion timestamp but the operator
		// does not recognize that it must remove their finalizers. This can happen if, for example, someone manually
		// deletes a ServiceAccount instead of deleting the Installation object. In this case, we need
		// to allow the deletion to complete so the operator can re-create the resources. Otherwise the objects will be stuck terminating forever.
		toCheck := render.CNIPluginFinalizedObjects()
		needsCleanup := []client.Object{}
		for _, obj := range toCheck {
			if err := r.client.Get(ctx, types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}, obj); err != nil {
				if !apierrors.IsNotFound(err) {
					r.status.SetDegraded(operator.ResourceReadError, "Error querying object", err, reqLogger)
					return reconcile.Result{}, err
				}
				// Not found - nothing to do.
				continue
			}
			if obj.GetDeletionTimestamp() != nil {
				// The object is marked for deletion, but the installation is not terminating. We need to remove the finalizers from this object
				// so that it can be deleted and recreated.
				reqLogger.Info("Object is marked for deletion but installation is not terminating",
					"kind", obj.GetObjectKind(),
					"name", obj.GetName(),
					"namespace", obj.GetNamespace(),
				)
				obj.SetFinalizers(stringsutil.RemoveStringInSlice(render.CNIFinalizer, obj.GetFinalizers()))
				needsCleanup = append(needsCleanup, obj)
			}
		}
		if len(needsCleanup) > 0 {
			// Add a component to remove the finalizers from the objects that need it.
			reqLogger.Info("Removing finalizers from objects that are wronly marked for deletion")
			components = append(components, render.NewPassthrough(needsCleanup...))
		}
	}

	// Fetch any existing default BGPConfiguration object.
	bgpConfiguration := &crdv1.BGPConfiguration{}
	err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfiguration)
	if err != nil && !apierrors.IsNotFound(err) {
		r.status.SetDegraded(operator.ResourceReadError, "Unable to read BGPConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Build a configuration for rendering calico/node.
	nodeCfg := render.NodeConfiguration{
		K8sServiceEp:                  k8sapi.Endpoint,
		Installation:                  &instance.Spec,
		IPPools:                       crdPoolsToOperator(currentPools.Items),
		LogCollector:                  logCollector,
		BirdTemplates:                 birdTemplates,
		TLS:                           typhaNodeTLS,
		ClusterDomain:                 r.clusterDomain,
		NodeReporterMetricsPort:       nodeReporterMetricsPort,
		BGPLayouts:                    bgpLayout,
		NodeAppArmorProfile:           nodeAppArmorProfile,
		MigrateNamespaces:             needNsMigration,
		CanRemoveCNIFinalizer:         canRemoveCNI,
		PrometheusServerTLS:           nodePrometheusTLS,
		FelixHealthPort:               *felixConfiguration.Spec.HealthPort,
		BindMode:                      bgpConfiguration.Spec.BindMode,
		FelixPrometheusMetricsEnabled: utils.IsFelixPrometheusMetricsEnabled(felixConfiguration),
		FelixPrometheusMetricsPort:    felixPrometheusMetricsPort,
	}
	components = append(components, render.Node(&nodeCfg))

	csiCfg := render.CSIConfiguration{
		Installation: &instance.Spec,
		Terminating:  installationMarkedForDeletion,
		OpenShift:    instance.Spec.KubernetesProvider.IsOpenShift(),
	}
	components = append(components, render.CSI(&csiCfg))

	// Build a configuration for rendering calico/kube-controllers.
	kubeControllersCfg := kubecontrollers.KubeControllersConfiguration{
		K8sServiceEp:                k8sapi.Endpoint,
		Installation:                &instance.Spec,
		ManagementCluster:           managementCluster,
		ManagementClusterConnection: managementClusterConnection,
		ClusterDomain:               r.clusterDomain,
		MetricsPort:                 kubeControllersMetricsPort,
		Terminating:                 installationMarkedForDeletion,
		MetricsServerTLS:            kubeControllerTLS,
		TrustedBundle:               typhaNodeTLS.TrustedBundle,
		Namespace:                   common.CalicoNamespace,
		BindingNamespaces:           []string{common.CalicoNamespace},
	}
	components = append(components, kubecontrollers.NewCalicoKubeControllers(&kubeControllersCfg))

	// v3 NetworkPolicy will fail to reconcile if the API server deployment is unhealthy. In case the API Server
	// deployment becomes unhealthy and reconciliation of non-NetworkPolicy resources in the core controller
	// would resolve it, we render the network policies of components last to prevent a chicken-and-egg scenario.
	if includeV3NetworkPolicy {
		components = append(components,
			kubecontrollers.NewCalicoKubeControllersPolicy(&kubeControllersCfg),
			render.NewPassthrough(networkpolicy.AllowTigeraDefaultDeny(common.CalicoNamespace)),
		)
	}

	imageSet, err := imageset.GetImageSet(ctx, r.client, instance.Spec.Variant)
	if err != nil {
		r.status.SetDegraded(operator.ResourceReadError, "Error getting ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if imageSet == nil {
		// There is no imageSet for the configured variant, but check to see if there are any
		// ImageSets with a different variant so we can give the user some kind of indication
		// to why an existing ImageSet is being ignored.
		nvis, err := imageset.DoesNonVariantImageSetExist(ctx, r.client, instance.Spec.Variant)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Error checking for non-variant ImageSet", err, reqLogger)
			return reconcile.Result{}, err
		} else {
			if nvis {
				reqLogger.Info("An ImageSet exists for a different variant")
			}
		}
	}

	if err = imageset.ValidateImageSet(imageSet); err != nil {
		r.status.SetDegraded(operator.ResourceValidationError, "Error validating ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ResolveImages(imageSet, components...); err != nil {
		r.status.SetDegraded(operator.ResourceValidationError, "Error resolving ImageSet for components", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a component handler to create or update the rendered components.
	handler := r.newComponentHandler(log, r.client, r.scheme, instance)
	for _, component := range components {
		if err := handler.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
			r.status.SetDegraded(operator.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// TODO: We handle too many components in this controller at the moment. Once we are done consolidating,
	// we can have the CreateOrUpdate logic handle this for us.
	r.status.AddDaemonsets([]types.NamespacedName{{Name: common.NodeDaemonSetName, Namespace: common.CalicoNamespace}})
	r.status.AddDeployments([]types.NamespacedName{{Name: common.KubeControllersDeploymentName, Namespace: common.CalicoNamespace}})
	certificateManager.AddToStatusManager(r.status, common.CalicoNamespace)

	// Run this after we have rendered our components so the new (operator created)
	// Deployments and Daemonset exist with our special migration nodeSelectors.
	if needNsMigration {
		if err := r.namespaceMigration.Run(ctx, reqLogger); err != nil {
			r.status.SetDegraded(operator.ResourceMigrationError, "error migrating resources to calico-system", err, reqLogger)
			// We should always requeue a migration problem. Don't return error
			// to make sure we never start backing off retrying.
			return reconcile.Result{Requeue: true}, nil
		}
		// Requeue so we can update our resources (without the migration changes)
		return reconcile.Result{Requeue: true}, nil
	} else if r.namespaceMigration.NeedCleanup() {
		if err := r.namespaceMigration.CleanupMigration(ctx, reqLogger); err != nil {
			r.status.SetDegraded(operator.ResourceMigrationError, "error migrating resources to calico-system", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Determine which MTU to use in the status fields.
	statusMTU := 0
	if instance.Spec.CalicoNetwork != nil && instance.Spec.CalicoNetwork.MTU != nil {
		// If set explicitly in the spec, then use that.
		statusMTU = int(*instance.Spec.CalicoNetwork.MTU)
	} else if calicoDirectoryExists() {
		// Otherwise, if the /var/lib/calico directory is present, see if we can read
		// a value from there.
		statusMTU, err = readMTUFile()
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "error reading network MTU", err, reqLogger)
			return reconcile.Result{}, err
		}
	} else {
		// If neither is present, then we don't have MTU information available.
		// Auto-detection will still be used for Calico, but the operator won't know
		// what the value is.
		reqLogger.V(1).Info("Unable to determine MTU - no explicit config, and /var/lib/calico is not mounted")
	}

	// We have successfully reconciled the Calico installation.
	if instance.Spec.KubernetesProvider.IsOpenShift() {
		openshiftConfig := &configv1.Network{}
		err = r.client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig)
		if err != nil {
			r.status.SetDegraded(operator.ResourceReadError, "Unable to update OpenShift Network config: failed to read OpenShift network configuration", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Get resource before updating to use in the Patch call.
		patchFrom := client.MergeFrom(openshiftConfig.DeepCopy())

		// Update the config status with the current state.
		reqLogger.WithValues("openshiftConfig", openshiftConfig).V(1).Info("Updating OpenShift cluster network status")
		openshiftConfig.Status.ClusterNetwork = openshiftConfig.Spec.ClusterNetwork
		openshiftConfig.Status.ServiceNetwork = openshiftConfig.Spec.ServiceNetwork
		openshiftConfig.Status.NetworkType = "Calico"
		openshiftConfig.Status.ClusterNetworkMTU = statusMTU

		if err = r.client.Patch(ctx, openshiftConfig, patchFrom); err != nil {
			r.status.SetDegraded(operator.ResourcePatchError, "Error patching openshift network status", err, reqLogger.WithValues("openshiftConfig", openshiftConfig))
			return reconcile.Result{}, err
		}
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	// If eBPF is enabled in the operator API, patch FelixConfiguration to enable it within Felix.
	_, err = utils.PatchFelixConfiguration(ctx, r.client, func(fc *crdv1.FelixConfiguration) (bool, error) {
		return r.setBPFUpdatesOnFelixConfiguration(ctx, instance, fc, reqLogger)
	})
	if err != nil {
		r.status.SetDegraded(operator.ResourceUpdateError, "Error updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	// We can clear the degraded state now since as far as we know everything is in order.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Write updated status.
	if statusMTU > math.MaxInt32 || statusMTU < 0 {
		return reconcile.Result{}, errors.New("the MTU size should be between Max int32 (2147483647) and 0")
	}
	instance.Status.MTU = int32(statusMTU)
	// Variant and CalicoVersion must be updated at the same time.
	instance.Status.Variant = instance.Spec.Variant
	instance.Status.CalicoVersion = calicoVersion
	if imageSet == nil {
		instance.Status.ImageSet = ""
	} else {
		instance.Status.ImageSet = imageSet.Name
	}
	instance.Status.Computed = &instance.Spec
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}

	reqLogger.V(1).Info("Finished reconciling Installation")
	return reconcile.Result{}, nil
}

func (r *CalicoSystemBundleController) upstreamCertificates(cm certificatemanager.CertificateManager) ([]certificatemanagement.CertificateInterface, error) {
	toQuery := map[string]string{
		// By default, we only need the operator's CA cert.
		certificatemanagement.CASecretName: common.OperatorNamespace(),
	}

	if r.elasticExternal {
		// If configured to use external Elasticsearch, get the Elasticsearch public certs.
		toQuery[logstorage.ExternalESPublicCertName] = common.OperatorNamespace()
	}

	// Query each certificate.
	certs := []certificatemanagement.CertificateInterface{}
	for name, namespace := range toQuery {
		if cert, err := cm.GetCertificate(r.client, name, namespace); err != nil {
			return nil, fmt.Errorf("error querying certificate %s/%s: %w", namespace, name, err)
		} else if cert == nil {
			return nil, fmt.Errorf("certificate %s/%s not found", namespace, name)
		} else {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}
