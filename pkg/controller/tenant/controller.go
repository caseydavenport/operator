// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/go-logr/logr"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/compliance"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rtenant "github.com/tigera/operator/pkg/render/tenant"
	"k8s.io/apimachinery/pkg/api/errors"
)

var log = logf.Log.WithName("controller_tenant")

func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	ri, err := newReconciler(mgr, opts)
	if err != nil {
		return fmt.Errorf("failed to create tenant Reconciler: %w", err)
	}

	c, err := controller.New("tigera-tenant-controller", mgr, controller.Options{Reconciler: ri})
	if err != nil {
		return fmt.Errorf("Failed to create tigera-tenant-controller: %w", err)
	}

	return add(c, ri)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions) (*Reconcile, error) {
	statusManager := status.New(mgr.GetClient(), "calico", opts.KubernetesVersion)
	r := &Reconcile{
		config:              mgr.GetConfig(),
		client:              mgr.GetClient(),
		scheme:              mgr.GetScheme(),
		status:              statusManager,
		enterpriseCRDsExist: opts.EnterpriseCRDExists,
		clusterDomain:       opts.ClusterDomain,
		usePSP:              opts.UsePSP,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

// add adds watches for resources that are available at startup
func add(c controller.Controller, r *Reconcile) error {
	// Watch for changes to primary resource Tenant
	err := c.Watch(&source.Kind{Type: &operator.Tenant{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-tenant-controller failed to watch primary resource: %w", err)
	}

	// Watch for secrets in the operator namespace. We watch for all secrets, since we care
	// about specifically named ones as well as image pull secrets that
	// may have been provided by the user with arbitrary names.
	err = utils.AddSecretsWatch(c, "", common.OperatorNamespace())
	if err != nil {
		return fmt.Errorf("tigera-tenant-controller failed to watch secrets: %w", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("tigera-tenant-controller failed to watch ImageSet: %w", err)
	}

	// Watch for changes to primary resource ManagementCluster
	err = c.Watch(&source.Kind{Type: &operator.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-tenant-controller failed to watch primary resource: %v", err)
	}

	// Watch the internal manager TLS secret in the calico namespace, where it's copied for kube-controllers.
	if err = utils.AddSecretsWatch(c, render.ManagerInternalTLSSecretName, common.CalicoNamespace); err != nil {
		return fmt.Errorf("tigera-tenant-controller failed to watch secret '%s' in '%s' namespace: %w", render.ManagerInternalTLSSecretName, common.OperatorNamespace(), err)
	}

	return nil
}

var _ reconcile.Reconciler = &Reconcile{}

// Reconcile reconciles a Tenant object
type Reconcile struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	config              *rest.Config
	client              client.Client
	scheme              *runtime.Scheme
	status              status.StatusManager
	enterpriseCRDsExist bool
	clusterDomain       string
	usePSP              bool
}

func (r *Reconcile) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling Tenant.operator.tigera.io")

	// Get ManagementCluster object.
	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.SetDegraded(operator.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}
	if managementCluster == nil {
		return reconcile.Result{}, nil
	}

	// List all Tenant objects.
	tenants := operator.TenantList{}
	if err := r.client.List(ctx, &tenants); err != nil {
		r.SetDegraded(operator.ResourceReadError, "Error reading tenants", err, reqLogger)
		return reconcile.Result{}, err
	}

	_, installation, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	// Mark CR found so we can report converter problems via tigerastatus
	r.status.OnCRFound()

	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("License not found", err.Error())
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}
		r.status.SetDegraded("Error querying license", err.Error())
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Query for pull secrets in operator namespace
	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		r.SetDegraded(operator.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Build a trusted cert bundle. This is used for TODO
	certificateManager, err := certificatemanager.Create(r.client, installation, r.clusterDomain)
	if err != nil {
		r.SetDegraded(operator.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	trustedBundle := certificateManager.CreateTrustedBundle()

	compliance, err := compliance.GetCompliance(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(string(operator.ResourceReadError), fmt.Sprintf("Error querying compliance: %s", err.Error()))
		return reconcile.Result{}, err
	}

	esSecrets, err := utils.ElasticsearchSecrets(ctx, []string{render.ElasticsearchManagerUserSecret}, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Elasticsearch secrets are not available yet, waiting until they become available", err.Error())
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Failed to get Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	// Fetch the Authentication spec. If present, we use to configure user authentication.
	trustedSecretNames := []string{}
	authenticationCR, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded("Error while fetching Authentication", err.Error())
		return reconcile.Result{}, err
	}
	if authenticationCR != nil && authenticationCR.Status.State != operator.TigeraStatusReady {
		r.status.SetDegraded("Authentication is not ready", fmt.Sprintf("authenticationCR status: %s", authenticationCR.Status.State))
		return reconcile.Result{}, nil
	} else if authenticationCR != nil {
		trustedSecretNames = append(trustedSecretNames, render.DexTLSSecretName)
	}
	for _, secretName := range trustedSecretNames {
		certificate, err := certificateManager.GetCertificate(r.client, secretName, common.OperatorNamespace())
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("failed to retrieve %s", secretName))
			r.status.SetDegraded(fmt.Sprintf("Failed to retrieve %s", secretName), err.Error())
			return reconcile.Result{}, err
		} else if certificate == nil {
			reqLogger.Info(fmt.Sprintf("Waiting for secret '%s' to become available", secretName))
			r.status.SetDegraded(fmt.Sprintf("Waiting for secret '%s' to become available", secretName), "")
			return reconcile.Result{}, nil
		}
		trustedBundle.AddCertificates(certificate)
	}

	keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.clusterDomain)
	if err != nil {
		log.Error(err, "Failed to process the authentication CR.")
		r.status.SetDegraded("Failed to process the authentication CR.", err.Error())
		return reconcile.Result{}, err
	}

	tunnelSecret, err := certificateManager.GetKeyPair(r.client, render.VoltronTunnelSecretName, common.OperatorNamespace())
	if tunnelSecret == nil {
		r.status.SetDegraded(fmt.Sprintf("Waiting for secret %s in namespace %s to be available", render.VoltronTunnelSecretName, common.OperatorNamespace()), "")
		return reconcile.Result{}, err
	} else if err != nil {
		r.status.SetDegraded(fmt.Sprintf("Error fetching TLS secret %s in namespace %s", render.VoltronTunnelSecretName, common.OperatorNamespace()), err.Error())
		return reconcile.Result{}, nil
	}

	// We expect that the secret that holds the certificates for internal communication within the management
	// K8S cluster is already created by the KubeControllers
	internalTrafficSecret, err := certificateManager.GetKeyPair(r.client, render.ManagerInternalTLSSecretName, common.OperatorNamespace())
	if internalTrafficSecret == nil {
		r.status.SetDegraded(fmt.Sprintf("Waiting for secret %s in namespace %s to be available", render.ManagerInternalTLSSecretName, common.OperatorNamespace()), "")
		return reconcile.Result{}, err
	} else if err != nil {
		r.status.SetDegraded(fmt.Sprintf("Error fetching TLS secret %s in namespace %s", render.ManagerInternalTLSSecretName, common.OperatorNamespace()), err.Error())
		return reconcile.Result{}, nil
	}

	// Es-proxy needs to trust Voltron for cross-cluster requests.
	trustedBundle.AddCertificates(internalTrafficSecret)

	esClusterConfig, err := utils.GetElasticsearchClusterConfig(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch cluster configuration is not available, waiting for it to become available")
			r.status.SetDegraded("Elasticsearch cluster configuration is not available, waiting for it to become available", err.Error())
			return reconcile.Result{}, nil
		}
		log.Error(err, "Failed to get the elasticsearch cluster configuration")
		r.status.SetDegraded("Failed to get the elasticsearch cluster configuration", err.Error())
		return reconcile.Result{}, err
	}

	imageSet, err := imageset.GetImageSet(ctx, r.client, installation.Variant)
	if err != nil {
		r.SetDegraded(operator.ResourceReadError, "Error getting ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	// For each tenant, render the necessary objects.
	one := int32(1)
	for _, t := range tenants.Items {
		ns := fmt.Sprintf("tenant-%s", t.Name) // TODO: Duplicated in render pkg
		svcDNSNames := append(dns.GetServiceDNSNames(rtenant.VoltronName, ns, r.clusterDomain), "localhost")
		tlsSecret, err := certificateManager.GetOrCreateKeyPair(
			r.client,
			render.ManagerTLSSecretName,
			common.OperatorNamespace(),
			svcDNSNames)
		if err != nil {
			r.status.SetDegraded("Error getting or creating manager TLS certificate", err.Error())
			return reconcile.Result{}, err
		}

		cfg := rtenant.Configuration{
			Tenant:            &t,
			Installation:      installation,
			ManagementCluster: managementCluster,
			Compliance:        compliance,

			Openshift:     installation.KubernetesProvider == operator.ProviderOpenShift,
			ClusterDomain: r.clusterDomain,

			PullSecrets:           pullSecrets,
			ESSecrets:             esSecrets,
			KeyValidatorConfig:    keyValidatorConfig,
			TrustedCertBundle:     trustedBundle,
			TLSKeyPair:            tlsSecret,
			TunnelSecret:          tunnelSecret,
			InternalTrafficSecret: internalTrafficSecret,
			ESClusterConfig:       esClusterConfig,

			Replicas:                &one,
			ComplianceLicenseActive: utils.IsFeatureActive(license, common.ComplianceFeature),
			UsePSP:                  r.usePSP,
		}

		// Render the tenants objects.
		handler := utils.NewComponentHandler(log, r.client, r.scheme, &t)
		component, err := rtenant.Tenant(&cfg)
		if err != nil {
			r.status.SetDegraded("Failed to render tenant", err.Error())
			return reconcile.Result{}, err
		}

		if err = imageset.ResolveImages(imageSet, component); err != nil {
			r.SetDegraded(operator.ResourceValidationError, "Error resolving ImageSet for components", err, reqLogger)
			return reconcile.Result{}, err
		}

		if err := handler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded("Error creating / updating tenant", err.Error())
			return reconcile.Result{}, err
		}
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	// We can clear the degraded state now since as far as we know everything is in order.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Created successfully. Requeue anyway so that we perform periodic reconciliation.
	// This acts as a backstop to catch reconcile issues, and also makes sure we spot when
	// things change that might not trigger a reconciliation.
	reqLogger.V(1).Info("Finished reconciling network tenant")
	return reconcile.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *Reconcile) SetDegraded(reason operator.TigeraStatusReason, message string, err error, log logr.Logger) {
	log.WithValues(string(reason), message).Error(err, string(reason))
	errormsg := ""
	if err != nil {
		errormsg = err.Error()
	}
	r.status.SetDegraded(string(reason), fmt.Sprintf("%s - Error: %s", message, errormsg))
}
