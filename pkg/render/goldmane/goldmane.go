// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package goldmane

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/ptr"
)

type Configuration struct {
	Installation *operatorv1.InstallationSpec
}

type goldmane struct {
	cfg *Configuration
}

func New(cfg *Configuration) render.Component {
	return &goldmane{
		cfg: cfg,
	}
}

// ResolveImages should call components.GetReference for all images that the Component
// needs, passing 'is' to the GetReference call and if there are any errors those
// are returned. It is valid to pass nil for 'is' as GetReference accepts the value.
// ResolveImages must be called before Objects is called for the component.
func (g *goldmane) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

// Objects returns the lists of objects in this component that should be created and/or deleted during
// rendering.
func (g *goldmane) Objects() (objsToCreate []client.Object, objsToDelete []client.Object) {
	serviceaccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "goldmane",
			Namespace: common.CalicoNamespace,
		},
	}

	clusterRole := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "goldmane",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}

	clusterRoleBinding := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "goldmane",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceaccount.Name,
				Namespace: serviceaccount.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     clusterRole.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	deployment := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "goldmane",
			Namespace: common.CalicoNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.Int32ToPtr(1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "goldmane"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"k8s-app": "goldmane"},
				},
				Spec: corev1.PodSpec{
					Tolerations:        rmeta.TolerateAll,
					ImagePullSecrets:   g.cfg.Installation.ImagePullSecrets,
					ServiceAccountName: serviceaccount.Name,
					Containers:         []corev1.Container{g.container()},
				},
			},
		},
	}

	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "goldmane",
			Namespace: deployment.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: deployment.Spec.Template.ObjectMeta.Labels,
			Ports:    []corev1.ServicePort{{Port: 443}},
		},
	}

	return []client.Object{
		&serviceaccount,
		&clusterRole,
		&clusterRoleBinding,
		&deployment,
		&svc,
	}, nil
}

func (g *goldmane) container() corev1.Container {
	return corev1.Container{
		Name:            "goldmane",
		Image:           "caseydavenport/goldmane:latest",
		ImagePullPolicy: render.ImagePullPolicy(),
	}
}

// Ready returns true if the component is ready to be created.
func (g *goldmane) Ready() bool {
	return true
}

// SupportedOSTypes returns operating systems that is supported of the components returned by the Objects() function.
// The "componentHandler" converts the returned OSTypes to a node selectors for the "kubernetes.io/os" label on client.Objects
// that create pods. Return OSTypeAny means that no node selector should be set for the "kubernetes.io/os" label.
func (g *goldmane) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
