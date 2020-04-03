

## :package: Other

- 0690043 Merge pull request #484 from rafaelvanoni/rafael-release-v1.4-1

[cherry-pick] Operator: Customize rolling update parameters
- 3da691f Merge pull request #482 from tmjd/pick458-r1.4

[Pick 458] Pick HostPorts (portmap) configuration
- e0b654f Merge pull request #479 from tmjd/fix-git-ver-r1.4

Fix GIT_VERSION in makefile
- 9d9b415 Update operator CRDs based on release-v1.4 branch (#478)


- 95e1b98 Updating Calico Enterprise versions for release-v1.4 (#476)

* Updating Calico Enterprise versions for release-v1.4
* Updating OS versions to v3.13.1 for Calico Enterprise versions for release-v1.4
* Fixing wrong versions (should not have hash suffix).
* Fixing bad SHAs for Enterprise images, fixing broken images tests.
* Fixing borked tests.
- 589c65a Fix role (#472)


- 6fd2f6a Merge pull request #477 from tmjd/fix-pin-r1.4

Fix cloud-on-k8s pin
- 3e836af adding DNS logs to flow to splunk (#470)


- c5ef2fc Merge pull request #467 from hstern/cnx-12314-1.4

CNX-12314: Swap GlobalAlert Summary and Description in templates
- 6d46787 Adding doc for unsupported annotation. (#395)

* Adding doc for unsupported annotation.

* Update README.md

* Update README.md

* Update README.md
- 494d171 Merge pull request #457 from doublek/tech-preview-admission-control

Move admission controller support behind a tech-preview feature flag
- 8d1a972 Merge pull request #449 from tmjd/remove-crds-from-operator-install

CRD removal from operator
- ab58906 Merge pull request #455 from caseydavenport/casey-fix-metrics-port

Fix nodeMetricsPort to adjust correct setting
- 27563e5 Update the ECK operator to v1.0.1 (#450)

* Remove lingering webhook created by eck when clustertype -> managed

* Remove lingering webhook created by eck when clustertype -> managed

* Replace ECK alpha with ECK GA

* Add some comments for clarity.

* Add Elastic's CRD's to our repo

* Update outdated eck version

* Improve comment explaining ECK trial.

* Add rbac permission for operator

* Set kube-controllers to latest.
- be699d0 Merge pull request #453 from doublek/apiserver-webhook-reader

Add RBAC for the apiserver to read webhook configurations
- 1225e0b Merge pull request #430 from penkeysuresh/splunk-ga

making changes to enable splunk as log destination
- dab4d5f Merge pull request #447 from tmjd/add-version-override

Add override for git version
- bb20503 Merge pull request #445 from tmjd/go-sum-up-tigera-api

Update go.sum with tigera/api change
- e8cf0c2 Merge pull request #446 from hstern/cnx-12079

CNX-11995: Make GlobalAlertTemplate.Summary optional
- b9f428c Merge pull request #444 from tmjd/release-notes

Update release notes
- a8ed821 Merge pull request #436 from tmjd/test-branch

Fix building
- 53789ac Merge pull request #440 from hstern/cnx-11995

CNX-11995: Make GlobalAlertTemplate.Summary optional
- b097c74 Merge pull request #439 from caseydavenport/run-gen-versions

Run gen-versions
- d42caaa Merge pull request #438 from caseydavenport/include-rbac-configmaps

Include RBAC for accessing configmaps
- ed69adc Merge pull request #433 from manojah99/master

CNX-11540: added summary spec
- 290d101 Merge pull request #403 from tmjd/img-path-config

Adding image path config
- 0d6b932 custom FlexVolume path (#417)

* WIP: custom FlexVolume path

* Erik's code review

* Make gen-files

* Add render UT for when FlexVolumePath is set to None

* Move FlexVolumePath out of CalicoNetwork

* Check if a user specified FlexVolumePath is valid

* Fix

* Fix (2)

* Regex for absolute path, move validation to validation.go

* Fix

* Move check for relative path to validation{_test}.go

* Fixes for field validation

* Fix missing FlexVolumePath parameter in validation_test.go

* Fix comment

- 6f8e598 Merge pull request #413 from Brian-McM/bm-add-kibana-external-service

Create ExternalService for Kibana if the cluster type is Managed
- b3ad786 Merge pull request #420 from gianlucam76/bgp-rbac

calico-node clusterrole: add secrets permissions
- 3681dc1 Merge pull request #419 from tmjd/component-ignore-flag

Ignore some old components that are still in some version files
- 64ce919 Merge pull request #392 from sebrandon1/disable_flexvol

Add toggle for FlexVol init container
- 24bdc3d dont panic on unexpected genversion data (#406)


- b656343 Merge pull request #393 from tmjd/migration-patch-fix

Migration patch fix
- cbc9d18 Change the token key name to token instead of access_token for digest lookups on elasticsearch (#400)


- 752832b Merge pull request #402 from Brian-McM/bm-update-intrusion-detection

Update intrusion detection image to newest and use correct on for con…
- 2c5bb5e Merge pull request #401 from Brian-McM/bm-fix-kibana-version

Use eck kibana version for kibana version
- 756c98c Merge pull request #399 from Brian-McM/bm-update-kube-controller-version

Update kube controller version
- 34ed74a Merge pull request #398 from Brian-McM/bm-fix-es-and-kibana-versioning

Use component Version instead of Digest for Elasticsearch and Kibana …
- efcb4ac Merge pull request #390 from Brian-McM/bm-combine-managed-and-management-cluster-logic

Combine Management /  Managed cluster logic for LogStorage at the con…
- b4a0c2c gather digests of images (#378)

* enhance gen-versions to include digests

* cleanup flag pointers

* handle operatorInit genversion

* clean ci

* fix ze tests

* flip digest ref on

* fix operator-init

* cleanup components print

* code review

- 3ddcbc5 accept empty string for installation.spec.kubernetesProvider (#394)


- 713f0fe Merge pull request #374 from caseydavenport/casey-support-blocksize

Support configuring block size on IP pools
- a090ba9 add configurable controlPlaneNodeSelector (#381)

* operator installation node selector

* Update gen-files

- 5647531 add configurable node metrics port (#371)

* WIP: add configurable node metrics port

* Fixes

* Fixes

* Add UTs

* Update pkg/apis/operator/v1/types.go

Co-Authored-By: Dan (Turk) Osborne <dan@projectcalico.org>

* Partial code review fixes

* nodeMetricsPort() changes

* Casey's code review

Co-authored-by: Dan (Turk) Osborne <dan@projectcalico.org>

- a88708d Remove compliance server. Add test suite for compliance. (#382)

* Remove compliance server. Add test suite for compliance.

* Taken up on suggested test improvements by Brian

* Use Rafael's new delete functionality to remove unwanted objects.

- fc76ce9 Change render.Component.Objects() to return two object slices (#386)

* Change render.Component.Objects() to return two object slices

* Rene's code review

* Casey's code review

* nit

* nit

- 8398ba8 Merge pull request #383 from tmjd/ent-iptables-auto

iptables backend detection is updated in TigeraSecureEnterprise
- bb7b953 Merge pull request #377 from Brian-McM/bm-dont-overwrite-es-or-kb-statuses

Don't overwrite Elasticsearch or Kibana CR statuses on update
- 274f091 Merge pull request #376 from tmjd/pick-375-to-master

Pick 375: For Openshift install put CNI config where multus expects
- b9cfafd Merge pull request #373 from Brian-McM/bm-change-StatusManager-to-interface

Change StatusManager type to interface
- 86d644c Merge pull request #369 from tmjd/fix-dns-service-for-openshift

Update OpenShift dns service to correct name
- a4fc58d Merge pull request #367 from Brian-McM/CNX-11672-increase-eck-operator-memory

(CNX-11672) Increase eck operator memory to prevent OCP OOMKILL
- dfb939b Create sa and rbac for managed cluster's compliance server, so it can… (#365)

* Create sa and rbac for managed cluster's compliance server, so it can check rbac

* Add extra rbac role. Move compliance-server resources out of else{}

* Improved explanation in comment

- 4fd8b84 Merge pull request #362 from Brian-McM/bm-copy-over-pull-secret-to-guardian-namespace

Copy over pull secret to guardian namespace
- 1fc7f0f Merge pull request #360 from caseydavenport/casey-readme-cleanups

A few readme tidy-ups
- 062f11a A few readme tidy-ups

- ebc67e3 Copy over pull secret to guardian namespace

- cfc1b95 (CNX-11672) Increase eck operator memory to prevent OCP OOMKILL

The memory limit was just a little to low

- 8e7d509 Update OpenShift dns service to correct name

- b2b1828 Change StatusManager type to interface

This makes it easier to stub out for tests / makes it easily extensible

- 19cd3d7 For Openshift install put CNI config where multus expects

- 13a8186 Don't overwrite Elasticsearch or Kibana CR statuses on update

Found while writing tests. This should stop extra reconciliations (probably one extra happening when updating elasticsearch or kibana) and needed for new tests

- de35ab1 iptables backend detection is updated in TigeraSecureEnterprise

- 12ca0ba Support configuring block size on IP pools

- 04d9337 Combine Management /  Managed cluster logic for LogStorage at the controller / render levels

This commit combines the separate logic for the Management / Managed cluster into one code path, instead of having the multiple render / controller paths. This was now possible with the addition of render components returning what they want deleted, and these changes greatly simplify the LogStorage logic over all

This commit fix ticket SAAS-664 as well, where we weren't cleaning up Elasticsearch correctly in the Managed Clusters

- 3729c5e Use component Version instead of Digest for Elasticsearch and Kibana CR versions

- e10fc25 Update kube controller version

- a615c9d Use eck kibana version for kibana version

- da1a7ab Update intrusion detection image to newest and use correct on for controller

- b44bad5 Fix patching daemonset

- Need to patch nodeSelector differently if there is already a
nodeSelector or not

- 7a3c6ff Update to v2.7.0 images

- 6bb918e Add toggle for FlexVol init container

- 7ebba82 Update zz_generated.deepcopy.go
- 277333b Some fixes needed from a previous change

- 89ac6f4 Ignore some old components that are still in some version files

- 013bd6e calico-node clusterrole: add secrets permissions

Such secrets permissions are needed to properly configure bgp password
in bgppeers

- 19f80d0 Create ExternalService for Kibana if the cluster type is Managed

This commit adds an ExternalService named "tigera-secure-kb-http" in the tigera-kibana namespace that sends it's traffic to guardian on port 5601 to allow access to the Management clusters Kibana.

- f246c1d Adding image path config

- Fix Image render tests so they run

- Remove unused code

- Switch instances of Tigera Secure to Enterprise

- d4b2f27 added go.sum

- c6db4c1 go mod and template fix

- 161a2b7 Fixed missing v3 spec

- 2c0e719 CNX-11540: added summary spec

- 4157b06 Include RBAC for accessing configmaps

- 82ba592 Run gen-versions

- 5706642 CNX-11995: Make GlobalAlertTemplate.Summary optional

- 525e91b Remove unused private-repo secret dependency

- 4b23ec5 Update release notes

- Include version update and requried gen-versions
- Add step to create github release

- 46392e9 CNX-12079: Add Summary field to GlobalAlert

- 178dd74 Cleanup go.sum

- go mod tidy
- Add tigera/api lines to go.sum to prevent dirty builds

- 78f300c Allow override of git version

- d67bab3 making changes to enable splunk as log destination

  * adding operator API spec for splunk storage
  * making changes to log collector controller
  * making changes to fluentd to render splunk env vars
  * adding test case to render splunk, updating others
  * making changes to support self signed splunk servers

- 1c39b16 Add RBAC for the apiserver to read webhook configurations

- 485e993 Fix nodeMetricsPort to adjust correct setting

- 2516fd6 Remove CRD installation from operator

- 71a3ab6 Add support for tech-preview annotation

- 0d01e8a CNX-12314: Swap GlobalAlert Summary and Description in templates

- 4494e58 Fix cloud-on-k8s pin

v1.0.1 is not a valid git tag and caused problems generating the
reference API docs. This tag was unused I guess since there is a
replace line for the package.

- fd7043d Reverting defaultEnterpriseRegistry for gen-versions code back to gcr.io for now (need to add support for Quay authroization later).

- df7a3d7 Fixing borked tests.

- e60b497 Fixing bad SHAs for Enterprise images, fixing broken images tests.

- 12bb140 Fixing wrong versions (should not have hash suffix).

- e019b95 Updating OS versions to v3.13.1 for Calico Enterprise versions for release-v1.4

- 2370eab Updating Calico Enterprise versions for release-v1.4

- 2d857f3 Fix GIT_VERSION in makefile

- a7ee254 Fix up portmap cni config spacing

- 01ea8e7 Fixing UTs, were these not ran before?

- 2e175db Add HostPorts configuration

- Add annotation hash for cni config

- 7effda4 Remove incorrect merged references to 'Variant'

- bcddf94 Post merge fixes

<details><summary>a27d071 Customize rolling update parameters (#456)</summary>

* Operator: Customize rolling update parameters
* Rename waitForCalicoPodsHealthy to waitUntilNodeCanBeMigrated; fix off by one error

</details>

my job here is done...
