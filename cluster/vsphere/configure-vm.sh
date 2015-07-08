#!/bin/bash

# Copyright 2015 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# If we have any arguments at all, this is a push and not just setup.
is_push=$@

readonly KNOWN_TOKENS_FILE="/srv/salt-overlay/salt/kube-apiserver/known_tokens.csv"
readonly BASIC_AUTH_FILE="/srv/salt-overlay/salt/kube-apiserver/basic_auth.csv"

function ensure-install-dir() {
  INSTALL_DIR="/var/cache/kubernetes-install"
  mkdir -p ${INSTALL_DIR}
  cd ${INSTALL_DIR}
}

function salt-apiserver-timeout-grain() {
    cat <<EOF >>/etc/salt/minion.d/grains.conf
  minRequestTimeout: '$1'
EOF
}

function set-broken-motd() {
  echo -e '\nBroken (or in progress) vSphere Kubernetes node setup! Suggested first step:\n  tail /var/log/startupscript.log\n' > /etc/motd
}

function set-good-motd() {
  echo -e '\n=== vSphere Kubernetes node setup complete ===\n' > /etc/motd
}

function set-kube-env() {
  . /tmp/kube-env.sh
}

function configure-hosts() {
  echo "${KUBERNETES_MASTER_IP} ${KUBERNETES_MASTER_NAME}" >> /etc/hosts
}

function remove-docker-artifacts() {
  echo "== Deleting docker0 =="
  # Forcibly install bridge-utils (options borrowed from Salt logs).
  until apt-get -q -y -o DPkg::Options::=--force-confold -o DPkg::Options::=--force-confdef install bridge-utils; do
    echo "== install of bridge-utils failed, retrying =="
    sleep 5
  done

  # Remove docker artifacts on minion nodes, if present
  iptables -t nat -F || true
  ifconfig docker0 down || true
  brctl delbr docker0 || true
  echo "== Finished deleting docker0 =="
}

validate-hash() {
  local -r file="$1"
  local -r expected="$2"
  local actual

  actual=$(sha1sum ${file} | awk '{ print $1 }') || true
  if [[ "${actual}" != "${expected}" ]]; then
    echo "== ${file} corrupted, sha1 ${actual} doesn't match expected ${expected} =="
    return 1
  fi
}

# Ensure salt-minion isn't running and never runs
stop-salt-minion() {
  if [[ -e /etc/init/salt-minion.override ]]; then
    # Assume this has already run (upgrade, or baked into containervm)
    return
  fi

  # This ensures it on next reboot
  echo manual > /etc/init/salt-minion.override
  update-rc.d salt-minion disable

  while service salt-minion status >/dev/null; do
    echo "salt-minion found running, stopping"
    service salt-minion stop
    sleep 1
  done
}

# Create the overlay files for the salt tree.  We create these in a separate
# place so that we can blow away the rest of the salt configs on a kube-push and
# re-apply these.
function create-salt-pillar() {
  # Always overwrite the cluster-params.sls (even on a push, we have
  # these variables)
  mkdir -p /srv/salt-overlay/pillar
  cat <<EOF >/srv/salt-overlay/pillar/cluster-params.sls
instance_prefix: '$(echo "$INSTANCE_PREFIX" | sed -e "s/'/''/g")'
node_instance_prefix: '$(echo "$NODE_INSTANCE_PREFIX" | sed -e "s/'/''/g")'
cluster_cidr: '$(echo "$CLUSTER_IP_RANGE" | sed -e "s/'/''/g")'
allocate_node_cidrs: '$(echo "$ALLOCATE_NODE_CIDRS" | sed -e "s/'/''/g")'
service_cluster_ip_range: '$(echo "$SERVICE_CLUSTER_IP_RANGE" | sed -e "s/'/''/g")'
enable_cluster_monitoring: '$(echo "$ENABLE_CLUSTER_MONITORING" | sed -e "s/'/''/g")'
enable_cluster_logging: '$(echo "$ENABLE_CLUSTER_LOGGING" | sed -e "s/'/''/g")'
enable_node_logging: '$(echo "$ENABLE_NODE_LOGGING" | sed -e "s/'/''/g")'
logging_destination: '$(echo "$LOGGING_DESTINATION" | sed -e "s/'/''/g")'
elasticsearch_replicas: '$(echo "$ELASTICSEARCH_LOGGING_REPLICAS" | sed -e "s/'/''/g")'
enable_cluster_dns: '$(echo "$ENABLE_CLUSTER_DNS" | sed -e "s/'/''/g")'
dns_replicas: '$(echo "$DNS_REPLICAS" | sed -e "s/'/''/g")'
dns_server: '$(echo "$DNS_SERVER_IP" | sed -e "s/'/''/g")'
dns_domain: '$(echo "$DNS_DOMAIN" | sed -e "s/'/''/g")'
admission_control: '$(echo "$ADMISSION_CONTROL" | sed -e "s/'/''/g")'
EOF
}

# This should only happen on cluster initialization.
#
#  - Uses KUBE_PASSWORD and KUBE_USER to generate basic_auth.csv.
#  - Uses KUBE_BEARER_TOKEN, KUBELET_TOKEN, and KUBE_PROXY_TOKEN to generate
#    known_tokens.csv (KNOWN_TOKENS_FILE).
#  - Uses CA_CERT, MASTER_CERT, and MASTER_KEY to populate the SSL credentials
#    for the apiserver.
#  - Optionally uses KUBECFG_CERT and KUBECFG_KEY to store a copy of the client
#    cert credentials.
#
# After the first boot and on upgrade, these files exists on the master-pd
# and should never be touched again (except perhaps an additional service
# account, see NB below.)
function create-salt-master-auth() {
  if [[ ! -e /srv/kubernetes/ca.crt ]]; then
    if  [[ ! -z "${CA_CERT:-}" ]] && [[ ! -z "${MASTER_CERT:-}" ]] && [[ ! -z "${MASTER_KEY:-}" ]]; then
      mkdir -p /srv/kubernetes
      (umask 077;
        echo "${CA_CERT}" | base64 -d > /srv/kubernetes/ca.crt;
        echo "${MASTER_CERT}" | base64 -d > /srv/kubernetes/server.cert;
        echo "${MASTER_KEY}" | base64 -d > /srv/kubernetes/server.key;
        # Kubecfg cert/key are optional and included for backwards compatibility.
        # TODO(roberthbailey): Remove these two lines once GKE no longer requires
        # fetching clients certs from the master VM.
        echo "${KUBECFG_CERT:-}" | base64 -d > /srv/kubernetes/kubecfg.crt;
        echo "${KUBECFG_KEY:-}" | base64 -d > /srv/kubernetes/kubecfg.key)
    fi
  fi
  if [ ! -e "${BASIC_AUTH_FILE}" ]; then
    mkdir -p /srv/salt-overlay/salt/kube-apiserver
    (umask 077;
      echo "${KUBE_PASSWORD},${KUBE_USER},admin" > "${BASIC_AUTH_FILE}")
  fi
  if [ ! -e "${KNOWN_TOKENS_FILE}" ]; then
    mkdir -p /srv/salt-overlay/salt/kube-apiserver
    (umask 077;
      echo "${KUBE_BEARER_TOKEN},admin,admin" > "${KNOWN_TOKENS_FILE}";
      echo "${KUBELET_TOKEN},kubelet,kubelet" >> "${KNOWN_TOKENS_FILE}";
      echo "${KUBE_PROXY_TOKEN},kube_proxy,kube_proxy" >> "${KNOWN_TOKENS_FILE}")

    # Generate tokens for other "service accounts".  Append to known_tokens.
    #
    # NB: If this list ever changes, this script actually has to
    # change to detect the existence of this file, kill any deleted
    # old tokens and add any new tokens (to handle the upgrade case).
    local -r service_accounts=("system:scheduler" "system:controller_manager" "system:logging" "system:monitoring" "system:dns")
    for account in "${service_accounts[@]}"; do
      token=$(dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64 | tr -d "=+/" | dd bs=32 count=1 2>/dev/null)
      echo "${token},${account},${account}" >> "${KNOWN_TOKENS_FILE}"
    done
  fi
}

# TODO(roberthbailey): Remove the insecure kubeconfig configuration files
# once the certs are being plumbed through for GKE.
function create-salt-node-auth() {
  if [[ ! -e /srv/kubernetes/ca.crt ]]; then
    if [[ ! -z "${CA_CERT:-}" ]] && [[ ! -z "${KUBELET_CERT:-}" ]] && [[ ! -z "${KUBELET_KEY:-}" ]]; then
      mkdir -p /srv/kubernetes
      (umask 077;
        echo "${CA_CERT}" | base64 -d > /srv/kubernetes/ca.crt;
        echo "${KUBELET_CERT}" | base64 -d > /srv/kubernetes/kubelet.crt;
        echo "${KUBELET_KEY}" | base64 -d > /srv/kubernetes/kubelet.key)
    fi
  fi
  kubelet_kubeconfig_file="/srv/salt-overlay/salt/kubelet/kubeconfig"
  if [ ! -e "${kubelet_kubeconfig_file}" ]; then
    mkdir -p /srv/salt-overlay/salt/kubelet
    if [[ ! -z "${CA_CERT:-}" ]] && [[ ! -z "${KUBELET_CERT:-}" ]] && [[ ! -z "${KUBELET_KEY:-}" ]]; then
      (umask 077;
        cat > "${kubelet_kubeconfig_file}" <<EOF
apiVersion: v1
kind: Config
users:
- name: kubelet
  user:
    client-certificate-data: ${KUBELET_CERT}
    client-key-data: ${KUBELET_KEY}
clusters:
- name: local
  cluster:
    certificate-authority-data: ${CA_CERT}
contexts:
- context:
    cluster: local
    user: kubelet
  name: service-account-context
current-context: service-account-context
EOF
)
    else
      (umask 077;
      cat > "${kubelet_kubeconfig_file}" <<EOF
apiVersion: v1
kind: Config
users:
- name: kubelet
  user:
    token: ${KUBELET_TOKEN}
clusters:
- name: local
  cluster:
     insecure-skip-tls-verify: true
contexts:
- context:
    cluster: local
    user: kubelet
  name: service-account-context
current-context: service-account-context
EOF
)
    fi
  fi

  kube_proxy_kubeconfig_file="/srv/salt-overlay/salt/kube-proxy/kubeconfig"
  if [ ! -e "${kube_proxy_kubeconfig_file}" ]; then
    mkdir -p /srv/salt-overlay/salt/kube-proxy
    if [[ ! -z "${CA_CERT:-}" ]]; then
      (umask 077;
        cat > "${kube_proxy_kubeconfig_file}" <<EOF
apiVersion: v1
kind: Config
users:
- name: kube-proxy
  user:
    token: ${KUBE_PROXY_TOKEN}
clusters:
- name: local
  cluster:
    certificate-authority-data: ${CA_CERT}
contexts:
- context:
    cluster: local
    user: kube-proxy
  name: service-account-context
current-context: service-account-context
EOF
)
    else
      (umask 077;
      cat > "${kube_proxy_kubeconfig_file}" <<EOF
apiVersion: v1
kind: Config
users:
- name: kube-proxy
  user:
    token: ${KUBE_PROXY_TOKEN}
clusters:
- name: local
  cluster:
     insecure-skip-tls-verify: true
contexts:
- context:
    cluster: local
    user: kube-proxy
  name: service-account-context
current-context: service-account-context
EOF
)
    fi
  fi
}

function unpack-release() {
  rm -rf kubernetes
  echo "Unpacking Salt tree and checking integrity of binary release tar"
  tar xzf "${SALT_TAR_PATH}" && tar tzf "${SERVER_BINARY_TAR_PATH}" > /dev/null

  echo "Running release install script"
  sudo kubernetes/saltbase/install.sh "${SERVER_BINARY_TAR_PATH}"
}

function fix-apt-sources() {
  sed -i -e "\|^deb.*http://http.debian.net/debian| s/^/#/" /etc/apt/sources.list
}

function salt-run-local() {
  cat <<EOF >/etc/salt/minion.d/local.conf
file_client: local
file_roots:
  base:
    - /srv/salt
EOF
}

function salt-debug-log() {
  cat <<EOF >/etc/salt/minion.d/log-level-debug.conf
log_level: debug
log_level_logfile: debug
EOF
}

function salt-master-role() {
  cat <<EOF >/etc/salt/minion.d/grains.conf
grains:
  roles:
    - kubernetes-master
  cbr-cidr: 10.45.67.0/30
  cloud: vsphere
EOF
}

function salt-node-role() {
  cat <<EOF >/etc/salt/minion.d/grains.conf
grains:
  roles:
    - kubernetes-pool
  cbr-cidr: 10.123.45.0/30
  cloud: vsphere
EOF
}

function salt-docker-opts() {
  DOCKER_OPTS=""

  if [[ -n "${EXTRA_DOCKER_OPTS-}" ]]; then
    DOCKER_OPTS="${EXTRA_DOCKER_OPTS}"
  fi

  if [[ -n "{DOCKER_OPTS}" ]]; then
    cat <<EOF >>/etc/salt/minion.d/grains.conf
  docker_opts: '$(echo "$DOCKER_OPTS" | sed -e "s/'/''/g")'
EOF
  fi
}

function salt-set-apiserver() {
  cat <<EOF >>/etc/salt/minion.d/grains.conf
  api_servers: '${KUBERNETES_MASTER_NAME}'
EOF
}

function configure-salt() {
  fix-apt-sources
  mkdir -p /etc/salt/minion.d
  salt-run-local
  if [[ "${KUBERNETES_MASTER}" == "true" ]]; then
    salt-master-role
    if [ -n "${KUBE_APISERVER_REQUEST_TIMEOUT:-}"  ]; then
        salt-apiserver-timeout-grain $KUBE_APISERVER_REQUEST_TIMEOUT
    fi
  else
    salt-node-role
    salt-docker-opts
    salt-set-apiserver
  fi
  stop-salt-minion
}

function run-salt() {
  echo "== Calling Salt =="
  salt-call --local state.highstate || true
}

####################################################################################

if [[ -z "${is_push}" ]]; then
  echo "== kube-up node config starting =="
  set-broken-motd
  ensure-install-dir
  set-kube-env
  configure-hosts
  create-salt-pillar
  if [[ "${KUBERNETES_MASTER}" == "true" ]]; then
    create-salt-master-auth
  else
    create-salt-node-auth
  fi
  unpack-release
  configure-salt
  remove-docker-artifacts
  run-salt
  set-good-motd
  echo "== kube-up node config done =="
else
  echo "== kube-push node config starting =="
  ensure-install-dir
  set-kube-env
  create-salt-pillar
  download-release
  run-salt
  echo "== kube-push node config done =="
fi
