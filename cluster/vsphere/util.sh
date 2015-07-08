#!/bin/bash

# Copyright 2014 The Kubernetes Authors All rights reserved.
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

# A library of helper functions and constants for the local config.

# Use the config file specified in $KUBE_CONFIG_FILE, or default to
# config-default.sh.
KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../..
source "${KUBE_ROOT}/cluster/vsphere/config-common.sh"
source "${KUBE_ROOT}/cluster/vsphere/${KUBE_CONFIG_FILE-"config-default.sh"}"
source "${KUBE_ROOT}/cluster/common.sh"

# Detect the IP for the master
#
# Assumed vars:
#   MASTER_NAME
# Vars set:
#   KUBE_MASTER_NAME
#   KUBE_MASTER_IP
function detect-master {
  KUBE_MASTER_NAME=${MASTER_NAME}
  if [[ -z "${KUBE_MASTER_IP-}" ]]; then
    KUBE_MASTER_IP=$(govc vm.ip ${MASTER_NAME})
  fi
  if [[ -z "${KUBE_MASTER_IP-}" ]]; then
    echo "Could not detect Kubernetes master node. Make sure you've launched a cluster with 'kube-up.sh'" >&2
    exit 1
  fi
  echo "$KUBE_MASTER_NAME (external IP: $KUBE_MASTER_IP)"
}

# Detect the information about the minions
#
# Assumed vars:
#   MINION_NAMES
# Vars set:
#   KUBE_MINION_IP_ADDRESS (array)
function detect-minions {
  KUBE_MINION_IP_ADDRESSES=()
  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    local minion_ip=$(govc vm.ip ${MINION_NAMES[$i]})
    if [[ -z "${minion_ip-}" ]] ; then
      echo "Did not find ${MINION_NAMES[$i]}" >&2
    else
      echo "Found ${MINION_NAMES[$i]} at ${minion_ip}"
      KUBE_MINION_IP_ADDRESSES+=("${minion_ip}")
    fi
  done
  if [[ -z "${KUBE_MINION_IP_ADDRESSES-}" ]]; then
    echo "Could not detect Kubernetes minion nodes. Make sure you've launched a cluster with 'kube-up.sh'" >&2
    exit 1
  fi
}

function trap-add {
  local handler="$1"
  local signal="${2-EXIT}"
  local cur

  cur="$(eval "sh -c 'echo \$3' -- $(trap -p ${signal})")"
  if [[ -n "${cur}" ]]; then
    handler="${cur}; ${handler}"
  fi

  trap "${handler}" ${signal}
}

function verify-prereqs {
  which "govc" >/dev/null || {
    echo "Can't find govc in PATH, please install and retry."
    echo ""
    echo "    go install github.com/vmware/govmomi/govc"
    echo ""
    exit 1
  }
}

function verify-ssh-prereqs {
  local rc

  rc=0
  ssh-add -L 1> /dev/null 2> /dev/null || rc="$?"
  # "Could not open a connection to your authentication agent."
  if [[ "${rc}" -eq 2 ]]; then
    eval "$(ssh-agent)" > /dev/null
    trap-add "kill ${SSH_AGENT_PID}" EXIT
  fi

  rc=0
  ssh-add -L 1> /dev/null 2> /dev/null || rc="$?"
  # "The agent has no identities."
  if [[ "${rc}" -eq 1 ]]; then
    # Try adding one of the default identities, with or without passphrase.
    ssh-add || true
  fi

  # Expect at least one identity to be available.
  if ! ssh-add -L 1> /dev/null 2> /dev/null; then
    echo "Could not find or add an SSH identity."
    echo "Please start ssh-agent, add your identity, and retry."
    exit 1
  fi
}

# Create a temp dir that'll be deleted at the end of this bash session.
#
# Vars set:
#   KUBE_TEMP
function ensure-temp-dir {
  if [[ -z ${KUBE_TEMP-} ]]; then
    KUBE_TEMP=$(mktemp -d -t kubernetes.XXXXXX)
    trap-add 'rm -rf "${KUBE_TEMP}"' EXIT
  fi
}

# Verify and find the various tar files that we are going to use on the server.
#
# Vars set:
#   SERVER_BINARY_TAR
#   SALT_TAR
function find-release-tars {
  SERVER_BINARY_TAR="${KUBE_ROOT}/server/kubernetes-server-linux-amd64.tar.gz"
  if [[ ! -f "$SERVER_BINARY_TAR" ]]; then
    SERVER_BINARY_TAR="${KUBE_ROOT}/_output/release-tars/kubernetes-server-linux-amd64.tar.gz"
  fi
  if [[ ! -f "$SERVER_BINARY_TAR" ]]; then
    echo "!!! Cannot find kubernetes-server-linux-amd64.tar.gz"
    exit 1
  fi

  SALT_TAR="${KUBE_ROOT}/server/kubernetes-salt.tar.gz"
  if [[ ! -f "$SALT_TAR" ]]; then
    SALT_TAR="${KUBE_ROOT}/_output/release-tars/kubernetes-salt.tar.gz"
  fi
  if [[ ! -f "$SALT_TAR" ]]; then
    echo "!!! Cannot find kubernetes-salt.tar.gz"
    exit 1
  fi
}

function sha1sum-file() {
  if which shasum >/dev/null 2>&1; then
    shasum -a1 "$1" | awk '{ print $1 }'
  else
    sha1sum "$1" | awk '{ print $1 }'
  fi
}

# Take the local tar files and upload them to any instance.
#
# Assumed vars:
#   SERVER_BINARY_TAR
#   SALT_TAR
#
# Vars set:
#   SERVER_BINARY_TAR_PATH
#   SERVER_BINARY_TAR_HASH
#   SALT_TAR_PATH
#   SALT_TAR_HASH
function upload-tars {
  local ip=$1

  kube-ssh ${ip} "mkdir -p /home/kube/cache/kubernetes-install"

  SERVER_BINARY_TAR_PATH="/home/kube/cache/kubernetes-install/${SERVER_BINARY_TAR##*/}"
  SERVER_BINARY_TAR_HASH=$(sha1sum-file "${SERVER_BINARY_TAR}")
  kube-scp ${ip} "${SERVER_BINARY_TAR}" "${SERVER_BINARY_TAR_PATH}"

  SALT_TAR_PATH="/home/kube/cache/kubernetes-install/${SALT_TAR##*/}"
  SALT_TAR_HASH=$(sha1sum-file "${SALT_TAR}")
  kube-scp ${ip} "${SALT_TAR}" "${SALT_TAR_PATH}"
}

# Ensure that we have a password created for validating to the master. Will
# read from kubeconfig for the current context if available.
#
# Assumed vars
#   KUBE_ROOT
#
# Vars set:
#   KUBE_USER
#   KUBE_PASSWORD
function get-password {
  get-kubeconfig-basicauth
  if [[ -z "${KUBE_USER}" || -z "${KUBE_PASSWORD}" ]]; then
    KUBE_USER=admin
    KUBE_PASSWORD=$(python -c 'import string,random; print "".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))')
  fi
}

# Ensure that we have a bearer token created for validating to the master.
# Will read from kubeconfig for the current context if available.
#
# Assumed vars
#   KUBE_ROOT
#
# Vars set:
#   KUBE_BEARER_TOKEN
function get-bearer-token() {
  get-kubeconfig-bearertoken
  if [[ -z "${KUBE_BEARER_TOKEN:-}" ]]; then
    KUBE_BEARER_TOKEN=$(dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64 | tr -d "=+/" | dd bs=32 count=1 2>/dev/null)
  fi
}

# Wait for background jobs to finish. Exit with
# an error status if any of the jobs failed.
function wait-for-jobs {
  local fail=0
  local job
  for job in $(jobs -p); do
    wait "${job}" || fail=$((fail + 1))
  done
  if (( fail != 0 )); then
    echo -e "${color_red}${fail} commands failed.  Exiting.${color_norm}" >&2
    # Ignore failures for now.
    # exit 2
  fi
}

# Run command over ssh
function kube-ssh {
  local host="$1"
  shift
  ssh ${SSH_OPTS-} "kube@${host}" "$@" 2> /dev/null
}

# Copy file over ssh
function kube-scp {
  local host="$1"
  local src="$2"
  local dst="$3"
  scp ${SSH_OPTS-} "${src}" "kube@${host}:${dst}"
}

# Instantiate a generic kubernetes virtual machine (master or minion)
#
# Usage:
#   kube-up-vm VM_NAME [options to pass to govc vm.create]

#
# Example:
#   kube-up-vm "vm-name" -c 2 -m 4096
#
# Assumed vars:
#   DISK
#   GUEST_ID
function kube-up-vm {
  local vm_name="$1"
  shift

  govc vm.create \
    -debug \
    -disk="${DISK}" \
    -g="${GUEST_ID}" \
    -link=true \
    "$@" \
    "${vm_name}"

  # Retrieve IP first, to confirm the guest operations agent is running.
  govc vm.ip "${vm_name}" > /dev/null

  govc guest.mkdir \
    -vm="${vm_name}" \
    -p \
    /home/kube/.ssh

  ssh-add -L > "${KUBE_TEMP}/${vm_name}-authorized_keys"

  govc guest.upload \
    -vm="${vm_name}" \
    -f \
    "${KUBE_TEMP}/${vm_name}-authorized_keys" \
    /home/kube/.ssh/authorized_keys
}

# Kick off a local script on a kubernetes virtual machine (master or minion)
#
# Usage:
#   kube-run VM_NAME LOCAL_FILE
function kube-run {
  local vm_name="$1"
  local file="$2"
  local dst="/tmp/$(basename "${file}")"
  govc guest.upload -vm="${vm_name}" -f -perm=0755 "${file}" "${dst}"

  local vm_ip
  vm_ip=$(govc vm.ip "${vm_name}")
  kube-ssh ${vm_ip} "nohup sudo ${dst} < /dev/null 1> ${dst}.out 2> ${dst}.err &"
}

# Quote something appropriate for a yaml string.
function sh-quote {
  echo "\"$(echo "${@}" | sed -e "s/\"/\\\"/g")\""
}

function write-master-env {
  build-kube-env true "${KUBE_TEMP}/master-kube-env.sh"
}

function write-node-env {
  local tmp

  tmp="$(mktemp -d -t env.XXXXXX)/node-kube-env.sh"

  build-kube-env false "${tmp}"

  echo $tmp
}

# $1: if 'true', we're building a master yaml, else a node
function build-kube-env {
  local master=$1
  local file=$2

  rm -f ${file}
  cat >$file <<EOF
export ENV_TIMESTAMP=$(sh-quote $(date -u +%Y-%m-%dT%T%z))
export INSTANCE_PREFIX=$(sh-quote ${INSTANCE_PREFIX})
export NODE_INSTANCE_PREFIX=$(sh-quote ${NODE_INSTANCE_PREFIX})
export CLUSTER_IP_RANGE=$(sh-quote ${CLUSTER_IP_RANGE:-10.244.0.0/16})
export SERVER_BINARY_TAR_PATH=$(sh-quote ${SERVER_BINARY_TAR_PATH})
export SERVER_BINARY_TAR_HASH=$(sh-quote ${SERVER_BINARY_TAR_HASH})
export SALT_TAR_PATH=$(sh-quote ${SALT_TAR_PATH})
export SALT_TAR_HASH=$(sh-quote ${SALT_TAR_HASH})
export SERVICE_CLUSTER_IP_RANGE=$(sh-quote ${SERVICE_CLUSTER_IP_RANGE})
export KUBERNETES_MASTER_NAME=$(sh-quote ${KUBE_MASTER_NAME})
export KUBERNETES_MASTER_IP=$(sh-quote ${KUBE_MASTER_IP})
export ALLOCATE_NODE_CIDRS=$(sh-quote ${ALLOCATE_NODE_CIDRS:-false})
export ENABLE_CLUSTER_MONITORING=$(sh-quote ${ENABLE_CLUSTER_MONITORING:-none})
export ENABLE_CLUSTER_LOGGING=$(sh-quote ${ENABLE_CLUSTER_LOGGING:-false})
export ENABLE_NODE_LOGGING=$(sh-quote ${ENABLE_NODE_LOGGING:-false})
export LOGGING_DESTINATION=$(sh-quote ${LOGGING_DESTINATION:-})
export ELASTICSEARCH_LOGGING_REPLICAS=$(sh-quote ${ELASTICSEARCH_LOGGING_REPLICAS:-})
export ENABLE_CLUSTER_DNS=$(sh-quote ${ENABLE_CLUSTER_DNS:-false})
export DNS_REPLICAS=$(sh-quote ${DNS_REPLICAS:-})
export DNS_SERVER_IP=$(sh-quote ${DNS_SERVER_IP:-})
export DNS_DOMAIN=$(sh-quote ${DNS_DOMAIN:-})
export KUBELET_TOKEN=$(sh-quote ${KUBELET_TOKEN:-})
export KUBE_PROXY_TOKEN=$(sh-quote ${KUBE_PROXY_TOKEN:-})
export ADMISSION_CONTROL=$(sh-quote ${ADMISSION_CONTROL:-})
export CA_CERT=$(sh-quote ${CA_CERT_BASE64:-})
EOF
  if [ -n "${KUBE_APISERVER_REQUEST_TIMEOUT:-}"  ]; then
    cat >>$file <<EOF
export KUBE_APISERVER_REQUEST_TIMEOUT=$(sh-quote ${KUBE_APISERVER_REQUEST_TIMEOUT})
EOF
  fi
  if [[ "${master}" == "true" ]]; then
    # Master-only env vars.
    cat >>$file <<EOF
export KUBERNETES_MASTER="true"
export KUBE_USER=$(sh-quote ${KUBE_USER})
export KUBE_PASSWORD=$(sh-quote ${KUBE_PASSWORD})
export KUBE_BEARER_TOKEN=$(sh-quote ${KUBE_BEARER_TOKEN})
export MASTER_CERT=$(sh-quote ${MASTER_CERT_BASE64:-})
export MASTER_KEY=$(sh-quote ${MASTER_KEY_BASE64:-})
export KUBECFG_CERT=$(sh-quote ${KUBECFG_CERT_BASE64:-})
export KUBECFG_KEY=$(sh-quote ${KUBECFG_KEY_BASE64:-})
EOF
  else
    # Node-only env vars.
    cat >>$file <<EOF
export KUBERNETES_MASTER="false"
export EXTRA_DOCKER_OPTS=$(sh-quote ${EXTRA_DOCKER_OPTS:-})
export KUBELET_CERT=$(sh-quote ${KUBELET_CERT_BASE64:-})
export KUBELET_KEY=$(sh-quote ${KUBELET_KEY_BASE64:-})
EOF
  fi
}

# create-master-instance creates the master instance. If called with
# an argument, the argument is used as the name to a reserved IP
# address for the master. (In the case of upgrade/repair, we re-use
# the same IP.)
#
# It requires a whole slew of assumed variables, partially due to to
# the call to write-master-env. Listing them would be rather
# futile. Instead, we list the required calls to ensure any additional
# variables are set:
#   ensure-temp-dir
#   get-bearer-token
#   upload-tars
#
function create-master-instance {
  local dst

  upload-tars "${KUBE_MASTER_IP}"

  write-master-env

  dst="/tmp/configure-vm.sh"

  # Copy environment
  kube-scp "${KUBE_MASTER_IP}" "${KUBE_TEMP}/master-kube-env.sh" "/tmp/kube-env.sh"

  # Copy script
  kube-scp "${KUBE_MASTER_IP}" "${KUBE_ROOT}/cluster/vsphere/configure-vm.sh" "${dst}"

  # Run script
  kube-ssh "${KUBE_MASTER_IP}" "nohup sudo bash ${dst} < /dev/null 1> ${dst}.out 2> ${dst}.err &"
}

# create-node-instance creates a node instance. If called with
# an argument, the argument is used as the name to a reserved IP
# address for the master. (In the case of upgrade/repair, we re-use
# the same IP.)
#
# It requires a whole slew of assumed variables, partially due to to
# the call to write-master-env. Listing them would be rather
# futile. Instead, we list the required calls to ensure any additional
# variables are set:
#   ensure-temp-dir
#   get-bearer-token
#   upload-tars
#
function create-node-instance {
  local ip=$1
  local env_src
  local dst

  upload-tars "${ip}"

  dst="/tmp/configure-vm.sh"

  # Copy environment
  kube-scp "${ip}" "$(write-node-env)" "/tmp/kube-env.sh"

  # Copy script
  kube-scp "${ip}" "${KUBE_ROOT}/cluster/vsphere/configure-vm.sh" "${dst}"

  # Run script
  kube-ssh "${ip}" "nohup sudo bash ${dst} < /dev/null 1> ${dst}.out 2> ${dst}.err &"
}

# Create certificate pairs for the cluster.
# $1: The public IP for the master.
#
# These are used for static cert distribution (e.g. static clustering) at
# cluster creation time. This will be obsoleted once we implement dynamic
# clustering.
#
# The following certificate pairs are created:
#
#  - ca (the cluster's certificate authority)
#  - server
#  - kubelet
#  - kubecfg (for kubectl)
#
# TODO(roberthbailey): Replace easyrsa with a simple Go program to generate
# the certs that we need.
#
# Assumed vars
#   KUBE_TEMP
#
# Vars set:
#   CERT_DIR
#   CA_CERT_BASE64
#   MASTER_CERT_BASE64
#   MASTER_KEY_BASE64
#   KUBELET_CERT_BASE64
#   KUBELET_KEY_BASE64
#   KUBECFG_CERT_BASE64
#   KUBECFG_KEY_BASE64
function create-certs {
  local -r cert_ip="${1}"

  local octects=($(echo "$SERVICE_CLUSTER_IP_RANGE" | sed -e 's|/.*||' -e 's/\./ /g'))
  ((octects[3]+=1))
  local -r service_ip=$(echo "${octects[*]}" | sed 's/ /./g')
  local -r sans="IP:${cert_ip},IP:${service_ip},DNS:kubernetes,DNS:kubernetes.default,DNS:kubernetes.default.svc,DNS:kubernetes.default.svc.${DNS_DOMAIN},DNS:${MASTER_NAME}"

  # Note: This was heavily cribbed from make-ca-cert.sh
  (cd "${KUBE_TEMP}"
    curl -L -O https://storage.googleapis.com/kubernetes-release/easy-rsa/easy-rsa.tar.gz > /dev/null 2>&1
    tar xzf easy-rsa.tar.gz > /dev/null 2>&1
    cd easy-rsa-master/easyrsa3
    ./easyrsa init-pki > /dev/null 2>&1
    ./easyrsa --batch "--req-cn=${cert_ip}@$(date +%s)" build-ca nopass > /dev/null 2>&1
    ./easyrsa --subject-alt-name="${sans}" build-server-full "${MASTER_NAME}" nopass > /dev/null 2>&1
    ./easyrsa build-client-full kubelet nopass > /dev/null 2>&1
    ./easyrsa build-client-full kubecfg nopass > /dev/null 2>&1) || {
    # If there was an error in the subshell, just die.
    # TODO(roberthbailey): add better error handling here
    echo "=== Failed to generate certificates: Aborting ==="
    exit 2
  }
  CERT_DIR="${KUBE_TEMP}/easy-rsa-master/easyrsa3"
  # By default, linux wraps base64 output every 76 cols, so we use 'tr -d' to remove whitespaces.
  # Note 'base64 -w0' doesn't work on Mac OS X, which has different flags.
  CA_CERT_BASE64=$(cat "${CERT_DIR}/pki/ca.crt" | base64 | tr -d '\r\n')
  MASTER_CERT_BASE64=$(cat "${CERT_DIR}/pki/issued/${MASTER_NAME}.crt" | base64 | tr -d '\r\n')
  MASTER_KEY_BASE64=$(cat "${CERT_DIR}/pki/private/${MASTER_NAME}.key" | base64 | tr -d '\r\n')
  KUBELET_CERT_BASE64=$(cat "${CERT_DIR}/pki/issued/kubelet.crt" | base64 | tr -d '\r\n')
  KUBELET_KEY_BASE64=$(cat "${CERT_DIR}/pki/private/kubelet.key" | base64 | tr -d '\r\n')
  KUBECFG_CERT_BASE64=$(cat "${CERT_DIR}/pki/issued/kubecfg.crt" | base64 | tr -d '\r\n')
  KUBECFG_KEY_BASE64=$(cat "${CERT_DIR}/pki/private/kubecfg.key" | base64 | tr -d '\r\n')
}

# Instantiate a kubernetes cluster
#
# Assumed vars:
#   KUBE_ROOT
#   <Various vars set in config file>
function kube-up {
  verify-ssh-prereqs
  ensure-temp-dir

  get-password
  get-bearer-token

  # Make sure we have the tar files locally
  find-release-tars

  # Generate a bearer token for this cluster. We push this separately
  # from the other cluster variables so that the client (this
  # computer) can forget it later. This should disappear with
  # https://github.com/GoogleCloudPlatform/kubernetes/issues/3168
  KUBELET_TOKEN=$(dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64 | tr -d "=+/" | dd bs=32 count=1 2>/dev/null)
  KUBE_PROXY_TOKEN=$(dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64 | tr -d "=+/" | dd bs=32 count=1 2>/dev/null)

  echo "Starting master VM (this can take a minute)..."
  kube-up-vm ${MASTER_NAME} -c ${MASTER_CPU-1} -m ${MASTER_MEMORY_MB-1024}
  detect-master
  create-certs "${KUBE_MASTER_IP}"
  create-master-instance

  echo "Starting minion VMs (this can take a minute)..."
  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    kube-up-vm "${MINION_NAMES[$i]}" -c ${MINION_CPU-1} -m ${MINION_MEMORY_MB-1024} &
  done
  wait-for-jobs

  detect-minions
  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    create-node-instance "${KUBE_MINION_IP_ADDRESSES[$i]}"
  done

  # Create kubeconfig as early as possible so that we keep
  # the certs around in case the script fails later on.
  export KUBE_CERT="${CERT_DIR}/pki/issued/kubecfg.crt"
  export KUBE_KEY="${CERT_DIR}/pki/private/kubecfg.key"
  export CA_CERT="${CERT_DIR}/pki/ca.crt"
  export CONTEXT="${INSTANCE_PREFIX}"
  (
   umask 077
   create-kubeconfig
  )

  echo "Waiting for cluster initialization."
  echo
  echo "  This will continually check to see if the API for kubernetes is reachable."
  echo "  This might loop forever if there was some uncaught error during start"
  echo "  up."
  echo

  # curl in mavericks is borked.
  secure=""
  if which sw_vers > /dev/null; then
    if [[ $(sw_vers | grep ProductVersion | awk '{print $2}') = "10.9."* ]]; then
      secure="--insecure"
    fi
  fi

  until curl --cacert "${CERT_DIR}/pki/ca.crt" \
          -H "Authorization: Bearer ${KUBE_BEARER_TOKEN}" \
          ${secure} \
          --max-time 5 --fail --output /dev/null --silent \
          "https://${KUBE_MASTER_IP}/api/v1/pods"; do
      printf "."
      sleep 2
  done

  echo "Kubernetes cluster created."

  echo
  echo -e "${color_green}Kubernetes cluster is running.  The master is running at:"
  echo
  echo -e "${color_yellow}  https://${KUBE_MASTER_IP}"
  echo
  echo -e "${color_green}The user name and password to use is located in ${KUBECONFIG}.${color_norm}"
  echo
}

# Delete a kubernetes cluster
function kube-down {
  govc vm.destroy ${MASTER_NAME} &

  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    govc vm.destroy ${MINION_NAMES[i]} &
  done

  wait
}

# Update a kubernetes cluster with latest source
function kube-push {
	echo "TODO"
}

# Execute prior to running tests to build a release if required for env
function test-build-release {
	echo "TODO"
}

# Execute prior to running tests to initialize required structure
function test-setup {
	echo "TODO"
}

# Execute after running tests to perform any required clean-up
function test-teardown {
	echo "TODO"
}
