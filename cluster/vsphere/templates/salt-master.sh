#!/bin/bash

# Copyright 2014 Google Inc. All rights reserved.
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

# Use other Debian mirror
sed -i -e "s/http.us.debian.org/mirrors.kernel.org/" /etc/apt/sources.list

# Prepopulate the name of the Master
mkdir -p /etc/salt/minion.d
echo "master: $MASTER_NAME" > /etc/salt/minion.d/master.conf

# Associate minion names with their IP addresses
for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
  if ! grep -q ${MINION_NAMES[i]} /etc/hosts; then
    echo "Adding host entry for ${MINION_NAMES[i]}"
    echo "${KUBE_MINION_IP_ADDRESSES[i]} ${MINION_NAMES[i]}" >> /etc/hosts
  fi
done

function join {
  local IFS="$1"
  shift
  echo "$*"
}

cat <<EOF >/etc/salt/minion.d/grains.conf
grains:
  minion_ips: $(join , ${KUBE_MINION_IP_ADDRESSES[@]})
  roles:
    - kubernetes-master
EOF

# Auto accept all keys from minions that try to join
mkdir -p /etc/salt/master.d
cat <<EOF >/etc/salt/master.d/auto-accept.conf
auto_accept: True
EOF

cat <<EOF >/etc/salt/master.d/reactor.conf
# React to new minions starting by running highstate on them.
reactor:
  - 'salt/minion/*/start':
    - /srv/reactor/start.sls
EOF

mkdir -p /srv/salt/nginx
echo $MASTER_HTPASSWD > /srv/salt/nginx/htpasswd

# Install Salt
#
# We specify -X to avoid a race condition that can cause minion failure to
# install.  See https://github.com/saltstack/salt-bootstrap/issues/270
#
# -M installs the master
if [ ! -x /etc/init.d/salt-master ]; then
  wget -q -O - https://bootstrap.saltstack.com | sh -s -- -M -X
else
  /etc/init.d/salt-master restart
  /etc/init.d/salt-minion restart
fi

echo $MASTER_HTPASSWD > /srv/salt/nginx/htpasswd
