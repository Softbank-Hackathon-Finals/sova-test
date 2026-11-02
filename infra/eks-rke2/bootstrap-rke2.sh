#!/bin/sh
# Fixed operator-owned VM only. Never run this through an agent shell tool.
set -eu
umask 077
test "$(id -u)" = 0
test "$(uname -m)" = aarch64
test "$(cat /etc/sova-qualification-id)" = sova-rke2-qualification-v1
test ! -e /etc/systemd/system/k3s.service
test ! -e /etc/systemd/system/rke2-server.service
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates iptables conntrack socat
modprobe overlay
modprobe br_netfilter
printf '%s\n' overlay br_netfilter > /etc/modules-load.d/sova-rke2.conf
cat > /etc/sysctl.d/90-sova-rke2.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
SYSCTL
sysctl --system
artifact=$(mktemp -d /var/tmp/sova-rke2.XXXXXXXX)
trap 'rm -rf "$artifact"' EXIT HUP INT TERM
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 \
  --output "$artifact/rke2.tar.gz" \
  'https://github.com/rancher/rke2/releases/download/v1.35.9%2Brke2r1/rke2.linux-arm64.tar.gz'
printf '%s  %s\n' 41a2595f4d07c456f603e17e03b9b9c75ac69de1d8d3bdcf598f750a674e510d "$artifact/rke2.tar.gz" | sha256sum --check -
tar -xzf "$artifact/rke2.tar.gz" -C /usr/local
install -d -m 0700 /etc/rancher/rke2
cat > /etc/rancher/rke2/audit-policy.yaml <<'AUDIT'
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
  - level: Metadata
AUDIT
cat > /etc/rancher/rke2/config.yaml <<'CONFIG'
node-name: sova-rke2-target
tls-san: [localhost, 127.0.0.1]
write-kubeconfig-mode: "0600"
disable: [rke2-ingress-nginx, rke2-metrics-server]
cni: canal
kube-apiserver-arg:
  - anonymous-auth=false
  - audit-policy-file=/etc/rancher/rke2/audit-policy.yaml
  - audit-log-path=/var/lib/rancher/rke2/server/logs/audit.log
  - audit-log-maxage=2
  - audit-log-maxbackup=2
  - audit-log-maxsize=10
CONFIG
# The release archive includes the upstream systemd unit.
cp /usr/local/lib/systemd/system/rke2-server.service /etc/systemd/system/rke2-server.service
systemctl daemon-reload
systemctl enable --now rke2-server
printf '%s\n' 'RKE2 started; node readiness and protection controls require separate readback.'
