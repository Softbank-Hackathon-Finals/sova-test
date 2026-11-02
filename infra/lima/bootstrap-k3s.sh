#!/bin/sh
# Run only inside the separately created Sova target VM, as its root operator.
# No remote install script is executed; the release binary is checksum pinned.
set -eu
umask 077
test "$(uname -s)" = Linux
test "$(uname -m)" = aarch64
test "$(id -u)" = 0
test "$(cat /etc/sova-qualification-id)" = sova-target-qualification-v1
test ! -e /etc/systemd/system/k3s.service

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade
apt-get install -y --no-install-recommends curl ca-certificates iptables conntrack

artifact_dir=$(mktemp -d /var/tmp/sova-k3s.XXXXXXXX)
trap 'rm -rf "$artifact_dir"' EXIT HUP INT TERM
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 180 \
  --output "$artifact_dir/k3s-arm64" \
  'https://github.com/k3s-io/k3s/releases/download/v1.37.1%2Bk3s1/k3s-arm64'
printf '%s  %s\n' a1561ca4aef8b99f5588a840d4468ac39c8c1cd92470bbcb9634823fa221741a "$artifact_dir/k3s-arm64" | sha256sum --check -
install -m 0755 "$artifact_dir/k3s-arm64" /usr/local/bin/k3s

modprobe overlay
modprobe br_netfilter
printf '%s\n' overlay br_netfilter > /etc/modules-load.d/sova-k3s.conf
cat > /etc/sysctl.d/90-sova-k3s.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
SYSCTL
sysctl --system
install -d -m 0700 /etc/rancher/k3s
cat > /etc/rancher/k3s/audit-policy.yaml <<'AUDIT'
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
  - level: Metadata
AUDIT
cat > /etc/rancher/k3s/config.yaml <<'CONFIG'
node-name: sova-target
bind-address: 0.0.0.0
https-listen-port: 6443
tls-san: [localhost, 127.0.0.1]
write-kubeconfig-mode: "0600"
secrets-encryption: true
disable: [traefik, servicelb]
kube-apiserver-arg:
  - anonymous-auth=false
  - audit-policy-file=/etc/rancher/k3s/audit-policy.yaml
  - audit-log-path=/var/lib/rancher/k3s/server/logs/audit.log
  - audit-log-maxage=2
  - audit-log-maxbackup=2
  - audit-log-maxsize=10
CONFIG
cat > /etc/systemd/system/k3s.service <<'SERVICE'
[Unit]
Description=Sova qualification Kubernetes target
Wants=network-online.target
After=network-online.target
[Service]
Type=notify
ExecStart=/usr/local/bin/k3s server --config /etc/rancher/k3s/config.yaml
Delegate=yes
KillMode=process
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
TasksMax=infinity
TimeoutStartSec=240
[Install]
WantedBy=multi-user.target
SERVICE
chmod 0600 /etc/rancher/k3s/config.yaml /etc/rancher/k3s/audit-policy.yaml
chmod 0644 /etc/systemd/system/k3s.service
systemctl daemon-reload
systemctl enable --now k3s
node_deadline=$(($(date +%s) + 180))
until /usr/local/bin/k3s kubectl get node/sova-target >/dev/null 2>&1; do
  test "$(date +%s)" -lt "$node_deadline"
  sleep 1
done
/usr/local/bin/k3s kubectl wait --for=condition=Ready node/sova-target --timeout=180s
printf '%s\n' 'Sova k3s node is Ready. Verify security outcomes and reboot requirements separately.'
