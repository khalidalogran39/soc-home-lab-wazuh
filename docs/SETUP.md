# Lab Build Guide

How this lab was built on an Apple Silicon Mac. Commands are the ones actually used.

## 1. Hypervisor and VM
1. Install **VMware Fusion** (free for personal use; Universal build runs natively on Apple Silicon).
2. Download **Ubuntu Server 24.04 LTS — ARM64** ISO (`ubuntu-24.04.x-live-server-arm64.iso`).
   AMD64 images will not boot on Apple Silicon.
3. Create a VM: **4 vCPU · 8 GB RAM · 60 GB disk**, NAT networking (meets Wazuh's all-in-one minimum).
4. Install Ubuntu with the OpenSSH server option, note the VM IP (`hostname -I`).

The VM can run headless from the Mac:

```bash
VMRUN="/Applications/VMware Fusion.app/Contents/Library/vmrun"
VMX=~/"Virtual Machines.localized/SOC Ubuntu ARM64.vmwarevm/SOC Ubuntu ARM64.vmx"
"$VMRUN" start "$VMX" nogui     # start
"$VMRUN" list                   # status
"$VMRUN" stop "$VMX" soft       # clean shutdown
```

## 2. Key-based SSH from the Mac

```bash
ssh-keygen -t ed25519 -f ~/.ssh/soc_lab -C "soc-lab"
ssh-copy-id -i ~/.ssh/soc_lab.pub <user>@<vm-ip>
cat >> ~/.ssh/config <<EOF
Host soc
  HostName <vm-ip>
  User <user>
  IdentityFile ~/.ssh/soc_lab
EOF
ssh soc
```

## 3. Wazuh all-in-one (inside the VM)

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
# admin credentials are stored in wazuh-install-files.tar → wazuh-passwords.txt
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A1 "'admin'"
```

Dashboard: `https://<vm-ip>` (self-signed certificate). Change the `admin` password after first login.

## 4. macOS agent

Download the arm64 package matching the manager version, verify its signature, then install with
enrollment variables:

```bash
curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.9-1.arm64.pkg
pkgutil --check-signature wazuh-agent.pkg        # expect: signed + notarized
echo "WAZUH_MANAGER='<vm-ip>' && WAZUH_AGENT_NAME='my-mac'" > /tmp/wazuh_envs
sudo installer -pkg ./wazuh-agent.pkg -target /
sudo /Library/Ossec/bin/wazuh-control start
```

Verify on the manager:

```bash
ssh soc 'sudo /var/ossec/bin/agent_control -l'
```

## 5. Deploy the custom detections

```bash
# decoder and rules
ssh soc 'sudo tee -a /var/ossec/etc/decoders/local_decoder.xml' < detections/local_decoder.xml
ssh soc 'sudo tee -a /var/ossec/etc/rules/local_rules.xml'     < detections/local_rules.xml
# FIM: paste detections/ossec-syscheck-snippet.xml inside <syscheck> in /var/ossec/etc/ossec.conf
ssh soc 'sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager'
```

Test a decoder/rule without generating a real event:

```bash
ssh soc "echo \"Nov 05 13:17:28 host usermod[1]: add 'test' to group 'sudo'\" | sudo /var/ossec/bin/wazuh-logtest"
```

## 6. Run the scenarios
Each report in [`reports/`](../reports/) has a **Reproduction / Simulation** section with the exact commands
and a cleanup step. Run them only in this isolated lab.
