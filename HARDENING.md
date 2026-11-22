# PersistenceScanner - System Hardening & Remediation Guide

This document provides actionable system hardening and remediation measures mapped directly to all detection rules in **PersistenceScanner** (`rules.json`).

---

## ⚠️ Disclaimer & Operational Warning

* **Context-Dependent Configuration:** The commands and configurations below are not universally applicable to every Linux environment. Hardening measures must be tailored to the specific operational role of the host (e.g., production web server, database node, CI/CD runner, or workstation).
* **Users, Groups & Distribution Differences:** System user accounts, service accounts, and default administrative groups (e.g., `sudo` vs. `wheel`, `adm`) vary across Linux distributions and organizational setups. Always adapt ownership, group assignments, and allowlists (such as `/etc/cron.allow`) to match your local identity and privilege model.
* **Risk of Service Disruption:** Aggressive hardening controls—such as mounting `/tmp` or `/dev/mqueue` with `noexec`, enabling `KillUserProcesses=yes`, or enforcing strict egress firewall rules—can break legitimate applications, background worker sessions (`screen`/`tmux`), package managers, and automated scripts.
* **Testing & Backups Required:** Always validate changes in a staging environment before applying them to production. Create backups of critical configuration files (especially `/etc/fstab`, `/etc/pam.d/`, `/etc/sudoers`, and `/etc/systemd/logind.conf`) and maintain an active out-of-band root session when modifying authentication or firewall policies.

---

## 1. Filesystem, Temporary Directories & POSIX Message Queues

*Mitigates: Execution of hidden payloads from `/tmp`, `/dev/shm`, `/var/tmp`, `/run/user`, POSIX message queue execution (`/dev/mqueue`), and immutable/append-only file attribute abuse (`chattr +i` / `+a`).*

### Mount Temporary Directories & `/dev/mqueue` with `noexec`
Prevent direct binary and script execution from world-writable temporary locations and POSIX message queues by updating `/etc/fstab` and remounting:

```bash
# Example entries for /etc/fstab
tmpfs   /tmp         tmpfs   defaults,rw,nosuid,nodev,noexec,relatime  0 0
tmpfs   /var/tmp     tmpfs   defaults,rw,nosuid,nodev,noexec,relatime  0 0
tmpfs   /dev/shm     tmpfs   defaults,rw,nosuid,nodev,noexec,relatime  0 0
mqueue  /dev/mqueue  mqueue  defaults,rw,nosuid,nodev,noexec,relatime  0 0

# Apply changes immediately
sudo mount -o remount,noexec,nosuid,nodev /tmp
sudo mount -o remount,noexec,nosuid,nodev /var/tmp
sudo mount -o remount,noexec,nosuid,nodev /dev/shm
sudo mount -o remount,noexec,nosuid,nodev /dev/mqueue
```

### Drop `CAP_LINUX_IMMUTABLE` in Services & Monitor File Attributes
Prevent compromised services from setting immutable attributes (`chattr +i` / `+a`) and audit attribute modifications via `auditd`:

```bash
# Add to Systemd unit [Service] section to block chattr +i/+a
CapabilityBoundingSet=~CAP_LINUX_IMMUTABLE

# Monitor file attribute changes (ioctl) using auditd
sudo auditctl -a always,exit -F arch=b64 -S ioctl -F a1=0x40086602 -k file_attr_change
```

---

## 2. Process, Interpreter, Binary Tools & Network Controls

*Mitigates: Reverse shells (`nc -e`, `ncat`, `socat`, `bash -i`, `/dev/tcp/`, `/dev/udp/`), fileless piping (`curl/wget | sh`), inline interpreters (`python -c`, `perl -e`, `php -r`, `ruby -e`, `lua -e`), obfuscation & binary reconstruction (`base64/32`, `rev`, `printf \x..`, `xxd -r`, `hexdump`, `od`), and crypto-mining (`xmrig`, `stratum+tcp://`).*

### Enforce Strict Egress Firewall Rules (`nftables`)
Block unauthorized outbound connections to prevent reverse shells, mining pool traffic, and unapproved payload downloads (including `curl -k`):

```bash
# Example nftables egress policy (allow DNS, HTTP/HTTPS only)
sudo nft add table inet filter
sudo nft add chain inet filter output { type filter hook output priority 0 \; policy drop \; }
sudo nft add rule inet filter output ct state established,related accept
sudo nft add rule inet filter output oif "lo" accept
sudo nft add rule inet filter output udp dport 53 accept
sudo nft add rule inet filter output tcp dport { 53, 80, 443 } accept
```

### Remove High-Risk Network Tools & Restrict Binary Reconstruction Utilities
Remove unnecessary relay tools and restrict access to hex/binary dumping utilities used to reconstruct obfuscated payloads:

```bash
# Remove legacy netcat/socat if not required
sudo apt purge -y netcat-traditional socat   # Debian/Ubuntu
sudo dnf remove -y nc socat                  # RHEL/Rocky/Alma

# Restrict binary reconstruction tools (xxd, hexdump, od) to root
sudo chown root:root /usr/bin/xxd /usr/bin/hexdump /usr/bin/od 2>/dev/null
sudo chmod 0750 /usr/bin/xxd /usr/bin/hexdump /usr/bin/od 2>/dev/null
```

### Enforce Application Allowlisting (`fapolicyd`)
Deploy `fapolicyd` to block execution of untrusted binaries (such as `xmrig`) and inline/piped scripts:

```bash
# Enable File Access Policy Daemon (RHEL/Fedora/Rocky)
sudo dnf install -y fapolicyd
sudo systemctl enable --now fapolicyd
```

---

## 3. Authentication & Shared Library Hardening

*Mitigates: `LD_PRELOAD` / `LD_LIBRARY_PATH` hijacking and PAM authentication backdoors (`pam_permit.so`, `pam_exec.so`).*

### Sanitize Environment Variables in `sudo` & Protect `/etc/ld.so.preload`
Ensure privilege escalation resets linker variables and lock down system-wide preload configurations:

```bash
# Verify env_reset is active in /etc/sudoers
echo "Defaults env_reset" | sudo EDITOR='tee -a' visudo

# Lock down /etc/ld.so.preload permissions (if present)
sudo chown root:root /etc/ld.so.preload 2>/dev/null
sudo chmod 0644 /etc/ld.so.preload 2>/dev/null
```

### Audit `/etc/pam.d/` & Verify Package Integrity
Monitor PAM configuration changes in real time and verify that shared libraries have not been tampered with:

```bash
# Enforce strict ownership and permissions on PAM configs
sudo chown -R root:root /etc/pam.d/
sudo chmod 0755 /etc/pam.d/
sudo chmod 0644 /etc/pam.d/*

# Monitor /etc/pam.d/ via auditd
sudo auditctl -w /etc/pam.d/ -p wa -k pam_config_changes

# Verify integrity of installed PAM libraries
dpkg -V libpam-modules 2>/dev/null || rpm -Va pam
```

---

## 4. Scheduled Tasks, D-Bus & Daemon Sandboxing

*Mitigates: Unauthorized `@reboot` tasks, `| at` job queuing, Systemd unit hijacking, D-Bus systemd triggers (`dbus-send`, `busctl` -> `org.freedesktop.systemd1`), Udev `ENV{}` macro evasion, and `/etc/update-motd.d/` backdoors.*

### Restrict Access to `cron` and `at`
Use allowlists so only explicitly authorized accounts can schedule background jobs, or disable `atd` entirely:

```bash
# Restrict cron and at strictly to root
echo "root" | sudo tee /etc/cron.allow > /dev/null
echo "root" | sudo tee /etc/at.allow > /dev/null
sudo chmod 0600 /etc/cron.allow /etc/at.allow

# Disable the 'at' daemon if unused
sudo systemctl disable --now atd
```

### Harden D-Bus Access to `org.freedesktop.systemd1`
Ensure non-root users cannot invoke systemd management methods via `dbus-send` or `busctl`:

```bash
# Create a restrictive D-Bus policy blocking non-root systemd1 manipulation
cat << 'EOF' | sudo tee /etc/dbus-1/system.d/99-restrict-systemd1.conf > /dev/null
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy context="default">
    <deny send_destination="org.freedesktop.systemd1"
          send_interface="org.freedesktop.systemd1.Manager"/>
  </policy>
  <policy user="root">
    <allow send_destination="org.freedesktop.systemd1"/>
  </policy>
</busconfig>
EOF

sudo systemctl reload dbus
```

### Apply Sandboxing Directives to Custom Systemd Units
Harden custom service files in `/etc/systemd/system/` to isolate filesystem and privilege boundaries:

```ini
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

### Lock Down Udev Rules & Dynamic MOTD Scripts
Prevent non-root modification of hardware event triggers (`RUN`, `ENV{}`) and login banners:

```bash
# Enforce strict permissions on Udev rules and MOTD scripts
sudo chown -R root:root /etc/udev/rules.d/ /etc/update-motd.d/
sudo chmod 0755 /etc/udev/rules.d/ /etc/update-motd.d/
sudo chmod 0644 /etc/udev/rules.d/*.rules 2>/dev/null
sudo chmod 0755 /etc/update-motd.d/* 2>/dev/null

# Audit modifications to Udev and MOTD directories
sudo auditctl -w /etc/udev/rules.d/ -p wa -k udev_rule_changes
sudo auditctl -w /etc/update-motd.d/ -p wa -k motd_script_changes
```

---

## 5. Audit Logging, Session Lifecycle & Anti-Forensics Defense

*Mitigates: Shell history tampering (`history -c`, `unset HISTFILE`) and detached background execution (`nohup`).*

### Terminate Detached User Processes on Logout (`nohup` Mitigation)
Configure `systemd-logind` via a drop-in configuration to automatically terminate background processes spawned via `nohup` once a user session ends:

```bash
# Enforce KillUserProcesses=yes via logind.conf.d drop-in
sudo mkdir -p /etc/systemd/logind.conf.d
printf "[Login]\nKillUserProcesses=yes\n" | sudo tee /etc/systemd/logind.conf.d/99-kill-user-processes.conf > /dev/null
sudo systemctl restart systemd-logind
```

### Enforce Immutable Shell History Variables
Prevent users from unsetting or disabling command history logging within interactive shell sessions:

```bash
# Append readonly history enforcement to /etc/profile
cat << 'EOF' | sudo tee -a /etc/profile > /dev/null
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=""
readonly HISTFILE HISTSIZE HISTFILESIZE HISTTIMEFORMAT HISTCONTROL
EOF
```

### Enable Process Execution Auditing (`execve`)
Log all executed commands and arguments at the kernel level so clearing `.bash_history` cannot erase attacker activity:

```bash
# Log all 64-bit process executions via auditd
sudo auditctl -a always,exit -F arch=b64 -S execve -k exec_logging
```