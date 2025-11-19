# Linux Lab Guide — Zero to Hero

A structured, GitHub-friendly Markdown reformat of the Linux lab guide. Each lab contains Theory, Objectives, Quick Commands / Solutions and Practice exercises. Use this file as the canonical README for the docs/0-Linux lab folder.

---

## Table of Contents

- [Lab 0 — Introduction to Linux](#lab-0---introduction-to-linux)  
- [Lab 1 — Installation & Setup](#lab-1---installation--setup)  
- [Lab 2 — Basic Commands & Navigation](#lab-2---basic-commands--navigation)  
- [Lab 3 — File System & Permissions](#lab-3---file-system--permissions)  
- [Lab 4 — Text Processing & Editors](#lab-4---text-processing--editors)  
- [Lab 5 — Users & Groups Management](#lab-5---users--groups-management)  
- [Lab 6 — Process Management](#lab-6---process-management)  
- [Lab 7 — Package Management](#lab-7---package-management)  
- [Lab 8 — Basic Network Commands](#lab-8---basic-network-commands)  
- [Lab 9 — Shell Scripting Basics](#lab-9---shell-scripting-basics)  
- [Lab 10 — Advanced File Operations](#lab-10---advanced-file-operations)  
- [Lab 11 — System Monitoring](#lab-11---system-monitoring)  
- [Lab 12 — Cron Jobs & Scheduling](#lab-12---cron-jobs--scheduling)  
- [Lab 13 — Log Management](#lab-13---log-management)  
- [Lab 14 — Firewall & Security](#lab-14---firewall--security)  
- [Lab 15 — SSH & Remote Access](#lab-15---ssh--remote-access)  
- [Lab 16 — Disk Management & Mounting](#lab-16---disk-management--mounting)  
- [Lab 17 — Advanced Shell Scripting](#lab-17---advanced-shell-scripting)  
- [Lab 18 — System Services & systemd](#lab-18---system-services--systemd)  
- [Lab 19 — Network Configuration](#lab-19---network-configuration)  
- [Lab 20 — Web Server Setup](#lab-20---web-server-setup)  
- [Lab 21 — Database Administration](#lab-21---database-administration)  
- [Lab 22 — Container Integration](#lab-22---container-integration)  
- [Lab 23 — System Hardening](#lab-23---system-hardening)  
- [Lab 24 — Performance Tuning](#lab-24---performance-tuning)  

---

## How to use
- Open the lab you want to work on and follow the Theory → Practice flow.
- Copy commands into a terminal (or VM) and experiment.
- Add solutions, notes and improvements via PRs to the repo.

---

## Lab 0 - Introduction to Linux

### Overview
- What Linux is, distributions, architecture, and why it matters for security and ops.

### Key points
- Kernel, shell, filesystem hierarchy, users/groups, package manager, everything-is-a-file.

### Next steps
- Install Ubuntu in a VM or use WSL/cloud instance and proceed to Lab 1.

---

## Lab 1 - Installation & Setup

### Objectives
- Install Ubuntu, perform post-install updates, enable firewall, install dev tools.

### Quick commands
```bash
# update & upgrade
sudo apt update && sudo apt upgrade -y

# install essentials
sudo apt install -y curl wget git vim build-essential snapd

# check system info
lsb_release -a
whoami && sudo whoami
df -h && free -h
ip addr show
```

### Practice
- Create user accounts, enable UFW, install snap and common tools.

---

## Lab 2 - Basic Commands & Navigation

### Theory
- Filesystem hierarchy, basic commands: pwd, ls, cd, mkdir, cp, mv, rm, find, locate.

### Examples
```bash
pwd
ls -la
cd ~
mkdir -p lab-practice/docs/projects/web
touch file1.txt file2.txt file3.txt
cp file1.txt docs/
mv file2.txt docs/backup.txt
find . -name "*.txt"
cat file1.txt
man ls
```

---

## Lab 3 - File System & Permissions

### Theory
- Permission model: owner/group/others; read/write/execute; numeric and symbolic modes; special bits (SUID, SGID, sticky).

### Examples
```bash
mkdir permissions-lab && cd permissions-lab
echo "Hello Linux!" > test.txt
ls -l test.txt
chmod 444 test.txt
chmod u+w test.txt
echo '#!/bin/bash' > hello.sh
echo 'echo "Hello from script!"' >> hello.sh
chmod +x hello.sh && ./hello.sh
ln -s test.txt link-to-test
```

---

## Lab 4 - Text Processing & Editors

### Tools
- grep, sed, awk, cut, sort, uniq, vim, nano.

### Examples
```bash
echo -e "2024-01-15 ERROR Something\n2024-01-16 INFO OK" > sample.log
grep ERROR sample.log
awk '{print $1, $2}' sample.log
sed 's/ERROR/CRITICAL/g' sample.log
sort sample.log > sorted.log
```

---

## Lab 5 - Users & Groups Management

### Theory
- /etc/passwd, /etc/shadow, /etc/group, sudo, useradd/usermod/userdel, groups and policies.

### Examples
```bash
id
groups
sudo groupadd developers
sudo useradd -m -s /bin/bash testuser
sudo passwd testuser
sudo usermod -aG developers testuser
sudo userdel -r testuser
```

---

## Lab 6 - Process Management

### Commands
- ps, top, htop, kill, killall, nice, renice, jobs, bg/fg.

### Examples
```bash
ps aux
top
sleep 300 &
jobs
kill $(pgrep sleep)
ps aux --sort=-%cpu | head -n 10
```

---

## Lab 7 - Package Management

### APT basics
```bash
sudo apt update
sudo apt install -y tree htop ncdu tmux
apt list --upgradable
sudo apt autoremove -y
sudo apt clean
```

---

## Lab 8 - Basic Network Commands

### Tools
- ping, curl, wget, ss, netstat, ip, tcpdump, nslookup/dig.

### Examples
```bash
ping -c 4 8.8.8.8
curl -s https://httpbin.org/ip
ss -tuln
sudo tcpdump -i lo -c 20
ip addr show
```

---

## Lab 9 - Shell Scripting Basics

### Goals
- Shebang, variables, args, conditionals, loops, read, functions.

### Example script
```bash
#!/bin/bash
NAME="${1:-User}"
echo "Hello, $NAME"
```

---

## Lab 10 - Advanced File Operations

### Tools
- find, locate, rsync, tar, gzip, bzip2

### Examples
```bash
find . -name "*.txt"
sudo updatedb
rsync -av source/ dest/
tar -czvf testdir.tar.gz testdir
```

---

## Lab 11 - System Monitoring

### Tools
- top/htop, vmstat, iostat, iotop, sar, dmesg, free, df

### Examples
```bash
top -b -n1
vmstat 2 5
iostat -x 1 3
free -h
df -h
```

---

## Lab 12 - Cron Jobs & Scheduling

### Commands
```bash
crontab -l
# add job
(crontab -l 2>/dev/null; echo "* * * * * /tmp/test_cron.sh") | crontab -
systemctl status cron
at now + 2 minutes <<< 'echo "ran" >> /tmp/at_output.log'
```

---

## Lab 13 - Log Management

### Tools
- journalctl, rsyslog, logrotate, tail, logger

### Examples
```bash
journalctl -n 50
journalctl -u ssh -f
tail -f /var/log/syslog
sudo ls -la /etc/logrotate.d
```

---

## Lab 14 - Firewall & Security

### Tools & steps
- ufw, iptables, fail2ban, umask

### Examples
```bash
sudo ufw enable
sudo ufw allow ssh
sudo apt install -y fail2ban
umask 077
```

---

## Lab 15 - SSH & Remote Access

### Key tasks
- Key generation, authorized_keys, permissions, scp/rsync, SSH config.

### Examples
```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
scp file user@host:/tmp/
```

---

## Lab 16 - Disk Management & Mounting

### Commands
- lsblk, fdisk, losetup, mkfs, mount, blkid

### Example
```bash
sudo dd if=/dev/zero of=/tmp/disk.img bs=1M count=1024
sudo losetup /dev/loop0 /tmp/disk.img
sudo fdisk /dev/loop0   # create partition
sudo partprobe /dev/loop0
sudo mkfs.ext4 /dev/loop0p1
sudo mkdir -p /mnt/testdisk
sudo mount /dev/loop0p1 /mnt/testdisk
```

---

## Lab 17 - Advanced Shell Scripting

### Topics
- set -euo pipefail, traps, logging, retries, parallel execution, config parsing.

### Snippet
```bash
set -euo pipefail
trap 'echo "exiting"; exit' INT TERM EXIT
```

---

## Lab 18 - System Services & systemd

### Tasks
- Create unit files, timers, manage services, journalctl troubleshooting.

### Example unit
```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=My App
After=network.target

[Service]
ExecStart=/usr/bin/env bash -c 'while true; do echo hello; sleep 60; done'
Restart=always

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl start myapp
sudo systemctl enable myapp
journalctl -u myapp -f
```

---

## Lab 19 - Network Configuration

### Topics
- ip command, routing, netns, veth, bridging, bond.

### Examples
```bash
ip addr show
ip route show
sudo ip netns add testns
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns testns
```

---

## Lab 20 - Web Server Setup

### Tasks
- Install Apache/Nginx, virtual hosts, SSL (self-signed), reverse proxy.

### Examples
```bash
sudo apt install -y apache2
sudo a2ensite example.conf
sudo a2enmod ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/self.key -out /etc/ssl/certs/self.crt \
  -subj "/CN=localhost"
```

---

## Lab 21 - Database Administration

### Tasks
- Install MySQL/Postgres, users, backups.

### Examples
```bash
sudo apt install -y mysql-server
sudo mysql -e "CREATE DATABASE testdb;"
sudo mysql -e "CREATE USER 'testuser'@'localhost' IDENTIFIED BY 'pass'; GRANT ALL ON testdb.* TO 'testuser'@'localhost';"
mysqldump -u testuser -p testdb > /tmp/testdb.sql
```

---

## Lab 22 - Container Integration

### Tasks
- Docker basics, networks, volumes, compose, systemd integration.

### Examples
```bash
docker --version
docker network create myapp-network
docker run -d --name mydb --network myapp-network -e MYSQL_ROOT_PASSWORD=root mysql:8
docker build -t myapp .
docker-compose up -d
```

---

## Lab 23 - System Hardening

### Topics
- UFW/firewall rules, auditd, fail2ban, kernel sysctl hardening, SUID/SGID review, unattended-upgrades.

### Examples
```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo apt install -y auditd fail2ban unattended-upgrades
sudo tee /etc/sysctl.d/99-security.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
EOF
sudo sysctl --system
```

---

## Lab 24 - Performance Tuning

### Topics
- Baseline metrics, iostat/vmstat/perf, sysctl tuning, file descriptor limits, profiling.

### Examples
```bash
top
iostat -x 1 3
vmstat 1 5
sudo tee /etc/sysctl.d/99-performance.conf <<'EOF'
fs.file-max = 2097152
vm.swappiness = 10
net.core.rmem_max = 134217728
EOF
sudo sysctl --system
```

---

## References & Further Reading
- NIST, SANS DFIR courses, Volatility, MITRE ATT&CK, Docker docs, systemd documentation, official distro guides (Ubuntu, RHEL).

---

Notes:
- This file is reformatted to Markdown with consistent headings, code blocks and relative links for the repo.
- If you want the original raw content preserved, create a backup (e.g., Linux-Lab.md.orig) before replacing the file.
- I can expand any lab to include full step-by-step solutions and screenshots on request.

