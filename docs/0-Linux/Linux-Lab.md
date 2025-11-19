LINUX LAB GUIDE
ZERO TO HERO



Table of Contents



LINUX LAB GUIDE	1
Table of Contents	2
Lab 0: Introduction to Linux	36
What is Linux?	37
Why Learn Linux?	37
Linux Distributions Overview	37
Linux Architecture	37
Essential Linux Concepts	38
About These Linux Lab Guides	38
Next Step	38
Lab 1: Linux Installation & Setup	38
Important Note	38
What is this lab about?	39
What will you learn?	39
Installation Methods	39
Post-Installation Steps	39
How to test your knowledge	39
Update the package list and upgrade all packages.	39
SOLUTION:	39
Install essential development tools.	39
SOLUTION:	39
Check your Ubuntu version and system information.	40
SOLUTION:	40
Display current user and verify sudo access.	40
SOLUTION:	40
Check available disk space and memory.	40
SOLUTION:	40
View system uptime and load averages.	40
SOLUTION:	40
Display CPU information.	40
SOLUTION:	40
Check network interface configuration.	40
SOLUTION:	40
Install snap package manager and verify.	40
SOLUTION:	40
Enable and start the firewall.	40
SOLUTION:	40
Check running services status.	40
SOLUTION:	40
Create a test directory in your home folder.	40
SOLUTION:	40
Lab 2: Basic Commands & Navigation	40
What is the Linux Command Line?	40
Why Master Command Line Basics?	40
Linux File System Hierarchy	41
Basic Command Structure	41
Essential Navigation Commands	42
File Operations	42
Text Viewing Commands	42
Getting Help	42
Command Line Tips	42
Display your current working directory.	42
SOLUTION:	42
List all files in the current directory, including hidden files.	43
SOLUTION:	43
Navigate to your home directory.	43
SOLUTION:	43
Create a directory named "lab-practice".	43
SOLUTION:	43
Navigate into the lab-practice directory.	43
SOLUTION:	43
Create nested directories "docs/projects/web" in one command.	43
SOLUTION:	43
Create three empty files: file1.txt, file2.txt, file3.txt.	43
SOLUTION:	43
Copy file1.txt to the docs directory.	43
SOLUTION:	43
Move file2.txt to the docs directory and rename it to backup.txt.	43
SOLUTION:	43
Copy the entire docs directory to create a backup called docs-backup.	43
SOLUTION:	43
Find all .txt files in the current directory and subdirectories.	43
SOLUTION:	43
Display the contents of file1.txt (it should be empty).	43
SOLUTION:	43
Get help information for the ls command.	43
SOLUTION:	43
Go back to the parent directory.	43
SOLUTION:	43
Remove the file3.txt file.	43
SOLUTION:	44
Test Your Knowledge	44
What is the difference between absolute and relative paths?	44
How do you list all files including hidden ones?	44
What does the rm -rf command do and why is it dangerous?	44
How do you create nested directories in one command?	45
What is the purpose of the man command?	45
How do you copy a directory and all its contents?	45
Lab 3: File System & Permissions	45
Lab Theory	45
What is the Linux File System?	45
Linux File System Hierarchy Standard (FHS)	45
Understanding File Permissions	46
Permission Representation	46
(700): Owner full access, no others access	47
File Ownership	47
Special Permissions	47
File Types in Linux	47
Practice	47
Create a directory called "permissions-lab" and navigate to it.	47
SOLUTION:	47
Create a file called "test.txt" with some content.	47
SOLUTION:	47
Check the current permissions of test.txt.	48
SOLUTION:	48
Change permissions of test.txt to read-only for all users.	48
SOLUTION:	48
Try to write to the read-only file (this should fail).	48
SOLUTION:	48
Restore write permission for the owner.	48
SOLUTION:	48
Create a script file called "hello.sh" with a simple command.	48
SOLUTION:	48
Make the script executable and run it.	48
SOLUTION:	48
Check the owner and group of your files.	48
SOLUTION:	48
Create a symbolic link to test.txt called "link-to-test".	48
SOLUTION:	48
Display the file type information for all files.	48
SOLUTION:	48
Show disk usage of the current directory.	48
SOLUTION:	48
Find all executable files in the current directory.	48
SOLUTION:	48
Display the inode number of test.txt.	48
SOLUTION:	48
Test Your Knowledge	49
What does the permission 755 mean in numeric notation?	49
What is the difference between chown and chmod?	49
What does the sticky bit do and where is it commonly used?	49
How do you make a file executable for everyone?	49
What is the purpose of the /proc directory?	49
How do symbolic links differ from hard links?	49
Lab 4: Text Processing & Editors	49
Lab Theory	49
Why Text Processing Matters in Linux?	49
Essential Text Processing Tools	49
The Grep Command Family	50
Stream Editor (sed)	51
AWK Programming Language	51
Text Editors Overview	51
Vim Basics	52
Regular Expressions Basics	52
Practice	52
Create a sample data file with some log entries.	52
SOLUTION:	52
Search for all ERROR entries in the log file.	53
SOLUTION:	53
Search for ERROR entries and show line numbers.	53
SOLUTION:	53
Find all lines that do NOT contain ERROR.	53
SOLUTION:	53
Count how many lines contain the word "INFO".	53
SOLUTION:	53
Extract only the date (first field) from each line using awk.	53
SOLUTION:	53
Extract the date and log level (first two fields) using awk.	53
SOLUTION:	53
Replace all occurrences of "ERROR" with "CRITICAL" using sed.	53
SOLUTION:	53
Sort the log file by date and save to sorted.log.	53
SOLUTION:	53
Count the total number of lines, words, and characters in sample.log.	53
SOLUTION:	53
Create a file called "practice.txt" using nano editor with some content.	53
SOLUTION:	53
Use sed to delete all lines containing "INFO" from the log.	54
SOLUTION:	54
Extract unique log levels from the second column.	54
SOLUTION:	54
Find lines that start with "2024-01-16" using grep.	54
SOLUTION:	54
Count how many different dates appear in the log.	54
SOLUTION:	54
Test Your Knowledge	54
What is the difference between grep, egrep, and fgrep?	54
How do you search for a pattern recursively in all files under a directory?	54
What does the sed command "sed -i 's/old/new/g' file" do?	55
How do you print only the 3rd column of a CSV file using awk?	55
What are the main modes in vim and how do you switch between them?	55
How do you count the number of lines, words, and characters in a file?	55
Lab 5: Users & Groups Management	55
Lab Theory	55
What is Linux Multi-User System?	55
Why User Management Matters?	55
User Account Types	56
User Account Information	56
Essential User Commands	56
Group Management	56
Group Commands	57
sudo Configuration	57
Password Policies	57
Best Practices	58
Practice	58
Display information about the current user.	58
SOLUTION:	58
Show which groups the current user belongs to.	58
SOLUTION:	58
Display the contents of /etc/passwd for your user.	58
SOLUTION:	58
Create a new group called "developers".	58
SOLUTION:	58
Create a new user called "testuser" with bash shell.	58
SOLUTION:	58
Set a password for the testuser account.	58
SOLUTION:	58
Add testuser to the developers group.	58
SOLUTION:	58
Verify testuser is in the developers group.	59
SOLUTION:	59
Create a directory owned by the developers group.	59
SOLUTION:	59
Set group write permissions on the dev-project directory.	59
SOLUTION:	59
Switch to the testuser account and test access.	59
SOLUTION:	59
List all users on the system (extract from /etc/passwd).	59
SOLUTION:	59
Find all files owned by testuser.	59
SOLUTION:	59
Lock the testuser account.	59
SOLUTION:	59
Delete the testuser account and home directory.	59
SOLUTION:	59
Test Your Knowledge	59
What is the difference between su and sudo?	59
Where are user passwords stored and why?	59
What is the significance of UID 0?	59
How do you add a user to multiple groups during account creation?	60
What happens to a user's files when you delete their account?	60
How do you temporarily switch to a different primary group?	60
Lab 6: Process Management	60
Lab Theory	60
What are Linux Processes?	60
Why Process Management Matters?	60
Process States	61
Essential Process Commands	61
Process Control	62
System Monitoring	62
Practice	62
Display all running processes in detailed format.	62
SOLUTION:	62
Show processes in a tree format to see parent-child relationships.	62
SOLUTION:	62
Start the top command to monitor processes in real-time.	62
SOLUTION:	62
Find the process ID of the bash shell.	62
SOLUTION:	62
Display current system uptime and load averages.	62
SOLUTION:	62
Show memory usage information.	62
SOLUTION:	62
Start a long-running sleep command in the background.	62
SOLUTION:	62
List current background jobs.	62
SOLUTION:	62
Find the PID of the sleep process.	62
SOLUTION:	62
Kill the sleep process using its PID.	62
SOLUTION:	62
Start another sleep process and suspend it with Ctrl+Z.	62
SOLUTION:	62
Resume the suspended job in the background.	62
SOLUTION:	62
Display processes owned by the current user.	62
SOLUTION:	62
Kill all sleep processes at once.	62
SOLUTION:	62
Show the most CPU-intensive processes.	62
SOLUTION:	62
Test Your Knowledge	62
What is the difference between kill and killall commands?	62
How do you run a command in the background?	63
What does the load average represent in the uptime command?	63
How do you find processes consuming the most CPU?	63
What is a zombie process and how do you handle it?	63
Lab 7: Package Management	63
Lab Theory	63
What is Package Management?	63
Why Package Management Matters?	63
APT Package Manager	64
Essential APT Commands	64
Package Repositories	65
Package States	65
Practice	65
Update the package database.	65
SOLUTION:	65
Show upgradeable packages.	65
SOLUTION:	65
Search for packages related to "network".	66
SOLUTION:	66
Install the tree command utility.	66
SOLUTION:	66
Show detailed information about the tree package.	66
SOLUTION:	66
List all installed packages.	66
SOLUTION:	66
Install multiple packages: htop, ncdu, and tmux.	66
SOLUTION:	66
Check which files are installed by the tree package.	66
SOLUTION:	66
Find which package provides the /bin/ls command.	66
SOLUTION:	66
Remove the ncdu package but keep its configuration.	66
SOLUTION:	66
Show packages that can be automatically removed.	66
SOLUTION:	66
Clean the package cache.	66
SOLUTION:	66
Check for broken packages.	66
SOLUTION:	66
Hold the tmux package to prevent updates.	66
SOLUTION:	66
Show held packages.	67
SOLUTION:	67
Test Your Knowledge	67
What is the difference between apt remove and apt purge?	67
Why should you run apt update before apt upgrade?	67
What is a PPA and when would you use it?	67
How do you fix broken package dependencies?	67
What does apt autoremove do?	68
Lab 8: Basic Network Commands	68
Lab Theory	68
What is this lab about?	68
What will you learn?	68
Process Flow	69
Practice	69
Test connectivity to Google DNS server.	69
SOLUTION:	69
Download a test file using wget.	69
SOLUTION:	69
Use curl to fetch and display webpage content.	69
SOLUTION:	69
Download a file with curl and save with a specific name.	69
SOLUTION:	69
Check all listening TCP ports.	69
SOLUTION:	69
Use ss to show listening sockets.	70
SOLUTION:	70
Show all active network connections.	70
SOLUTION:	70
Check if a specific port is listening.	70
SOLUTION:	70
View current iptables rules.	70
SOLUTION:	70
Add a rule to allow HTTP traffic.	70
SOLUTION:	70
Test connectivity to a specific port using telnet.	70
SOLUTION:	70
Download a file quietly with wget.	70
SOLUTION:	70
Check network interface configuration.	70
SOLUTION:	70
Test DNS resolution for a domain.	70
SOLUTION:	70
Show routing table.	70
SOLUTION:	70
Test Your Knowledge	70
What is the difference between ping and wget commands?	70
When would you use ss instead of netstat?	70
What does the -c option do in the ping command?	70
How do iptables rules work in terms of order?	70
What is the purpose of the curl -o option?	70
Lab 9: Shell Scripting Basics	70
Lab Theory	70
What is this lab about?	70
What will you learn?	71
Process Flow	71
Practice	71
Create and execute a simple "Hello, World!" shell script.	71
SOLUTION:	71
Create a script that uses a variable to store a name and print a greeting.	71
SOLUTION:	71
Create a script that accepts a command-line argument and prints it.	71
SOLUTION:	71
Create a script that uses an `if` statement to check if a file exists.	72
SOLUTION:	72
Create a script that uses a `for` loop to print numbers from 1 to 5.	72
SOLUTION:	72
Create a script that reads input from the user.	72
SOLUTION:	72
What is the purpose of the `#!/bin/bash` line at the beginning of a script?	72
What is the difference between `$*` and `$@` in a shell script?	72
How do you check the exit status of the last command that was run?	73
What is the difference between single quotes (`'`) and double quotes (`"`) in shell scripting?	73
Lab 10: Advanced File Operations	73
Lab Theory	73
What is this lab about?	73
What will you learn?	73
Process Flow	73
Practice	74
Create a test directory structure with files.	74
SOLUTION:	74
Find all .txt files in testdir.	74
SOLUTION:	74
Find all files modified in the last 5 minutes.	74
SOLUTION:	74
Find files and execute ls -l on them.	74
SOLUTION:	74
Update the locate database.	74
SOLUTION:	74
Use locate to find bash executable.	74
SOLUTION:	74
Create a backup directory and sync with rsync.	74
SOLUTION:	74
Create a tar archive of testdir.	74
SOLUTION:	74
Create a gzipped tar archive.	74
SOLUTION:	74
List contents of the tar archive.	74
SOLUTION:	74
Extract the archive to a new location.	74
SOLUTION:	74
Find and delete empty directories.	74
SOLUTION:	74
Create a bzip2 compressed archive.	75
SOLUTION:	75
Sync directories with delete option.	75
SOLUTION:	75
Find files larger than 1KB.	75
SOLUTION:	75
Test Your Knowledge	75
What is the difference between find and locate commands?	75
What does the rsync -av option combination do?	75
What is the difference between tar.gz and tar.bz2 files?	75
How does the find command's -exec option work?	75
What is the purpose of rsync's --delete option?	76
Lab 11: System Monitoring	76
Lab Theory	76
What is this lab about?	76
What will you learn?	76
Process Flow	76
Practice	77
Display current system processes with top.	77
SOLUTION:	77
Check current system load and uptime.	77
SOLUTION:	77
Display memory usage information.	77
SOLUTION:	77
Show disk usage by filesystem.	77
SOLUTION:	77
Display directory size information.	77
SOLUTION:	77
Monitor system activity with vmstat.	77
SOLUTION:	77
Check I/O statistics with iostat.	77
SOLUTION:	77
Display current network connections.	77
SOLUTION:	77
Show processes by CPU usage.	77
SOLUTION:	77
Show processes by MEMORY usage.	77
SOLUTION:	77
Check system temperature (if available).	78
SOLUTION:	78
Monitor real-time process activity.	78
SOLUTION:	78
Display system information.	78
SOLUTION:	78
Check logged in users.	78
SOLUTION:	78
Display kernel ring buffer messages.	78
SOLUTION:	78
Check CPU information.	78
SOLUTION:	78
Test Your Knowledge	78
What is the difference between top and htop commands?	78
What does the load average numbers represent in system monitoring?	78
What is the purpose of the vmstat command?	79
How does iotop help in system monitoring?	79
What information does the sar command provide?	79
Lab 12: Cron Jobs & Scheduling	79
Lab Theory	79
What is this lab about?	79
What will you learn?	79
Process Flow	79
Practice	79
View current user cron jobs.	79
SOLUTION:	79
Create a test script for cron jobs.	79
SOLUTION:	79
Add a cron job that runs every minute.	79
SOLUTION:	80
Wait and check if cron job created log file.	80
SOLUTION:	80
View the contents of the cron log.	80
SOLUTION:	80
Add a daily cron job.	80
SOLUTION:	80
Add a weekly cron job.	80
SOLUTION:	80
List updated cron jobs.	80
SOLUTION:	80
Check system cron directories.	80
SOLUTION:	80
Schedule a one-time task with at.	80
SOLUTION:	80
List scheduled at jobs.	80
SOLUTION:	80
Check cron service status.	80
SOLUTION:	80
View system cron logs.	80
SOLUTION:	80
Wait and check at job output.	80
SOLUTION:	80
Remove the test cron jobs.	80
SOLUTION:	80
Test Your Knowledge	81
What do the five fields in a crontab entry represent?	81
What is the difference between crontab -e and crontab -l?	81
How do systemd timers differ from traditional cron jobs?	81
What does the at command do?	81
Where are system-wide cron jobs typically stored?	82
Lab 13: Log Management	82
Lab Theory	82
What is this lab about?	82
What will you learn?	82
Process Flow	83
Practice	83
View recent system journal entries.	83
SOLUTION:	83
Check kernel messages from current boot.	83
SOLUTION:	83
View logs for a specific service.	83
SOLUTION:	83
Show logs from the last hour.	83
SOLUTION:	83
View system log file directly.	83
SOLUTION:	83
Monitor syslog in real-time.	83
SOLUTION:	83
Check authentication logs.	83
SOLUTION:	83
Generate a test log entry.	83
SOLUTION:	83
Search for the test log entry.	83
SOLUTION:	83
View disk usage of journal logs.	83
SOLUTION:	83
Check logrotate configuration.	83
SOLUTION:	83
View rsyslog configuration.	83
SOLUTION:	83
Show logs with priority level.	83
SOLUTION:	83
Check systemd service failures.	83
SOLUTION:	83
Stop the background tail process.	83
SOLUTION:	83
Test Your Knowledge	83
What is the difference between journalctl and traditional log files?	83
How does log rotation prevent disk space issues?	84
Basic Example of a Logrotate Configuration	84
What is rsyslog and how does it work?	84
What does the --follow option do in journalctl?	84
Where are systemd journal files stored?	84
Lab 14: Firewall & Security	84
Lab Theory	84
What is this lab about?	85
What will you learn?	85
Process Flow	85
Practice	86
Check UFW status.	86
SOLUTION:	86
Enable UFW firewall.	86
SOLUTION:	86
Allow SSH connections through firewall.	86
SOLUTION:	86
Allow HTTP traffic on port 80.	86
SOLUTION:	86
Allow HTTPS traffic on port 443.	86
SOLUTION:	86
Check updated UFW status.	86
SOLUTION:	86
Check current iptables rules.	86
SOLUTION:	86
Check if fail2ban is installed.	86
SOLUTION:	86
Install fail2ban (if not present).	86
SOLUTION:	86
Check fail2ban service status.	86
SOLUTION:	86
View fail2ban configuration directory.	86
SOLUTION:	86
Check current fail2ban jails.	87
SOLUTION:	87
Check system login attempts.	87
SOLUTION:	87
Set strict umask for security.	87
SOLUTION:	87
Check current umask setting.	87
SOLUTION:	87
Test Your Knowledge	87
What is the difference between UFW and iptables?	87
How does fail2ban protect against brute-force attacks?	87
What is the purpose of the principle of least privilege?	87
What does the umask command control?	87
Why is it important to keep software updated for security?	88
Lab 15: SSH & Remote Access	88
Lab Theory	88
What is this lab about?	88
What will you learn?	88
Process Flow	89
Practice	89
Check SSH client version.	89
SOLUTION:	89
Check SSH server status.	89
SOLUTION:	89
Generate SSH key pair.	89
SOLUTION:	89
List SSH keys in .ssh directory.	89
SOLUTION:	89
View public key content.	89
SOLUTION:	89
Add public key to authorized keys.	89
SOLUTION:	89
Set correct permissions on SSH files.	89
SOLUTION:	89
Test SSH connection to localhost.	89
SOLUTION:	89
Create test files for transfer.	89
SOLUTION:	89
Copy file using scp to another location.	89
SOLUTION:	90
Verify scp transfer worked.	90
SOLUTION:	90
Use rsync for directory synchronization.	90
SOLUTION:	90
Check SSH connection attempts in logs.	90
SOLUTION:	90
Show SSH configuration options.	90
SOLUTION:	90
Check active SSH connections.	90
SOLUTION:	90
Test Your Knowledge	90
What is the difference between SSH keys and password authentication?	90
What do the scp, sftp, and rsync commands do differently?	90
What is SSH tunneling and when would you use it?	90
What files contain SSH client and server configurations?	90
What is the purpose of the SSH agent?	90
Lab 16: Disk Management & Mounting	90
Lab Theory	91
What is this lab about?	91
What will you learn?	91
Process Flow	91
Practice	91
List all available disk devices and their partitions.	91
SOLUTION:	91
Display detailed disk information using fdisk.	91
SOLUTION:	91
Check disk space usage for all mounted filesystems.	91
SOLUTION:	91
Create a 1GB file to simulate a disk for practice.	91
SOLUTION:	91
Set up the file as a loop device.	91
SOLUTION:	91
Create a new partition table on the loop device using fdisk.	92
SOLUTION:	92
Update the kernel partition table.	92
SOLUTION:	92
Create an ext4 filesystem on the first partition.	92
SOLUTION:	92
Create a mount point directory.	92
SOLUTION:	92
Mount the filesystem to the mount point.	92
SOLUTION:	92
Verify the mount and check available space.	92
SOLUTION:	92
Create a test file in the mounted filesystem.	92
SOLUTION:	92
Display the UUID of the filesystem.	92
SOLUTION:	92
Create a temporary fstab entry (simulation).	92
SOLUTION:	92
Unmount the filesystem safely.	92
SOLUTION:	92
Check if any processes are using the mount point.	92
SOLUTION:	92
Detach the loop device.	92
SOLUTION:	92
Show current mount points and their options.	93
SOLUTION:	93
Test Your Knowledge	93
What is the difference between a physical partition and a logical volume in LVM?	93
What is the purpose of the /etc/fstab file?	93
What are the advantages of LVM over traditional partitioning?	93
What is the difference between ext4 and xfs filesystems?	94
How do you permanently mount a filesystem in Linux?	94
What is a swap partition and when would you use swap files instead?	94
Lab 17: Advanced Shell Scripting	94
Lab Theory	94
What is this lab about?	94
What will you learn?	94
Process Flow	95
Practice	95
Create a script with proper shebang and error handling setup.	95
SOLUTION:	95
Add a function to log messages with timestamps.	95
SOLUTION:	95
Add a cleanup function to handle script termination.	95
SOLUTION:	95
Add parameter validation function.	95
SOLUTION:	95
Add a function to check if a command exists.	96
SOLUTION:	96
Create a retry mechanism function.	96
SOLUTION:	96
Add array processing function.	96
SOLUTION:	96
Add configuration file parser.	97
SOLUTION:	97
Add main script logic with command line parsing.	97
SOLUTION:	97
Make the script executable.	97
SOLUTION:	97
Create a simple config file for testing.	97
SOLUTION:	97
Test the script with help option.	97
SOLUTION:	97
Create a debug version that shows variable values.	98
SOLUTION:	98
Add input validation with regex.	98
SOLUTION:	98
Test script syntax without execution.	98
SOLUTION:	98
Create a performance monitoring function.	98
SOLUTION:	98
Add parallel processing capability.	98
SOLUTION:	98
Create a comprehensive test of all functions.	98
SOLUTION:	98
Test Your Knowledge	99
What is the difference between $@ and $* in bash scripting?	99
How do you implement proper error handling in bash scripts?	99
What are the benefits of using functions in shell scripts?	99
How do you debug a shell script effectively?	99
What is the purpose of trap in shell scripting?	99
How do you handle command-line arguments robustly in bash?	100
Lab 18: System Services & Systemd	100
Lab Theory	100
What is this lab about?	100
What will you learn?	100
Process Flow	101
Practice	101
List all active systemd services.	101
SOLUTION:	101
Show the status of the SSH service.	102
SOLUTION:	102
Show the status of the SSH service.	106
SOLUTION:	106
List all failed services.	106
SOLUTION:	106
Create a simple custom service unit file.	106
SOLUTION:	106
Reload systemd configuration to recognize new service.	106
SOLUTION:	106
Start the custom service.	106
SOLUTION:	106
Enable the service to start at boot.	107
SOLUTION:	107
View logs for your custom service.	107
SOLUTION:	107
Create a service with environment variables.	107
SOLUTION:	107
Create an environment file for the webapp service.	108
SOLUTION:	108
Create a timer unit to run a service periodically.	108
SOLUTION:	108
Create the corresponding backup service.	108
SOLUTION:	108
Enable and start the backup timer.	108
SOLUTION:	108
List all active timers.	108
SOLUTION:	108
Create a service with security restrictions.	108
SOLUTION:	108
Analyze service startup times.	109
SOLUTION:	109
Show service dependency tree for a target.	109
SOLUTION:	109
Stop and disable all custom services.	109
SOLUTION:	109
Test Your Knowledge	109
What is the difference between starting and enabling a systemd service?	109
What are systemd targets and how do they relate to runlevels?	109
How does systemd handle service dependencies?	110
What are the advantages of systemd over traditional init systems?	110
How do you troubleshoot a failing systemd service?	110
What is socket activation in systemd?	110
Lab 19: Network Configuration	110
Lab Theory	110
What is this lab about?	110
What will you learn?	111
Process Flow	111
Practice	111
Display all network interfaces and their configurations.	111
SOLUTION:	112
Show routing table information.	112
SOLUTION:	112
Display network interface statistics.	112
SOLUTION:	112
Check connectivity to a remote host.	112
SOLUTION:	112
Perform DNS lookup using dig.	112
SOLUTION:	112
Show DNS configuration.	112
SOLUTION:	112
Display network connections and listening ports.	112
SOLUTION:	112
Trace route to a destination.	112
SOLUTION:	112
Create a temporary IP alias on an interface.	112
SOLUTION:	112
Add a temporary static route.	112
SOLUTION:	112
Check ARP table entries.	112
SOLUTION:	112
Monitor network traffic on an interface.	112
SOLUTION:	112
Check network interface link status.	112
SOLUTION:	112
Configure a network namespace for testing.	112
SOLUTION:	112
Execute a command inside the network namespace.	112
SOLUTION:	112
Create a virtual ethernet pair.	112
SOLUTION:	112
Move one end of veth pair to namespace.	112
SOLUTION:	112
Configure IP addresses on veth interfaces.	112
SOLUTION:	112
Configure the interface inside the namespace.	112
SOLUTION:	112
Test connectivity between namespace and host.	112
SOLUTION:	112
Show network statistics and counters.	112
SOLUTION:	112
Test bandwidth using iperf3 (if available).	113
SOLUTION:	113
Test Your Knowledge	113
What is the difference between the ip and ifconfig commands?	113
How does network bonding improve network reliability?	113
What are the differences between static and dynamic routing?	113
How do you troubleshoot DNS resolution issues in Linux?	113
What is the purpose of the /etc/hosts file?	114
How do VLANs work at the Linux level?	114
Lab 20: Web Server Setup	114
Lab Theory	114
What is this lab about?	114
What will you learn?	115
Process Flow	115
Practice	116
Update package repository and install Apache.	116
SOLUTION:	116
Start and enable Apache service.	116
SOLUTION:	116
Check Apache service status.	116
SOLUTION:	116
Test Apache default page.	116
SOLUTION:	116
Create a custom website directory.	116
SOLUTION:	116
Create a simple HTML page.	116
SOLUTION:	116
Set proper ownership for web files.	117
SOLUTION:	117
Create Apache virtual host configuration.	117
SOLUTION:	117
Enable the new virtual host.	117
SOLUTION:	117
Disable the default Apache site.	117
SOLUTION:	117
Test Apache configuration syntax.	118
SOLUTION:	118
Reload Apache configuration.	118
SOLUTION:	118
Install Nginx alongside Apache (on different port).	118
SOLUTION:	118
Configure Nginx to run on port 8080.	118
SOLUTION:	118
Create Nginx server block for custom site.	118
SOLUTION:	118
Create directory and content for Nginx site.	118
SOLUTION:	118
Enable Nginx site and set permissions.	118
SOLUTION:	118
Test Nginx configuration.	118
SOLUTION:	118
Start Nginx service.	118
SOLUTION:	118
Test both web servers.	118
SOLUTION:	118
Generate self-signed SSL certificate.	119
SOLUTION:	119
Enable Apache SSL module.	1
SOLUTION:	1
Create HTTPS virtual host.	1
SOLUTION:	1
Enable HTTPS site and reload Apache.	1
SOLUTION:	1
Test Your Knowledge	1
What are the main differences between Apache and Nginx?	1
What is a virtual host and why is it useful?	1
How does SSL/TLS encryption work in web servers?	1
What is a reverse proxy and when would you use Nginx as one?	1
How do you troubleshoot web server performance issues?	1
What security measures should be implemented for production web servers?	1
Lab 21: Database Administration	1
Lab Theory	1
What is this lab about?	1
What will you learn?	1
Process Flow	1
Practice	1
Update package repository.	1
SOLUTION:	1
Install MySQL server.	1
SOLUTION:	1
Start and enable MySQL service.	1
SOLUTION:	1
Check MySQL service status.	1
SOLUTION:	1
Connect to MySQL and show databases.	1
SOLUTION:	1
Create a new MySQL database.	1
SOLUTION:	1
Create a MySQL user with password.	1
SOLUTION:	1
Grant privileges to the MySQL user.	1
SOLUTION:	1
Flush MySQL privileges.	1
SOLUTION:	1
Test connection with new user.	1
SOLUTION:	1
Start and enable PostgreSQL service.	1
SOLUTION:	1
Switch to postgres user and access PostgreSQL.	1
SOLUTION:	1
Create a PostgreSQL database.	1
SOLUTION:	1
Create a PostgreSQL user.	1
SOLUTION:	1
Grant database privileges to PostgreSQL user.	1
SOLUTION:	1
Create a simple table in MySQL.	1
SOLUTION:	1
Insert sample data into MySQL table.	1
SOLUTION:	1
Query data from MySQL table.	1
SOLUTION:	1
Create backup of MySQL database.	1
SOLUTION:	1
Create a PostgreSQL table and insert data.	1
SOLUTION:	1
Create backup of PostgreSQL database.	1
SOLUTION:	1
Show MySQL process list.	1
SOLUTION:	1
Check PostgreSQL active connections.	1
SOLUTION:	1
Test database backup restoration.	1
SOLUTION:	1
Test Your Knowledge	1
What are the main differences between MySQL and PostgreSQL?	1
What is the purpose of database normalization?	1
How do you secure a database server?	1
What are the different types of database backups?	1
What is a database transaction and ACID properties?	1
How do you troubleshoot database performance issues?	1
Lab 22: Container Integration	1
Lab Theory	1
What is this lab about?	1
What will you learn?	1
Process Flow	1
Practice	1
Verify Docker installation and version.	1
SOLUTION:	1
Display Docker system information.	1
SOLUTION:	1
Create a custom Docker network.	1
SOLUTION:	1
List all Docker networks.	1
SOLUTION:	1
Create a named Docker volume.	1
SOLUTION:	1
List all Docker volumes.	1
SOLUTION:	1
Run a database container with volume and network.	1
SOLUTION:	1
Create a simple web application container.	1
SOLUTION:	1
Create HTML content for the web app.	1
SOLUTION:	1
Test web application accessibility.	1
SOLUTION:	1
Check container logs.	1
SOLUTION:	1
Execute command inside running container.	1
SOLUTION:	1
Monitor container resource usage.	1
SOLUTION:	1
Create a Dockerfile for custom application.	1
SOLUTION:	1
Create a simple Node.js application files.	1
SOLUTION:	1
Build custom Docker image.	1
SOLUTION:	1
Run the custom application container.	1
SOLUTION:	1
Test the custom application health check.	1
SOLUTION:	1
Create a Docker Compose file.	1
SOLUTION:	1
Create systemd service for Docker container.	1
SOLUTION:	1
Enable the container systemd service.	1
SOLUTION:	1
Inspect Docker network configuration.	1
SOLUTION:	1
View container processes from host.	1
SOLUTION:	1
Clean up unused Docker resources.	1
SOLUTION:	1
Test Your Knowledge	1
What are the different Docker networking modes and when would you use each?	1
What is the difference between Docker volumes and bind mounts?	1
How do you ensure container security in production?	1
What are the benefits of using multi-stage Docker builds?	1
How do you monitor container performance and health?	1
What is container orchestration and why is it important?	1
Lab 23: System Hardening	1
Lab Theory	1
What is this lab about?	1
What will you learn?	1
Process Flow	1
Practice	1
Check current firewall status.	1
SOLUTION:	1
Enable and configure UFW firewall.	1
SOLUTION:	1
Allow SSH through the firewall.	1
SOLUTION:	1
Allow specific ports for web services.	1
SOLUTION:	10
1Check listening ports and services.	1
SOLUTION:	10
1Disable unnecessary services.	1
SOLUTION:	10
1Configure password policy.	1
SOLUTION:	10
1Set password aging policy.	1
SOLUTION:	10
1Install and configure fail2ban.	1
SOLUTION:	10
1Configure fail2ban for SSH protection.	1
SOLUTION:	10
1Install and configure auditd.	1
SOLUTION:	10
1Configure audit rules for file monitoring.	1
SOLUTION:	10
1Secure shared memory.	109O1LUTION:	109
Cf1igure kernel parameters for security.	1TION:	109
App 1kernel security settings.	110
SOLUTN1:	110
Secure l1e permissions for important files.	110
SOLUTION:110
Find and ser1e SUID/SGID files.	110
SOLUTION:	1
Configure aum1atic security updates.	110
SOLUTION:	1etup log monir1ing.	110
SOLUTION:	110
Chk1 for rootkitsn1d malware.	111
SOLUTION:	111
Confige1 SSH hardenin	1111
SOLUTION:	111
Test SSH cf1iguration.	11
1SOLUTION:	111
Check system r1 security comi1ance.	111
SOLUTION:	111
Review security st1us summary.	1
1SOLUTION:	111
Test Your Knowledge	11
What is ther1inciple of least privile1 and how do you implement it in Linux?	1ables and firewalld?	112
How does Linux audit system (auditd) he 1with security?	112
What is SELinux and how does it enhance su1rity?	112
How do you secure SSH access to a Linux serr1?	112
What are some key indicators of a compromisedi1nux system?	112
Lab 24: Performance Tuning	113
Lab Theory	113
Wt1 is this lab about?	113
What wl1 you learn?	11
1Process Flow	113
Practice	1
1Monitor real-time systeme1sources.	114
SOLI1ON:	114
Checm1emory usage details.	114
SOLUTION:	114
a1lyze disk I/Ot1atistics.	114
SOLUTION:	114
Mono1r virtual memy1 statistics.	114
SOLUTION:	114
Cc1k network intf1ace statistics.	114
SOLUTION:	114
Listr1ocesses by CPu1sage.	114
SOLUTION:	114
List processes  1memory usage.114
SOLUTION:	114
Check file descrt1or usage.	114O1LUTION:	114
Monitor system calls foa1 process.	114O1LUTION:	115
Check current I/O scd1uler.	115
SOLI1ON:	115
Tune kernel parameters for perfm1ance.	115
SOLI1ON:	115
Apply performance kernele1ttings.	115
SU1TION:	115
Check current swappiness setting.115
SOLUTION:	1
1Create a CPU stress test.	115
SOLUTION151
Monitor CPU a1ge during stress test.	115
SOLUTION:	116
Check procs1 nice values and priorities.	116
SOLUTION:	61
Change process priority using nice.	1OLUTION:	116
n1itor disk usage and find large files.	1TION:	116
Che 1filesystem inode usage.	116
SOLUTION:	16
Create perfm1ance monitoring script.	116
SOLUTION:	1 the performae1 monitoring script.	117
SOLUTION:117
Set up syst 1resource limits.	117
SOLUTION:	117
Check t1work buffer se1s.	117
SOLUTION:	117
Profile system perforn1ce with perf.117
SOLUTION:	117
Check interrupt dir1ibution acrosC1PUs.	117
SOLUTION:	117
Monitor n1text switches1117
SOLUTION:	117
Create system performancb1aseline.	117
L1UTION:	117
Test Your Knowledge	1e main systeme1sources you monitor for perfoa1nce issues?	1
1How do you identify if a system is CPU-u1nd, I/O-boundo1r memory-bound?	118
Whai1s the difference between load average and CPU utilization?	1ptimize disk I/O performance in Linux?	118
What kernel parameters commonly ne 1tuning for performance?	118
How do you monitor performance continuouy1 in production?	118








Lab 0: Introduction to Lu1x
Get familiar with Linux, its history, distributions, and why is1 essential for modern computing.
What is Linux?
Linux is a frea1nd open-source operating system kernel created by Linus Torvalds in 1991. It serves as the foundation for many operating systems called Linux distributions (distros). Linux powers everything from smartphones and embedded devices to servers and supercomputers, making it one of the most important technologies in modern computing.
Why Learn Linux?
- Server dominance in web infrastructure
- Essential for software development and DevOps
- High demand for Linux skills in tech industry
- Cost effective with no licensing fees
- Enhanced security compared to other systems
- Complete system customization control
Linux Distributions Overview
- Ubuntu: User-friendly, great for beginners
- CentOS/RHEL: Enterprise-focused, corporate standard
- Debian: Stable foundation for many distributions
- Fedora: Cutting-edge features from Red Hat
- Arch Linux: Minimalist, highly customizable
- SUSE: Enterprise-grade with European focus
Linux Architecture
- Kernel: Manages hardware and system resources
- Shell: Command-line interface for system interaction
- File System: Hierarchical structure from root (/)
- Processes: Running programs managed by kernel
- Users and Groups: Security and access control model
- Package Manager: Software installation and management
Essential Linux Concepts
- Everything is a file (devices, processes, system info)
- Case sensitive commands, filenames, and paths
- Multi-user system supporting simultaneous users
- Command line power for most system tasks
- Package-based software distribution model
- Open source philosophy with available source code
About These Linux Lab Guides
This curriculum progresses from basic concepts to advanced administration:
- Beginner Labs (0-8): Commands, file system, permissions
- Intermediate Labs (9-16): Scripting, monitoring, networking
- Advanced Labs (17-24): Services, security, performance tuning
Next Step
Learn how to install Linux (Ubuntu) and configure your first Linux environment for optimal learning and development.



Lab 1: Linux Installation & Setup

Lab Theory>

Important Note
The lab environment already has Ubuntu Linux pre-installed and configured. The "Start Lab" button is disabled for this installation lab. You can use this lab to learn about the installation process and practice post-installation configuration tasks on the existing environment, or follow along on your local machine using VirtualBox or VMware.
What is this lab about?
This lab guides you through installing Ubuntu Linux and setting up a complete development environment. You'll learn different installation methods, post-installation configuration, and essential software setup that forms the foundation for all subsequent Linux labs.
What will you learn?
- How to create a bootable Ubuntu USB drive or set up a virtual machine
- The Ubuntu installation process step-by-step
- Post-installation system updates and essential package installation
- How to configure user accounts and sudo privileges
- Essential development tools setup (git, curl, wget, vim)
- How to customize your Linux desktop environment for productivity
Installation Methods
- Virtual Machine: Safe learning environment without affecting main OS
- Dual Boot: Full hardware performance alongside existing OS
- Live USB: Try Linux without installing
- WSL: Run Linux inside Windows
- Cloud Instance: Remote Ubuntu server
Post-Installation Steps
- Update system packages to latest versions
- Install essential development tools (git, curl, vim)
- Configure firewall and basic security
- Set up user accounts and sudo privileges
- Install restricted multimedia codecs
How to test your knowledge
Complete the installation tasks below, then validate your setup by running system verification commands. The validation will check that Ubuntu is properly installed, updated, and configured with essential tools.


Update the package list and upgrade all packages.
SOLUTION:
sudo apt update && sudo apt upgrade -y


Install essential development tools.
SOLUTION:
sudo apt install -y curl wget git vim build-essential software-properties-common
Check your Ubuntu version and system information.
SOLUTION:
lsb_release -a
Display current user and verify sudo access.
SOLUTION:
whoami && sudo whoami
Check available disk space and memory.
SOLUTION:
df -h && free -h
View system uptime and load averages.
SOLUTION:
uptime
Display CPU information.
SOLUTION:
lscpu
Check network interface configuration.
SOLUTION:
ip addr show
Install snap package manager and verify.
SOLUTION:
sudo apt install snapd -y && snap version
Enable and start the firewall.
SOLUTION:
sudo ufw enable


Check running services status.
SOLUTION:
systemctl list-units --type=service --state=running
Create a test directory in your home folder.
SOLUTION:
mkdir ~/linux-lab-test

Lab 2: Basic Commands & Navigation
What is the Linux Command Line?
The Linux command line, accessed through a terminal or shell, is a text-based interface for interacting with the operating system. It provides direct access to system functions and is often more powerful and efficient than graphical interfaces.
Why Master Command Line Basics?
- Many tasks are faster via command line than GUI
- Commands can be scripted and automated
- Essential for managing remote servers via SSH
- Access to advanced system functions not available in GUI
- Same commands work across different Linux distributions
- Command line often works when GUI fails
Linux File System Hierarchy

- / (root): Top-level directory containing all others
- /home: User home directories
- /etc: System configuration files
- /var: Variable data like logs and databases
- /usr: User programs and applications
- /tmp: Temporary files cleared on reboot
- /bin: Essential system binaries
- /opt: Optional/third-party software
Basic Command Structure
Commands follow this pattern: command [options] [arguments]
- ls -l /home (command, option, argument)
- mkdir -p test/nested (nested directory creation)
- cp file1.txt backup/ (copy source to destination)
Essential Navigation Commands
- pwd: Print current working directory
- ls: List directory contents (ls -la for detailed view)
- cd: Change directory (cd .. for parent, cd ~ for home)
- find: Search for files and directories
- locate: Fast file search using database
- which: Find location of commands
File Operations
- touch: Create empty files or update timestamps
- cp: Copy files and directories (cp -r for recursive)
- mv: Move/rename files and directories
- rm: Remove files (rm -r for directories)
- mkdir: Create directories (mkdir -p for nested)
- rmdir: Remove empty directories
Text Viewing Commands
- cat: Display entire file content
- less/more: View file content page by page
- head: Show first lines of file
- tail: Show last lines of file (tail -f for real-time)
- grep: Search text patterns in files
Getting Help
- man: Manual pages for detailed command help
- --help: Quick command help option
- info: Detailed information pages
- apropos: Search manual pages by keyword
Command Line Tips
- Tab completion for commands and paths
- Up/down arrows to navigate command history
- Wildcards: * for multiple, ? for single character
- Pipes: | to chain commands together
- Background: & to run commands in background
Practice

Display your current working directory.
SOLUTION:
pwd

List all files in the current directory, including hidden files.
SOLUTION:
ls -la

Navigate to your home directory.
SOLUTION:
cd ~
Create a directory named "lab-practice".
SOLUTION:
mkdir lab-practice
Navigate into the lab-practice directory.
SOLUTION:
cd lab-practice
Create nested directories "docs/projects/web" in one command.
SOLUTION:
mkdir -p docs/projects/web


Create three empty files: file1.txt, file2.txt, file3.txt.
SOLUTION:
touch file1.txt file2.txt file3.txt
Copy file1.txt to the docs directory.
SOLUTION:
cp file1.txt docs/


Move file2.txt to the docs directory and rename it to backup.txt.
SOLUTION:
mv file2.txt docs/backup.txt
Copy the entire docs directory to create a backup called docs-backup.
SOLUTION:
cp -r docs docs-backup


Find all .txt files in the current directory and subdirectories.
SOLUTION:
find . -name "*.txt"


Display the contents of file1.txt (it should be empty).
SOLUTION:
cat file1.txt


Get help information for the ls command.
SOLUTION:
man ls
Go back to the parent directory.
SOLUTION:
cd ..
Remove the file3.txt file.
SOLUTION:
rm lab-practice/file3.txt
Test Your Knowledge
What is the difference between absolute and relative paths?
Absolute paths start from root (/) like /home/user/documents. Relative paths are from current directory like documents/file.txt or ../parent-directory.
How do you list all files including hidden ones?
Use ls -a or ls -la. Hidden files in Linux start with a dot (.) and are not displayed by default with a plain ls command.
What does the rm -rf command do and why is it dangerous?
rm -rf removes files and directories recursively (-r) and forcefully (-f) without confirmation. It is dangerous because it can delete entire directory trees permanently without asking for confirmation.
How do you create nested directories in one command?
Use mkdir -p path/to/nested/directory. The -p flag creates parent directories as needed and does not error if directories already exist.
What is the purpose of the man command?
The man command displays manual pages for commands, providing detailed documentation including syntax, options, examples, and related commands. Use q to quit the manual page.
How do you copy a directory and all its contents?
Use cp -r source_directory destination_directory. The -r (recursive) flag is required to copy directories and their contents.

Lab 3: File System & Permissions
Lab Theory
What is the Linux File System?
The Linux file system is a hierarchical structure organizing all files and directories. Unlike Windows with drive letters, Linux uses a single tree structure starting from root (/). Everything in Linux is treated as a file, including directories, devices, and processes.
Linux File System Hierarchy Standard (FHS)
- /bin: Essential system binaries (ls, cp, mv)
- /sbin: System administration binaries
- /etc: System configuration files
- /home: User home directories
- /var: Variable data (logs, databases, mail)
- /usr: User programs and data
- /tmp: Temporary files
- /proc: Virtual file system with process information
- /dev: Device files
- /mnt: Mount points for temporary file systems
Understanding File Permissions
Linux permission system based on three user types:
- Owner (u): The user who owns the file
- Group (g): Users in the file's group
- Others (o): All other users
Three permission types:
- Read (r): View file contents or list directory
- Write (w): Modify file contents or create/delete in directory
- Execute (x): Run file as program or enter directory
Permission Representation
Two formats for showing permissions:
- Symbolic: rwxrwxrwx (owner, group, others)
- Numeric: 755 (4=read, 2=write, 1=execute)
Common examples:
- rwxr-xr-x (755): Owner full, others read/execute
- rw-r--r-- (644): Owner read/write, others read only
- rwx
(700): Owner full access, no others access
File Ownership
Every file has owner and group:
- Owner: Individual user who owns the file
- Group: Group of users sharing access
- chown: Change ownership
- chgrp: Change group ownership
- chmod: Change permissions
Special Permissions
- Sticky Bit: Prevents deletion by non-owners
- SUID: Execute with owner's permissions
- SGID: Execute with group's permissions
- umask: Default permissions for new files
File Types in Linux
- Regular files (-): Standard files containing data
- Directories (d): Containers for other files
- Symbolic links (l): Pointers to other files
- Device files (b/c): Hardware device interfaces
- Named pipes (p): Inter-process communication
- Sockets (s): Network communication endpoints



Practice
Create a directory called "permissions-lab" and navigate to it.
SOLUTION:
mkdir permissions-lab && cd permissions-lab
Create a file called "test.txt" with some content.
SOLUTION:
echo "Hello Linux!" > test.txt
Check the current permissions of test.txt.
SOLUTION:
ls -l test.txt
Change permissions of test.txt to read-only for all users.
SOLUTION:
chmod 444 test.txt
Try to write to the read-only file (this should fail).
SOLUTION:
echo "This should fail" >> test.txt
Restore write permission for the owner.
SOLUTION:
chmod u+w test.txt


Create a script file called "hello.sh" with a simple command.
SOLUTION:
echo "#!/bin/bash
echo "Hello from script!"" > hello.sh
Make the script executable and run it.
SOLUTION:
chmod +x hello.sh && ./hello.sh
Check the owner and group of your files.
SOLUTION:
ls -l


Create a symbolic link to test.txt called "link-to-test".
SOLUTION:
ln -s test.txt link-to-test
Display the file type information for all files.
SOLUTION:
file *
Show disk usage of the current directory.
SOLUTION:
du -sh .
Find all executable files in the current directory.
SOLUTION:
find . -type f -executable
Display the inode number of test.txt.
SOLUTION:
ls -i test.txt
Test Your Knowledge
What does the permission 755 mean in numeric notation?
755 means owner has read/write/execute (7), group has read/execute (5), others have read/execute (5).
What is the difference between chown and chmod?
chown changes file ownership (user and group), while chmod changes file permissions (read, write, execute). Example: chown user:group file vs chmod 644 file.
What does the sticky bit do and where is it commonly used?
The sticky bit prevents users from deleting files they don't own in a directory. It's commonly used on /tmp directory, shown as t in permissions like drwxrwxrwt.
How do you make a file executable for everyone?
Use chmod +x filename or chmod a+x filename. This adds execute permission for all users (owner, group, others).
What is the purpose of the /proc directory?
/proc is a virtual file system that provides information about running processes and system status. Files like /proc/cpuinfo and /proc/meminfo contain hardware and memory information.
How do symbolic links differ from hard links?
Symbolic links are shortcuts that point to another file's path and can cross file systems. Hard links share the same inode and cannot cross file systems or link to directories.



Lab 4: Text Processing & Editors
Lab Theory
Why Text Processing Matters in Linux?
Linux systems generate massive amounts of text data - log files, configuration files, command output, and data files. Text processing is essential for system administration, data analysis, automation, and troubleshooting.
Essential Text Processing Tools
- grep: Search and filter text patterns
- sed: Stream editor for filtering and transforming text
- awk: Pattern scanning and processing language
- cut: Extract columns from text
- sort: Sort lines of text
- uniq: Remove duplicate lines
- wc: Count lines, words, and characters
- tr: Translate or delete characters
The Grep Command Family
grep searches text using patterns:
- grep pattern file: Basic pattern search
- grep -i pattern file: Case-insensitive search
- grep -r pattern directory: Recursive search
- grep -v pattern file: Invert match (non-matching)
- grep -n pattern file: Show line numbers
- egrep/grep -E: Extended regular expressions
- fgrep/grep -F: Fixed strings (no regex)
Stream Editor (sed)
sed performs text transformations:
- sed 's/old/new/g' file: Replace all occurrences
- sed '/pattern/d' file: Delete lines matching pattern
- sed -n '5,10p' file: Print lines 5-10
- sed -i 's/old/new/g' file: In-place editing
- sed '/pattern/a\text' file: Add text after matches
AWK Programming Language
awk for field-based processing:
- awk '{print $1}' file: Print first field
- awk -F: '{print $1}' file: Use colon separator
- awk 'NR > 1' file: Skip first line
- awk '{sum += $1} END {print sum}' file: Sum column
- awk '/pattern/ {print $0}' file: Print matches
Text Editors Overview
vim (Vi Improved):
- Modal editor with Normal, Insert, Visual, Command modes
- Powerful for large files and remote editing
- Steep learning curve but extremely efficient
- Available on virtually every Linux system
nano:
- Simple, intuitive editor good for beginners
- Shows keyboard shortcuts at bottom
- Similar to GUI text editors
Vim Basics
- Mode switching: i (insert), Esc (normal), : (command)
- Navigation: h,j,k,l or arrow keys
- Save/quit: :w (save), :q (quit), :wq (save and quit)
- Search: /pattern (forward), ?pattern (backward)
- Copy/paste: yy (copy line), p (paste), dd (delete)
Regular Expressions Basics
- . : Any single character
- * : Zero or more of previous character
- ^ : Start of line
- $ : End of line
- [abc] : Any character in brackets
- [0-9] : Any digit
- \+ : One or more (extended regex)
- \? : Zero or one (extended regex)


Practice


Create a sample data file with some log entries.
SOLUTION:
echo -e "2024-01-15 ERROR Database connection failed
2024-01-15 INFO User login successful
2024-01-15 WARNING Low disk space
2024-01-16 ERROR Authentication failed
2024-01-16 INFO System startup complete" > sample.log

Search for all ERROR entries in the log file.
SOLUTION:
grep ERROR sample.log
Search for ERROR entries and show line numbers.
SOLUTION:
grep -n ERROR sample.log
Find all lines that do NOT contain ERROR.
SOLUTION:
grep -v ERROR sample.log


Count how many lines contain the word "INFO".
SOLUTION:
grep -c INFO sample.log
Extract only the date (first field) from each line using awk.
SOLUTION:
awk '{print $1}' sample.log


Extract the date and log level (first two fields) using awk.
SOLUTION:
awk '{print $1, $2}' sample.log
Replace all occurrences of "ERROR" with "CRITICAL" using sed.
SOLUTION:
sed 's/ERROR/CRITICAL/g' sample.log
Sort the log file by date and save to sorted.log.
SOLUTION:
sort sample.log > sorted.log
Count the total number of lines, words, and characters in sample.log.
SOLUTION:
wc sample.log
Create a file called "practice.txt" using nano editor with some content.
SOLUTION:
echo "This is practice content for vim/nano lab" > practice.txt
Use sed to delete all lines containing "INFO" from the log.
SOLUTION:
sed '/INFO/d' sample.log
Extract unique log levels from the second column.
SOLUTION:
awk '{print $2}' sample.log | sort | uniq
Find lines that start with "2024-01-16" using grep.
SOLUTION:
grep "^2024-01-16" sample.log
Count how many different dates appear in the log.
SOLUTION:
awk '{print $1}' sample.log | sort | uniq | wc -l
Test Your Knowledge
What is the difference between grep, egrep, and fgrep?
grep uses basic regex, egrep (grep -E) uses extended regex with +, ?, |, (), fgrep (grep -F) treats patterns as fixed strings.
How do you search for a pattern recursively in all files under a directory?
Use grep -r "pattern" directory/ or grep -R "pattern" directory/. The -r option searches recursively through subdirectories.
What does the sed command "sed -i 's/old/new/g' file" do?
It replaces all occurrences (g flag) of "old" with "new" in the file and modifies the file in-place (-i flag) instead of printing to stdout.
How do you print only the 3rd column of a CSV file using awk?
Use awk -F, '{print $3}' file.csv. The -F, sets comma as field separator, and $3 refers to the third field.
What are the main modes in vim and how do you switch between them?
Normal mode (default), Insert mode (press i), Visual mode (press v), Command mode (press :). Press Esc to return to Normal mode from any other mode.
How do you count the number of lines, words, and characters in a file?
Use wc filename. wc -l counts lines only, wc -w counts words only, and wc -c counts characters only.

Lab 5: Users & Groups Management
Lab Theory
What is Linux Multi-User System?
Linux is designed as a multi-user operating system where multiple users can work simultaneously. Each user has their own account, home directory, and permissions. The system uses users and groups to control access to resources.
Why User Management Matters?
- Security: Control who can access what resources
- Organization: Separate different users' data and configs
- Resource Control: Limit what users can do on system
- Auditing: Track who performed what actions
- Collaboration: Enable multiple users to work securely
- Service Accounts: Run services under dedicated accounts
User Account Types
- Root User: System administrator with unlimited privileges (UID 0)
- System Users: Service accounts for daemons (UID 1-999)
- Regular Users: Normal user accounts for people (UID 1000+)
- Service Users: Accounts for specific applications
User Account Information
User data stored in several files:
- /etc/passwd: User account information
- /etc/shadow: Encrypted passwords and policies
- /etc/group: Group definitions and memberships
- /etc/gshadow: Group passwords and administrators
- /home/username: User's home directory
Essential User Commands
- useradd: Create new user accounts
- userdel: Delete user accounts
- usermod: Modify existing user accounts
- passwd: Change user passwords
- su: Switch user identity
- sudo: Execute commands as another user
- whoami: Display current username
- id: Show user and group IDs
Group Management
Groups are collections of users sharing permissions:
- Primary Group: User's main group (set at creation)
- Secondary Groups: Additional groups user belongs to
- Group permissions apply to all group members
- Files created inherit the user's primary group
Group Commands
- groupadd: Create new groups
- groupdel: Delete groups
- groupmod: Modify group settings
- gpasswd: Manage group memberships
- newgrp: Switch to different primary group temporarily
- groups: Show which groups a user belongs to
sudo Configuration
sudo allows users to run commands with elevated privileges:
- Configured in /etc/sudoers file
- Use visudo to edit safely
- Can grant specific commands or full access
- Logs all sudo usage for security auditing
- Timeout settings control privilege duration
Password Policies
Linux supports various password policies:
- Password aging: Force regular password changes
- Complexity requirements: Minimum length, character types
- Account locking: Lock accounts after failed attempts
- Password history: Prevent reusing recent passwords
- Expiration warnings: Notify before password expires
Best Practices
- Use sudo instead of logging in as root
- Create service accounts for applications
- Use strong passwords and enable policies
- Regularly audit and remove unused accounts
- Use groups to manage permissions efficiently
- Monitor user activity through logs
- Implement proper password aging policies


Practice


Display information about the current user.
SOLUTION:
id

Show which groups the current user belongs to.
SOLUTION:
groups
Display the contents of /etc/passwd for your user.
SOLUTION:
grep $USER /etc/passwd
Create a new group called "developers".
SOLUTION:
sudo groupadd developers
Create a new user called "testuser" with bash shell.
SOLUTION:
sudo useradd -m -s /bin/bash testuser
Set a password for the testuser account.
SOLUTION:
sudo passwd testuser
Add testuser to the developers group.
SOLUTION:
sudo usermod -aG developers testuser
Verify testuser is in the developers group.
SOLUTION:
groups testuser


Create a directory owned by the developers group.
SOLUTION:
sudo mkdir /tmp/dev-project && sudo chgrp developers /tmp/dev-project
Set group write permissions on the dev-project directory.
SOLUTION:
sudo chmod g+w /tmp/dev-project
Switch to the testuser account and test access.
SOLUTION:
sudo su - testuser
List all users on the system (extract from /etc/passwd).
SOLUTION:
cut -d: -f1 /etc/passwd
Find all files owned by testuser.
SOLUTION:
sudo find /home -user testuser -type f 2>/dev/null
Lock the testuser account.
SOLUTION:
sudo usermod -L testuser
Delete the testuser account and home directory.
SOLUTION:
sudo userdel -r testuser


Test Your Knowledge
What is the difference between su and sudo?
su requires target user's password and switches completely. sudo runs commands as another user using your password, with granular control.
Where are user passwords stored and why?
User passwords are stored in /etc/shadow (not /etc/passwd) for security. The shadow file is readable only by root and contains encrypted passwords, while passwd is world-readable but contains no password information.
What is the significance of UID 0?
UID 0 belongs to the root user, who has unlimited privileges on the system. Any user with UID 0 is treated as root, regardless of username.


How do you add a user to multiple groups during account creation?
Use useradd -G group1,group2,group3 username to add the user to multiple secondary groups, or use usermod -aG groups username for existing users.
What happens to a user's files when you delete their account?
By default, userdel only removes the account but leaves files. Use userdel -r to remove the home directory and mail spool, or manually clean up files owned by the user.
How do you temporarily switch to a different primary group?
Use the newgrp command followed by the group name. This creates a new shell session with the specified group as the primary group for file creation.


Lab 6: Process Management
Lab Theory
What are Linux Processes?
A process is a running instance of a program in Linux. Every command you execute, every application you run, and every system service creates one or more processes. Understanding process management is crucial for system administration and troubleshooting.
Why Process Management Matters?
- System monitoring: Track resource usage and system health
- Troubleshooting: Identify and resolve performance issues
- Security: Monitor for suspicious processes and activities
- Resource control: Manage CPU and memory usage
- Service management: Start, stop, and restart system services
- Automation: Create scripts that manage long-running processes
Process States
- Running: Currently executing on CPU
- Sleeping: Waiting for event or resource
- Stopped: Suspended by signal
- Zombie: Finished but parent hasn't collected exit status
- Daemon: Background system processes
Essential Process Commands
- ps: Display running processes
- top: Real-time process monitor
- htop: Enhanced interactive process viewer
- kill: Terminate processes by PID
- killall: Terminate processes by name
- jobs: Show background jobs
- nohup: Run commands immune to hangups
Process Control
- Ctrl+C: Interrupt (SIGINT) running process
- Ctrl+Z: Suspend (SIGTSTP) process to background
- & : Run command in background
- fg: Bring background job to foreground
- bg: Resume suspended job in background
System Monitoring
- uptime: System load averages
- free: Memory usage statistics
- iostat: I/O statistics
- vmstat: Virtual memory statistics
- lsof: List open files and processes
- netstat: Network connections and processes

Practice


Display all running processes in detailed format.
SOLUTION:
ps aux


Show processes in a tree format to see parent-child relationships.
SOLUTION:
ps auxf
Start the top command to monitor processes in real-time.
SOLUTION:
top
Find the process ID of the bash shell.
SOLUTION:
ps aux | grep bash
Display current system uptime and load averages.
SOLUTION:
uptime
Show memory usage information.
SOLUTION:
free -h
Start a long-running sleep command in the background.
SOLUTION:
sleep 300 &
List current background jobs.
SOLUTION:
jobs
Find the PID of the sleep process.
SOLUTION:
ps aux | grep sleep
Kill the sleep process using its PID.
SOLUTION:
kill $(pgrep sleep)
Start another sleep process and suspend it with Ctrl+Z.
SOLUTION:
sleep 100
Resume the suspended job in the background.
SOLUTION:
bg
Display processes owned by the current user.
SOLUTION:
ps u
Kill all sleep processes at once.
SOLUTION:
killall sleep


Show the most CPU-intensive processes.
SOLUTION:
ps aux --sort=-%cpu | head
Test Your Knowledge
What is the difference between kill and killall commands?
kill terminates processes by PID (process ID), while killall terminates processes by name. kill requires specific PID numbers, killall can terminate multiple processes with the same name.
How do you run a command in the background?
Add & at the end of the command (e.g., command &) or use Ctrl+Z to suspend a running process, then use bg command to resume it in background.
What does the load average represent in the uptime command?
Load average shows the average system load over 1, 5, and 15 minutes. Values represent the number of processes waiting for CPU time. Values equal to CPU cores indicate full utilization.
How do you find processes consuming the most CPU?
Use top command and press P to sort by CPU usage, or use ps aux --sort=-%cpu | head to show top CPU consumers.
What is a zombie process and how do you handle it?
A zombie process has finished execution but its parent hasn't collected its exit status. Kill the parent process to clean up zombies, or restart the system if necessary.

Lab 7: Package Management
Lab Theory
What is Package Management?
Package management is the method of installing, updating, configuring, and removing software packages on Linux systems. Ubuntu uses the Advanced Package Tool (apt) which handles dependencies, security updates, and software repositories automatically.
Why Package Management Matters?
- Security: Automated security updates and vulnerability patches
- Dependency handling: Automatically resolves software dependencies
- System integrity: Prevents conflicts between software packages
- Efficiency: Centralized software installation and removal
- Updates: Easy system-wide software updates
- Repositories: Access to thousands of tested software packages
APT Package Manager
- apt: Modern, user-friendly interface
- apt-get: Traditional interface with more options
- apt-cache: Search and query package information
- dpkg: Low-level package management tool
- aptitude: Advanced package management with dependency resolution
Essential APT Commands
- apt update: Refresh package lists from repositories
- apt upgrade: Upgrade installed packages
- apt install: Install new packages
- apt remove: Remove packages (keep configuration)
- apt purge: Remove packages and configuration files
- apt search: Search for packages
- apt show: Display package information
Package Repositories
- Main: Canonical-supported open source software
- Universe: Community-maintained open source software
- Restricted: Proprietary drivers and codecs
- Multiverse: Software with copyright restrictions
- PPA: Personal Package Archives for additional software
Package States
- Installed: Package is installed and configured
- Not installed: Package is available but not installed
- Upgradeable: Newer version available
- Held: Package version is locked
- Broken: Package has unmet dependencies


Practice
Update the package database.
SOLUTION:
sudo apt update
Show upgradeable packages.
SOLUTION:
apt list --upgradable
Search for packages related to "network".
SOLUTION:
apt search network
Install the tree command utility.
SOLUTION:
sudo apt install tree -y
Show detailed information about the tree package.
SOLUTION:
apt show tree
List all installed packages.
SOLUTION:
apt list --installed


Install multiple packages: htop, ncdu, and tmux.
SOLUTION:
sudo apt install htop ncdu tmux -y
Check which files are installed by the tree package.
SOLUTION:
dpkg -L tree
Find which package provides the /bin/ls command.
SOLUTION:
dpkg -S /bin/ls
Remove the ncdu package but keep its configuration.
SOLUTION:
sudo apt remove ncdu
Show packages that can be automatically removed.
SOLUTION:
apt autoremove --dry-run
Clean the package cache.
SOLUTION:
sudo apt clean


Check for broken packages.
SOLUTION:
sudo apt check
Hold the tmux package to prevent updates.
SOLUTION:
sudo apt-mark hold tmux
Show held packages.
SOLUTION:
apt-mark showhold
Test Your Knowledge
What is the difference between apt remove and apt purge?
apt remove uninstalls the package but keeps configuration files, while apt purge removes both the package and all its configuration files completely.
Why should you run apt update before apt upgrade?
apt update refreshes the local package database with latest package information from repositories. Without this, apt upgrade might miss newer package versions.
What is a PPA and when would you use it?
PPA (Personal Package Archive) provides software not in official repositories. Use for newer software versions, beta software, or applications not in Ubuntu repositories.
How do you fix broken package dependencies?
Use apt --fix-broken install or apt -f install to automatically fix dependency issues, or dpkg --configure -a to configure unconfigured packages.
What does apt autoremove do?
apt autoremove removes packages that were automatically installed as dependencies but are no longer needed by any installed packages.



Lab 8: Basic Network Commands
Lab Theory
What is this lab about?
This lab introduces you to fundamental network commands that every Linux administrator needs to know. You'll learn how to test connectivity, download files, check network status, and perform basic firewall operations.
What will you learn?
- How to test network connectivity using ping and different protocols
- How to download files from the internet using wget and curl
- How to check active network connections and listening ports
- How to view and manipulate basic iptables firewall rules
- How to troubleshoot common network issues on Linux systems
Process Flow
- Connectivity Testing: Use ping to test network reachability
- File Downloads: Download files using wget and curl with various options
- Network Status: Check active connections with netstat and ss
- Firewall Basics: View and add simple iptables rules for network security

Practice
Test connectivity to Google DNS server.
SOLUTION:
ping -c 4 8.8.8.8
Download a test file using wget.
SOLUTION:
wget https://httpbin.org/json
Use curl to fetch and display webpage content.
SOLUTION:
curl https://httpbin.org/ip
Download a file with curl and save with a specific name.
SOLUTION:
curl -o myip.json https://httpbin.org/ip
Check all listening TCP ports.
SOLUTION:
netstat -tlnp


Use ss to show listening sockets.
SOLUTION:
ss -tlnp
Show all active network connections.
SOLUTION:
netstat -tuln
Check if a specific port is listening.
SOLUTION:
ss -tlnp | grep :22
View current iptables rules.
SOLUTION:
sudo iptables -L
Add a rule to allow HTTP traffic.
SOLUTION:
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
Test connectivity to a specific port using telnet.
SOLUTION:
telnet google.com 80
Download a file quietly with wget.
SOLUTION:
wget -q https://httpbin.org/json
Check network interface configuration.
SOLUTION:
ip addr show
Test DNS resolution for a domain.
SOLUTION:
nslookup google.com
Show routing table.
SOLUTION:
ip route show


Test Your Knowledge
What is the difference between ping and wget commands?
Ping tests network connectivity using ICMP packets, while wget downloads files from web servers using HTTP/HTTPS protocols.
When would you use ss instead of netstat?
ss is the modern replacement for netstat, providing faster performance and more detailed socket information. It's recommended for current Linux systems.
What does the -c option do in the ping command?
The -c option specifies the count of ping packets to send before stopping, instead of pinging continuously.
How do iptables rules work in terms of order?
Iptables processes rules in order from top to bottom, and stops at the first matching rule. The order of rules is crucial for proper firewall behavior.
What is the purpose of the curl -o option?
The -o option specifies the output filename when downloading content with curl, instead of displaying it on the terminal.



Lab 9: Shell Scripting Basics
Lab Theory
What is this lab about?
This lab introduces the fundamentals of shell scripting in Linux, a critical skill for any DevOps professional. You will learn how to write, execute, and debug simple scripts, handle variables, and use basic control structures to automate tasks.
What will you learn?
- How to create and execute a shell script.
- Understanding the shebang (#! /bin/bash).
- Working with variables and user input.
- Using command-line arguments.
- Basic conditional logic with if statements.
- Looping with for loops.
Process Flow
- Script Creation: Write your first script and make it executable.
- Variables & Input: Learn to store and use data within your script.
- Conditionals & Loops: Add logic to your scripts to make decisions and repeat tasks.
- Practical Application: Build a simple script to automate a common task.

Practice


Create and execute a simple "Hello, World!" shell script.
SOLUTION:
echo "#!/bin/bash\necho \"Hello, DevOps World!\"" > hello.sh && chmod +x hello.sh && ./hello.sh
Create a script that uses a variable to store a name and print a greeting.
SOLUTION:

echo "#!/bin/bash\nNAME=\"Alice\"\necho \"Hello, $NAME!\"" > greeting.sh && chmod +x greeting.sh && ./greeting.sh
Create a script that accepts a command-line argument and prints it.
SOLUTION:
echo "#!/bin/bash\necho \"The first argument is: $1\"" > args.sh && chmod +x args.sh && ./args.sh "FirstArg"


Create a script that uses an `if` statement to check if a file exists.
SOLUTION:
echo "#!/bin/bash\nif [ -f /etc/hosts ]; then\n  echo \"/etc/hosts exists.\"\nelse\n  echo \"/etc/hosts does not exist.\"\nfi" > check_file.sh && chmod +x check_file.sh && ./check_file.sh
Create a script that uses a `for` loop to print numbers from 1 to 5.
SOLUTION:
echo "#!/bin/bash\nfor i in {1..5}; do\n  echo \"Number: $i\"\ndone" > loop.sh && chmod +x loop.sh && ./loop.sh
Create a script that reads input from the user.
SOLUTION:
echo "#!/bin/bash\necho \"What is your name?\"\nread USER_NAME\necho \"Nice to meet you, $USER_NAME!\"" > read_input.sh && chmod +x read_input.sh && echo "Bob" | ./read_input.sh
What is the purpose of the `#!/bin/bash` line at the beginning of a script?
This is called a "shebang". It tells the operating system which interpreter to use to execute the script. In this case, it specifies the bash shell.
What is the difference between `$*` and `$@` in a shell script?
Both represent all command-line arguments. However, `$*` treats all arguments as a single string, while `$@` treats each argument as a separate, quoted string. `$@` is generally safer to use.
How do you check the exit status of the last command that was run?
You check the special variable `$?`. An exit status of 0 means the command was successful, while any non-zero value indicates an error.
What is the difference between single quotes (`'`) and double quotes (`"`) in shell scripting?
Double quotes allow for variable expansion and command substitution (e.g., `echo "User: $USER"`). Single quotes treat every character literally (e.g., `echo 'User: $USER'` will print the literal string "$USER").



Lab 10: Advanced File Operations
Lab Theory
What is this lab about?
This lab covers advanced file operations that are essential for system administration and automation. You'll learn powerful commands for finding files, synchronizing directories, creating archives, and managing compressed files efficiently.
What will you learn?
- How to use find command with various criteria and actions
- How to locate files quickly using the locate database
- How to synchronize files and directories with rsync
- How to create, extract, and manage tar archives
- How to work with different compression formats (gzip, bzip2, xz)


Process Flow
- File Search: Use find with complex criteria and locate for fast searches
- Synchronization: Copy and sync files efficiently with rsync options
- Archiving: Create tar archives with different compression methods
- Extraction: Extract archives and manage compressed files



Practice


Create a test directory structure with files.
SOLUTION:
mkdir -p testdir/{subdir1,subdir2,subdir3} && touch testdir/file1.txt testdir/subdir1/file2.log testdir/subdir2/file3.txt testdir/subdir3/file4.log

Find all .txt files in testdir.
SOLUTION:
find testdir -name "*.txt"
Find all files modified in the last 5 minutes.
SOLUTION:
find testdir -mtime -5
Find files and execute ls -l on them.
SOLUTION:
find testdir -name "*.log" -exec ls -l {} \;
Update the locate database.
SOLUTION:
sudo updatedb
Use locate to find bash executable.
SOLUTION:
locate bash | head -5
Create a backup directory and sync with rsync.
SOLUTION:
mkdir backup && rsync -av testdir/ backup/
Create a tar archive of testdir.
SOLUTION:
tar -cvf testdir.tar testdir


Create a gzipped tar archive.
SOLUTION:
tar -czvf testdir.tar.gz testdir
List contents of the tar archive.
SOLUTION:
tar -tvf testdir.tar.gz
Extract the archive to a new location.
SOLUTION:
mkdir extracted && tar -xzf testdir.tar.gz -C extracted
Find and delete empty directories.
SOLUTION:
find testdir -type d -empty -delete
Create a bzip2 compressed archive.
SOLUTION:
tar -cjvf testdir.tar.bz2 testdir
Sync directories with delete option.
SOLUTION:
rsync -av --delete testdir/ backup/
Find files larger than 1KB.
SOLUTION:
find testdir -size +1k

Test Your Knowledge
What is the difference between find and locate commands?
Find searches the filesystem in real-time but is slower. Locate uses a pre-built database (updated by updatedb) and is much faster but may not show recent changes.
What does the rsync -av option combination do?
-a enables archive mode (preserves permissions, timestamps, links) and -v enables verbose output to show what files are being transferred.
What is the difference between tar.gz and tar.bz2 files?
tar.gz uses gzip compression (faster, larger files), while tar.bz2 uses bzip2 compression (slower, smaller files). Both are tar archives with different compression algorithms.
How does the find command's -exec option work?
-exec allows you to run a command on each file found. The {} placeholder represents the found file, and \; terminates the command.
What is the purpose of rsync's --delete option?
--delete removes files from the destination that don't exist in the source, making the destination an exact mirror of the source.

Lab 11: System Monitoring
Lab Theory
What is this lab about?
This lab introduces you to essential system monitoring tools that every Linux administrator needs to know. You'll learn how to monitor CPU, memory, disk I/O, and network activity to identify performance bottlenecks and system issues.
What will you learn?
- How to monitor system resources with htop and top
- How to track disk I/O activity with iotop and iostat
- How to analyze memory and virtual memory statistics with vmstat
- How to use sar for historical system activity reporting
- How to monitor processes and identify resource-intensive applications
Process Flow
- Real-time Monitoring: Use htop and top for live system resource viewing
- I/O Analysis: Monitor disk activity and identify I/O bottlenecks
- Memory Analysis: Track memory usage patterns and swap activity
- Historical Analysis: Use sar to review system performance over time
Practice


Display current system processes with top.
SOLUTION:
top -n 1
Check current system load and uptime.
SOLUTION:
uptime
Display memory usage information.
SOLUTION:
free -h
Show disk usage by filesystem.
SOLUTION:
df -h
Display directory size information.
SOLUTION:
du -sh /var/log
Monitor system activity with vmstat.
SOLUTION:
vmstat 2 3


Check I/O statistics with iostat.
SOLUTION:
iostat -x 1 2
Display current network connections.
SOLUTION:
ss -tuln
Show processes by CPU usage.
SOLUTION:
ps aux --sort=-%cpu | head -10
Show processes by MEMORY usage.
SOLUTION:
ps aux --sort=-%mem | head -10
Check system temperature (if available).
SOLUTION:
sensors || echo "sensors not available"
Monitor real-time process activity.
SOLUTION:
ps aux | grep -v grep | wc -l


Display system information.
SOLUTION:
uname -a
Check logged in users.
SOLUTION:
who
Display kernel ring buffer messages.
SOLUTION:
dmesg | tail -10
Check CPU information.
SOLUTION:
lscpu


Test Your Knowledge
What is the difference between top and htop commands?
htop provides a more user-friendly interface with color coding, mouse support, tree view, and easier process management compared to the basic top command.
What does the load average numbers represent in system monitoring?
Load average shows the system load over 1, 5, and 15 minutes. Values above the number of CPU cores indicate the system is under stress.
What is the purpose of the vmstat command?
vmstat displays virtual memory statistics including processes, memory, paging, block IO, traps, and CPU activity in real-time or at specified intervals.
How does iotop help in system monitoring?
iotop shows real-time disk I/O usage by processes, helping identify which processes are causing high disk activity and potential I/O bottlenecks.
What information does the sar command provide?
sar (System Activity Reporter) collects and reports system activity data including CPU usage, memory, I/O, and network statistics over time.


Lab 12: Cron Jobs & Scheduling
Lab Theory
What is this lab about?
This lab teaches you how to automate tasks and schedule jobs on Linux systems. You'll learn to use cron for recurring tasks, systemd timers for modern service scheduling, and the at command for one-time job execution.
What will you learn?
- How to create and manage cron jobs with crontab
- How to understand cron syntax and scheduling patterns
- How to work with system-wide and user-specific cron jobs
- How to use systemd timers as a modern alternative to cron
- How to schedule one-time tasks with the at command
Process Flow
- Cron Basics: Learn crontab syntax and create recurring jobs
- User Management: Handle personal and system cron jobs
- Advanced Scheduling: Use systemd timers for complex scheduling
- One-time Tasks: Schedule immediate or future one-time executions








Practice


View current user cron jobs.
SOLUTION:
crontab -l
Create a test script for cron jobs.
SOLUTION:
echo "#!/bin/bash" > /tmp/test_cron.sh && echo "echo \"Cron job executed at \$(date)\" >> /tmp/cron_output.log" >> /tmp/test_cron.sh && chmod +x /tmp/test_cron.sh
Add a cron job that runs every minute.
SOLUTION:
(crontab -l 2>/dev/null; echo "* * * * * /tmp/test_cron.sh") | crontab -
Wait and check if cron job created log file.
SOLUTION:
sleep 70 && ls -la /tmp/cron_output.log
View the contents of the cron log.
SOLUTION:
cat /tmp/cron_output.log
Add a daily cron job.
SOLUTION:
(crontab -l 2>/dev/null; echo "0 2 * * * /tmp/test_cron.sh") | crontab -
Add a weekly cron job.
SOLUTION:
(crontab -l 2>/dev/null; echo "0 3 * * 0 /tmp/test_cron.sh") | crontab -
List updated cron jobs.
SOLUTION:
crontab -l
Check system cron directories.
SOLUTION:
ls -la /etc/cron.*


Schedule a one-time task with at.
SOLUTION:
echo "echo \"At job executed at \$(date)\" >> /tmp/at_output.log" | at now + 2 minutes

List scheduled at jobs.
SOLUTION:
atq


Check cron service status.
SOLUTION:
systemctl status cron 2>/dev/null || systemctl status crond

View system cron logs.
SOLUTION:
journalctl -u cron -n 10 2>/dev/null || journalctl -u crond -n 10 2>/dev/null || grep CRON /var/log/syslog | tail -5 2>/dev/null || echo "Cron logs not available"


Wait and check at job output.
SOLUTION:
sleep 130 && cat /tmp/at_output.log 2>/dev/null || echo "At job may not have executed yet"
Remove the test cron jobs.
SOLUTION:
crontab -l | grep -v "/tmp/test_cron.sh" | crontab -

Test Your Knowledge
What do the five fields in a crontab entry represent?
The fields are: minute (0-59), hour (0-23), day of month (1-31), month (1-12), and day of week (0-7, where 0 and 7 are Sunday).
What is the difference between crontab -e and crontab -l?
crontab -e opens the cron editor to modify cron jobs, while crontab -l lists all current cron jobs for the user.
How do systemd timers differ from traditional cron jobs?
Systemd timers offer better logging, dependencies, calendar events, monotonic timers, and integration with systemd services, making them more powerful than cron.
What does the at command do?
The at command schedules one-time tasks to run at a specific time in the future, unlike cron which schedules recurring tasks.
Where are system-wide cron jobs typically stored?
System-wide cron jobs are stored in /etc/crontab, /etc/cron.d/, and the directories /etc/cron.hourly/, /etc/cron.daily/, /etc/cron.weekly/, /etc/cron.monthly/.


Lab 13: Log Management
Lab Theory
What is this lab about?
This lab covers comprehensive log management on Linux systems. You'll learn to navigate system logs, understand different logging systems, configure log rotation, and use logs for system troubleshooting and security monitoring.
What will you learn?
- How to use journalctl to query and filter systemd journal logs
- How to work with traditional syslog files and rsyslog configuration
- How to implement log rotation with logrotate to manage disk space
- How to monitor logs in real-time for system events and issues
- How to analyze logs for troubleshooting and security auditing
Process Flow
- Journal Access: Query systemd journal with journalctl filters
- Traditional Logs: Navigate syslog files and understand log formats
- Real-time Monitoring: Watch logs as events occur for immediate insights
- Log Management: Configure rotation and retention policies


Practice


View recent system journal entries.
SOLUTION:
journalctl -n 20

Check kernel messages from current boot.
SOLUTION:
journalctl -k -b
View logs for a specific service.
SOLUTION:
journalctl -u ssh
Show logs from the last hour.
SOLUTION:
journalctl --since "1 hour ago"
View system log file directly.
SOLUTION:
tail -20 /var/log/syslog
Monitor syslog in real-time.
SOLUTION:
tail -f /var/log/syslog &
Check authentication logs.
SOLUTION:
tail -10 /var/log/auth.log 2>/dev/null || journalctl -u ssh -n 10
Generate a test log entry.
SOLUTION:
logger "Test log entry from lab exercise"
Search for the test log entry.
SOLUTION:
journalctl | grep "Test log entry" | tail -1


View disk usage of journal logs.
SOLUTION:
journalctl --disk-usage
Check logrotate configuration.
SOLUTION:
ls -la /etc/logrotate.d/
View rsyslog configuration.
SOLUTION:
grep -v "^#" /etc/rsyslog.conf | grep -v "^$" | head -10
Show logs with priority level.
SOLUTION:
journalctl -p err
Check systemd service failures.
SOLUTION:
systemctl --failed


Stop the background tail process.
SOLUTION:
pkill -f "tail -f /var/log/syslog"


Test Your Knowledge
What is the difference between journalctl and traditional log files?
journalctl queries the systemd binary journal with structured data and advanced filtering, while traditional logs are text files in /var/log/ that use syslog format.
How does log rotation prevent disk space issues?
Log rotation automatically archives old logs, compresses them, and deletes very old ones based on size, age, or count limits, preventing logs from filling up disk space.
Basic Example of a Logrotate Configuration
Here’s a sample configuration:
# Rotate log files daily
daily  

# Keep 7 old log files
rotate 7  

# Compress old log files
compress  

# Create new log file after rotation
create  

# Log files that will be rotated
/var/log/apache2/*.log {
    rotate 5
    daily
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root adm
}



What is rsyslog and how does it work?
rsyslog is a system logging daemon that receives log messages from applications and the kernel, then routes them to appropriate files, remote servers, or other destinations based on rules.
What does the --follow option do in journalctl?
The --follow (or -f) option makes journalctl display new log entries in real-time as they are added, similar to tail -f for traditional log files.
Where are systemd journal files stored?
Systemd journal files are typically stored in /var/log/journal/ (persistent) or /run/log/journal/ (volatile, cleared on reboot).



Lab 14: Firewall & Security
Lab Theory
What is this lab about?
This lab introduces you to fundamental Linux security practices. You'll learn how to configure firewalls, protect against brute-force attacks, implement basic security hardening, and monitor system security events.
What will you learn?
- How to configure and manage UFW (Uncomplicated Firewall) for basic protection
- How to work with iptables for advanced firewall rules
- How to install and configure fail2ban to prevent brute-force attacks
- How to implement basic security hardening measures
- How to monitor security events and detect potential threats
Process Flow
- Firewall Setup: Configure UFW and iptables for network protection
- Intrusion Prevention: Set up fail2ban to block malicious IP addresses
- Security Hardening: Implement file permissions and access controls
- Monitoring: Track security events and failed login attempts




Practice
Check UFW status.
SOLUTION:
sudo ufw status
Enable UFW firewall.
SOLUTION:
sudo ufw enable
Allow SSH connections through firewall.
SOLUTION:
sudo ufw allow ssh
Allow HTTP traffic on port 80.
SOLUTION:
sudo ufw allow 80
Allow HTTPS traffic on port 443.
SOLUTION:
sudo ufw allow 443


Check updated UFW status.
SOLUTION:
sudo ufw status verbose
Check current iptables rules.
SOLUTION:
sudo iptables -L
Check if fail2ban is installed.
SOLUTION:
dpkg -l | grep fail2ban || echo "fail2ban not installed"


Install fail2ban (if not present).
SOLUTION:
sudo apt-get update && sudo apt-get install -y fail2ban 2>/dev/null || echo "fail2ban installation attempted"
Check fail2ban service status.
SOLUTION:
sudo systemctl status fail2ban
View fail2ban configuration directory.
SOLUTION:
ls -la /etc/fail2ban/
Check current fail2ban jails.
SOLUTION:
sudo fail2ban-client status 2>/dev/null || echo "fail2ban not running"
Check system login attempts.
SOLUTION:
sudo grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 || journalctl -u ssh | grep "Failed" | tail -5
Set strict umask for security.
SOLUTION:
umask 077
Check current umask setting.
SOLUTION:
umask
Test Your Knowledge
What is the difference between UFW and iptables?
UFW (Uncomplicated Firewall) is a user-friendly frontend for iptables, providing simpler commands. iptables is the underlying netfilter framework with more complex but powerful syntax.
How does fail2ban protect against brute-force attacks?
fail2ban monitors log files for repeated failed login attempts and automatically adds firewall rules to block the offending IP addresses for a configured duration.
What is the purpose of the principle of least privilege?
It means granting users and processes only the minimum access rights needed to perform their functions, reducing the potential attack surface.
What does the umask command control?
umask sets the default file permissions for newly created files and directories by defining which permission bits should be removed from the default permissions.
Why is it important to keep software updated for security?
Software updates often include security patches that fix vulnerabilities. Running outdated software leaves systems exposed to known exploits and attack vectors.







Lab 15: SSH & Remote Access
Lab Theory
What is this lab about?
This lab teaches you secure remote access and file transfer using SSH (Secure Shell). You'll learn to configure SSH servers, implement key-based authentication, transfer files securely, and use advanced SSH features for efficient remote system management.
What will you learn?
- How to configure SSH client and server settings
- How to generate and manage SSH key pairs for authentication
- How to transfer files securely using scp, sftp, and rsync over SSH
- How to use SSH tunneling and port forwarding
- How to implement SSH security best practices and hardening
Process Flow
- SSH Configuration: Set up client/server configs and key authentication
- File Transfer: Use various methods to securely transfer files
- Advanced Features: Implement tunneling, forwarding, and connection management
- Security Hardening: Apply best practices for SSH security


Practice


Check SSH client version.
SOLUTION:
ssh -V
Check SSH server status.
SOLUTION:
sudo systemctl status ssh 2>/dev/null || sudo systemctl status sshd
Generate SSH key pair.
SOLUTION:
ssh-keygen -t rsa -b 4096 -f ~/.ssh/test_rsa -N ""
List SSH keys in .ssh directory.
SOLUTION:
ls -la ~/.ssh/
View public key content.
SOLUTION:
cat ~/.ssh/test_rsa.pub
Add public key to authorized keys.
SOLUTION:
cat ~/.ssh/test_rsa.pub >> ~/.ssh/authorized_keys
Set correct permissions on SSH files.
SOLUTION:
chmod 600 ~/.ssh/authorized_keys ~/.ssh/test_rsa && chmod 644 ~/.ssh/test_rsa.pub
Test SSH connection to localhost.
SOLUTION:
ssh -i ~/.ssh/test_rsa -o StrictHostKeyChecking=no localhost "echo SSH connection successful"


Create test files for transfer.
SOLUTION:
mkdir -p ~/test_transfer && echo "Test file content" > ~/test_transfer/testfile.txt
Copy file using scp to another location.
SOLUTION:
scp ~/test_transfer/testfile.txt localhost:/tmp/scp_test.txt
Verify scp transfer worked.
SOLUTION:
cat /tmp/scp_test.txt


Use rsync for directory synchronization.
SOLUTION:
rsync -av ~/test_transfer/ localhost:/tmp/rsync_test/
Check SSH connection attempts in logs.
SOLUTION:
sudo grep "ssh" /var/log/auth.log 2>/dev/null | tail -5 || journalctl -u ssh -n 5
Show SSH configuration options.
SOLUTION:
ssh -G localhost | head -10


Check active SSH connections.
SOLUTION:
ss -tnlp | grep :22 || netstat -tnlp | grep :22


Test Your Knowledge
What is the difference between SSH keys and password authentication?
SSH keys use public-key cryptography (more secure, automated), while password authentication uses shared secrets (less secure, manual). Keys are recommended for better security.
What do the scp, sftp, and rsync commands do differently?
scp copies files over SSH, sftp provides interactive file transfer, and rsync synchronizes files/directories with delta transfer and many advanced options.
What is SSH tunneling and when would you use it?
SSH tunneling creates encrypted channels through SSH connections, allowing secure access to services on remote networks or bypassing firewalls while maintaining security.
What files contain SSH client and server configurations?
SSH client config is in ~/.ssh/config and /etc/ssh/ssh_config. SSH server config is in /etc/ssh/sshd_config.
What is the purpose of the SSH agent?
SSH agent manages SSH keys in memory, allowing single sign-on by caching unlocked private keys, eliminating the need to enter passphrases repeatedly.





Lab 16: Disk Management & Mounting
Lab Theory
What is this lab about?
This lab covers advanced disk management in Linux, including disk partitioning with fdisk, logical volume management (LVM), filesystem creation, and persistent mounting. These skills are essential for enterprise Linux administration and storage management.
What will you learn?
- How to use fdisk for disk partitioning and management.
- Understanding and implementing LVM (Logical Volume Manager).
- Creating and managing different filesystem types.
- Configuring persistent mounts using /etc/fstab.
- Advanced mounting techniques and options.
- Disk space management and monitoring techniques.
Process Flow
- Disk Analysis: Identify and analyze available storage devices.
- Partitioning: Create partitions using fdisk and other tools.
- LVM Setup: Configure physical volumes, volume groups, and logical volumes.
- Filesystem Creation: Format partitions with different filesystem types.
- Mounting: Mount filesystems temporarily and permanently.
- Monitoring: Check disk usage and health status.


Practice


List all available disk devices and their partitions.
SOLUTION:
lsblk -f
Display detailed disk information using fdisk.
SOLUTION:
sudo fdisk -l
Check disk space usage for all mounted filesystems.
SOLUTION:
df -h
Create a 1GB file to simulate a disk for practice.
SOLUTION:
sudo dd if=/dev/zero of=/tmp/disk.img bs=1M count=1024
Set up the file as a loop device.
SOLUTION:
sudo losetup /dev/loop0 /tmp/disk.img
Create a new partition table on the loop device using fdisk.
SOLUTION:
sudo fdisk /dev/loop0
Update the kernel partition table.
SOLUTION:
sudo partprobe /dev/loop0


Create an ext4 filesystem on the first partition.
SOLUTION:
sudo mkfs.ext4 /dev/loop0p1


Create a mount point directory.
SOLUTION:
sudo mkdir -p /mnt/testdisk
Mount the filesystem to the mount point.
SOLUTION:
sudo mount /dev/loop0p1 /mnt/testdisk


Verify the mount and check available space.
SOLUTION:
df -h /mnt/testdisk
Create a test file in the mounted filesystem.
SOLUTION:
sudo touch /mnt/testdisk/test.txt && echo "Hello from mounted filesystem" | sudo tee /mnt/testdisk/test.txt
Display the UUID of the filesystem.
SOLUTION:
sudo blkid /dev/loop0p1
Create a temporary fstab entry (simulation).
SOLUTION:
echo "# /dev/loop0p1 /mnt/testdisk ext4 defaults 0 2" | sudo tee -a /tmp/fstab.test
Unmount the filesystem safely.
SOLUTION:
sudo umount /mnt/testdisk
Check if any processes are using the mount point.
SOLUTION:
sudo lsof /mnt/testdisk || echo "No processes using mount point"
Detach the loop device.
SOLUTION:
sudo losetup -d /dev/loop0


Show current mount points and their options.
SOLUTION:
mount | grep -E "(ext4|xfs|btrfs)"
Test Your Knowledge
What is the difference between a physical partition and a logical volume in LVM?
Physical partitions are fixed-size divisions of a disk, while logical volumes in LVM are flexible and can span multiple physical volumes, be resized dynamically, and provide advanced features like snapshots.
What is the purpose of the /etc/fstab file?
/etc/fstab defines which filesystems are mounted automatically at boot time, specifying the device, mount point, filesystem type, options, and backup/fsck settings.
What are the advantages of LVM over traditional partitioning?
LVM provides dynamic resizing, spanning across multiple disks, snapshots for backups, easier migration, and the ability to create logical volumes that can be larger than individual physical disks.
What is the difference between ext4 and xfs filesystems?
ext4 is good for general use with features like journaling and backward compatibility. XFS excels with large files and high-performance workloads, better scalability, and advanced features like online defragmentation.
How do you permanently mount a filesystem in Linux?
Add an entry to /etc/fstab with the device, mount point, filesystem type, options, dump, and fsck fields, then run `mount -a` to test the configuration.
What is a swap partition and when would you use swap files instead?
Swap is virtual memory on disk. Swap files are more flexible than partitions - easier to resize, create, and remove without repartitioning. Modern systems often prefer swap files for their flexibility.


Lab 17: Advanced Shell Scripting
Lab Theory
What is this lab about?
This lab focuses on advanced shell scripting techniques that are essential for enterprise automation and system administration. You'll learn sophisticated error handling, debugging strategies, advanced parameter handling, and how to write maintainable, robust scripts.
What will you learn?
- Advanced error handling and exit codes in bash scripts.
- Debugging techniques using set options and debugging tools.
- Complex function creation and parameter handling.
- Advanced variable manipulation and array operations.
- Signal handling and trap mechanisms.
- Script optimization and best practices for enterprise environments.
Process Flow
- Script Structure: Learn advanced script organization and best practices.
- Error Handling: Implement comprehensive error checking and recovery.
- Debugging: Use built-in debugging features and external tools.
- Functions: Create reusable, modular script components.
- Signal Management: Handle system signals and cleanup operations.
- Testing: Validate script functionality and edge cases.

Practice
Create a script with proper shebang and error handling setup.
SOLUTION:
echo "#!/bin/bash |
set -euo pipefail" > /tmp/advanced_script.sh
Add a function to log messages with timestamps.
SOLUTION:
echo -e "
log_message() {
  echo "[$(date '%Y-%m-%d %H:%M:%S')] $*"
}" >> /tmp/advanced_script.sh
Add a cleanup function to handle script termination.
SOLUTION:
echo -e "
cleanup() {
  log_message "Cleaning up temporary files..."
  rm -f /tmp/script_temp_*
}
trap cleanup EXIT INT TERM" >> /tmp/advanced_script.sh
Add parameter validation function.
SOLUTION:
echo -e "
validate_params() {
  if [ $# -lt 1 ]; then
    log_message "ERROR: At least one parameter required"
    echo "Usage: $0 <command> [options]"
    exit 1
  fi
}" >> /tmp/advanced_script.sh
Add a function to check if a command exists.
SOLUTION:
echo -e "
command_exists() {
  command -v "$1" >/dev/null 2>&1
}" >> /tmp/advanced_script.sh


Create a retry mechanism function.
SOLUTION:
echo -e "
retry_command() {
  local max_attempts=$1
  local delay=$2
  shift 2
  local count=0
  until "$@"; do
    count=$((count + 1))
    if [ $count -ge $max_attempts ]; then
      log_message "Command failed after $max_attempts attempts"
      return 1
    fi
    log_message "Attempt $count failed, retrying in $delay seconds..."
    sleep $delay
  done
}" >> /tmp/advanced_script.sh
Add array processing function.
SOLUTION:
echo -e "
process_array() {
  local -n arr_ref=$1
  local operation=$2
  for item in "${arr_ref[@]}"; do
    log_message "Processing: $item with $operation"
    case $operation in
      "validate") [ -f "$item" ] && echo "Valid: $item" || echo "Invalid: $item" ;;
      "backup") cp "$item" "$item.bak" 2>/dev/null && echo "Backed up: $item" ;;
      *) echo "Unknown operation: $operation" ;;
    esac
  done
}" >> /tmp/advanced_script.sh
Add configuration file parser.
SOLUTION:
echo -e "
parse_config() {
  local config_file=$1
  if [ ! -f "$config_file" ]; then
    log_message "Config file not found: $config_file"
    return 1
  fi
  while IFS="=" read -r key value; do
    [ -z "$key" ] || [[ $key == \#* ]] && continue
    declare -g "CONFIG_$key"="$value"
    log_message "Loaded config: $key=$value"
  done < "$config_file"
}" >> /tmp/advanced_script.sh
Add main script logic with command line parsing.
SOLUTION:
echo -e "
main() {
  validate_params "$@"
  
  while getopts "hvd:c:" opt; do
    case $opt in
      h) echo "Usage: $0 [-h] [-v] [-d delay] [-c config] command"; exit 0 ;;
      v) set -x ;;
      d) DELAY=$OPTARG ;;
      c) CONFIG_FILE=$OPTARG ;;
      ?) exit 1 ;;
    esac
  done
  shift $((OPTIND-1))
  
  log_message "Script started with command: $1"
}

# Set defaults
DELAY=1
CONFIG_FILE="/tmp/script.conf"

# Run main function
main "$@"" >> /tmp/advanced_script.sh
Make the script executable.
SOLUTION:
chmod +x /tmp/advanced_script.sh
Create a simple config file for testing.
SOLUTION:
echo -e "DATABASE_HOST=localhost
DATABASE_PORT=5432
DEBUG_MODE=true
# This is a comment
LOG_LEVEL=info" > /tmp/script.conf


Test the script with help option.
SOLUTION:
/tmp/advanced_script.sh -h


Create a debug version that shows variable values.
SOLUTION:
echo -e "
debug_info() {
  log_message "=== Debug Information ==="
  log_message "Script: $0"
  log_message "PID: $$"
  log_message "User: $(whoami)"
  log_message "PWD: $PWD"
  log_message "Arguments: $*"
  log_message "========================"
}" >> /tmp/advanced_script.sh
Add input validation with regex.
SOLUTION:
echo -e "
validate_email() {
  local email=$1
  if [[ $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    log_message "Valid email: $email"
    return 0
  else
    log_message "Invalid email: $email"
    return 1
  fi
}" >> /tmp/advanced_script.sh


Test script syntax without execution.
SOLUTION:
bash -n /tmp/advanced_script.sh
Create a performance monitoring function.
SOLUTION:
echo -e "
monitor_performance() {
  local start_time=$(date +%s.%N)
  "$@"
  local exit_code=$?
  local end_time=$(date +%s.%N)
  local duration=$(echo "$end_time - $start_time" | bc -l)
  log_message "Command: $* | Exit code: $exit_code | Duration: ${duration}s"
  return $exit_code
}" >> /tmp/advanced_script.sh


Add parallel processing capability.
SOLUTION:
echo -e "
parallel_process() {
  local max_jobs=$1
  shift
  local pids=()
  for item in "$@"; do
    while [ ${#pids[@]} -ge $max_jobs ]; do
      for i in "${!pids[@]}"; do
        if ! kill -0 ${pids[i]} 2>/dev/null; then
          wait ${pids[i]}
          unset pids[i]
        fi
      done
      pids=("${pids[@]}")
      sleep 0.1
    done
    (
      log_message "Processing $item in background"
      sleep 2  # Simulate work
      log_message "Completed $item"
    ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do
    wait $pid
  done
}" >> /tmp/advanced_script.sh
Create a comprehensive test of all functions.
SOLUTION:
echo -e "
# Test all functions
if [ "$1" = "test" ]; then
  debug_info
  validate_email "test@example.com"
  validate_email "invalid-email"
  echo "file1 file2 file3" | xargs -n1 touch
  files=("file1" "file2" "file3")
  process_array files validate
  parallel_process 2 "task1" "task2" "task3" "task4"
  cleanup
fi" >> /tmp/advanced_script.sh

Test Your Knowledge
What is the difference between $@ and $* in bash scripting?
$@ preserves the original arguments as separate quoted strings, while $* concatenates all arguments into a single string. $@ is generally preferred for passing arguments to other commands.

How do you implement proper error handling in bash scripts?
Use set -e to exit on errors, set -u for undefined variables, implement trap for cleanup, check command exit codes with $?, and provide meaningful error messages with proper logging.
What are the benefits of using functions in shell scripts?
Functions promote code reusability, improve maintainability, enable modular design, provide local variable scoping, and make scripts easier to test and debug.
How do you debug a shell script effectively?
Use set -x for execution tracing, set -v for verbose mode, add echo statements, use the bash debugger (bashdb), validate syntax with bash -n, and implement logging mechanisms.
What is the purpose of trap in shell scripting?
trap allows you to catch signals and execute cleanup code when a script exits unexpectedly, ensuring resources are properly released and temporary files are cleaned up.
How do you handle command-line arguments robustly in bash?
Use getopts for option parsing, validate argument counts, provide default values, implement help messages, and handle both short and long options appropriately.
Lab 18: System Services & Systemd
Lab Theory
What is this lab about?
This lab covers comprehensive systemd service management, which is the standard init system and service manager for modern Linux distributions. You'll learn to manage services, create custom unit files, configure service dependencies, and troubleshoot service issues.
What will you learn?
- Complete systemctl command usage for service management.
- Creating and configuring custom systemd unit files.
- Understanding service states, targets, and dependencies.
- Advanced systemd features like timers and sockets.
- Service logging and troubleshooting with journalctl.
- Security and isolation features in systemd services.
Process Flow
- Service Discovery: List and examine existing services and their states.
- Service Control: Start, stop, enable, and disable services.
- Unit File Creation: Write custom service definitions.
- Dependency Management: Configure service relationships and ordering.
- Monitoring: Use logs and status commands for service health.
- Advanced Features: Implement timers, socket activation, and security settings.


Practice
List all active systemd services.
SOLUTION:
systemctl list-units --type=service --state=active

Show the status of the SSH service.
SOLUTION:
systemctl status ssh || systemctl status sshd
Example: 
root@c997e80ea65b3b53:~# systemctl list-units --type=service --state=active
  UNIT                               LOAD   ACTIVE
 SUB     DESCRIPTION                                             
 
  dbus.service                       loaded active running D-Bus System Message 
Bus                                 
  getty@tty1.service                 loaded active running Getty on tty1        
                                    
  kmod-static-nodes.service          loaded active exited  Create list of static
 device nodes for the current kernel
  networkd-dispatcher.service        loaded active running Dispatcher daemon for
 systemd-networkd                   
  serial-getty@ttyS0.service         loaded active running Serial Getty on ttyS0
                                    
  ssh.service                        loaded active running OpenBSD Secure Shell 
server                              
  systemd-journal-flush.service      loaded active exited  Flush Journal to Pers
istent Storage                      
  systemd-journald.service           loaded active running Journal Service      
                                    
  systemd-logind.service             loaded active running Login Service        
                                    
  systemd-modules-load.service       loaded active exited  Load Kernel Modules  
                                    
  systemd-random-seed.service        loaded active exited  Load/Save Random Seed
                                    
  systemd-remount-fs.service         loaded active exited  Remount Root and Kern
el File Systems                     
  systemd-resolved.service           loaded active running Network Name Resoluti
on                                  
  systemd-sysctl.service             loaded active exited  Apply Kernel Variable
s                                   
  systemd-sysusers.service           loaded active exited  Create System Users  
                                    
  systemd-timesyncd.service          loaded active running Network Time Synchron
ization                             
  systemd-tmpfiles-setup-dev.service loaded active exited  Create Static Device 
Nodes in /dev                       
  systemd-tmpfiles-setup.service     loaded active exited  Create Volatile Files
 and Directories                    
  systemd-udev-trigger.service       loaded active exited  udev Coldplug all Dev
ices                                
  systemd-udevd.service              loaded active running udev Kernel Device Ma
nager                               
  systemd-update-utmp.service        loaded active exited  Update UTMP about Sys
tem Boot/Shutdown                   
  systemd-user-sessions.service      loaded active exited  Permit User Sessions 
                                    
  user-runtime-dir@0.service         loaded active exited  User Runtime Director
y /run/user/0                       
  user@0.service                     loaded active running User Manager for UID 
0                                   

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.

24 loaded units listed.
Show the status of the SSH service.
SOLUTION:
systemctl status ssh || systemctl status sshd
List all failed services.
SOLUTION:
systemctl list-units --failed
root@c997e80ea65b3b53:~# systemctl list-units --failed
  UNIT LOAD ACTIVE SUB DESCRIPTION

0 loaded units listed.


Create a simple custom service unit file.
SOLUTION:
sudo tee /etc/systemd/system/myapp.service > /dev/null << EOF
[Unit]
Description=My Custom Application
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/bin/bash -c "while true; do echo \"MyApp is running - $(date)\" >> /tmp/myapp.log; sleep 30; done"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
Reload systemd configuration to recognize new service.
SOLUTION:
sudo systemctl daemon-reload
Start the custom service.
SOLUTION:
sudo systemctl start myapp.service
root@c997e80ea65b3b53:~# sudo systemctl daemon-reload
root@c997e80ea65b3b53:~# sudo systemctl start myapp.service
root@c997e80ea65b3b53:~# sudo systemctl status myapp.service
● myapp.service - My Custom Application
     Loaded: loaded (/etc/systemd/system/myapp.service; disabled; vendor preset:
 enabled)
     Active: active (running) since Fri 2025-09-12 13:49:34 UTC; 11s 
ago
   Main PID: 1030 (bash)
      Tasks: 2 (limit: 1172)
     Memory: 572.0K
     CGroup: /system.slice/myapp.service
             ├─1030 /bin/bash -c while true; do echo "MyApp is running - Fri Sep 1
2 13:49:02 UTC 2025" >> /tmp/myapp.log; sleep 30; done
             └─1031 sleep 30

Sep 12 13:49:34 c997e80ea65b3b53 systemd[1]: Started My Custom Application.
Enable the service to start at boot.
SOLUTION:
sudo systemctl enable myapp.service
View logs for your custom service.
SOLUTION:
journalctl -u myapp.service -f --lines=10
Create a service with environment variables.
SOLUTION:
sudo tee /etc/systemd/system/webapp.service > /dev/null << EOF
[Unit]
Description=Web Application Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=www-data
Group=www-data
Environment=APP_ENV=production
Environment=LOG_LEVEL=info
EnvironmentFile=-/etc/default/webapp
ExecStart=/bin/bash -c "echo \"Starting webapp with ENV=\$APP_ENV LEVEL=\$LOG_LEVEL\" >> /tmp/webapp.log"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
Create an environment file for the webapp service.
SOLUTION:
sudo mkdir -p /etc/default && echo -e "DATABASE_URL=postgresql://localhost:5432/webapp
SECRET_KEY=mysecretkey123" | sudo tee /etc/default/webapp


Create a timer unit to run a service periodically.
SOLUTION:
sudo tee /etc/systemd/system/backup.timer > /dev/null << EOF
[Unit]
Description=Run backup service every hour
Requires=backup.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

Create the corresponding backup service.
SOLUTION:
sudo tee /etc/systemd/system/backup.service > /dev/null << EOF
[Unit]
Description=Backup Service

[Service]
Type=oneshot
User=root
ExecStart=/bin/bash -c "echo \"Backup started at $(date)\" >> /tmp/backup.log && tar -czf /tmp/backup-$(date +%%Y%%m%%d-%%H%%M%%S).tar.gz /etc/hostname"
EOF
Enable and start the backup timer.
SOLUTION:
sudo systemctl daemon-reload && sudo systemctl enable backup.timer && sudo systemctl start backup.timer


List all active timers.
SOLUTION:
systemctl list-timers --active
Create a service with security restrictions.
SOLUTION:
sudo tee /etc/systemd/system/secure-app.service > /dev/null << EOF
[Unit]
Description=Secure Application
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/bin/bash -c "while true; do echo \"Secure app running - $(date)\" >> /tmp/secure-app.log; sleep 60; done"
Restart=always

# Security settings
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
EOF
Analyze service startup times.
SOLUTION:
systemd-analyze blame | head -10
Show service dependency tree for a target.
SOLUTION:
systemctl list-dependencies multi-user.target
Stop and disable all custom services.
SOLUTION:
sudo systemctl stop myapp.service webapp.service secure-app.service backup.timer && sudo systemctl disable myapp.service webapp.service secure-app.service backup.timer
Test Your Knowledge
What is the difference between starting and enabling a systemd service?
Starting a service runs it immediately, while enabling a service configures it to start automatically at boot. You typically need to do both for services you want running persistently.
What are systemd targets and how do they relate to runlevels?
Targets are groups of units that define system states, similar to traditional runlevels. Common targets include multi-user.target (like runlevel 3) and graphical.target (like runlevel 5).
How does systemd handle service dependencies?
Systemd uses directives like Requires, Wants, After, and Before in unit files to define dependencies and startup ordering, ensuring services start in the correct sequence.
What are the advantages of systemd over traditional init systems?
Systemd provides parallel service startup, on-demand activation, dependency management, integrated logging with journald, socket activation, and comprehensive service management features.
How do you troubleshoot a failing systemd service?
Use systemctl status, journalctl -u service-name, check unit file syntax, verify dependencies, examine logs, and use systemd-analyze for startup issues.
What is socket activation in systemd?
Socket activation allows systemd to listen on sockets and start services on-demand when connections are made, improving resource usage and startup times.
Lab 19: Network Configuration
Lab Theory
What is this lab about?
This lab focuses on comprehensive network configuration and management in Linux systems. You'll learn to configure network interfaces, manage routing tables, set up DNS resolution, implement network bonding, and troubleshoot complex network issues using modern tools.
What will you learn?
- Network interface configuration with ip and nmcli commands.
- Advanced routing configuration and policy-based routing.
- DNS configuration and troubleshooting techniques.
- Network bonding and bridging for high availability.
- Firewall configuration with iptables and firewalld.
- Network performance monitoring and optimization.
Process Flow
- Interface Discovery: Identify and examine network interfaces and their configurations.
- Interface Configuration: Configure IP addresses, routes, and network settings.
- Routing Management: Set up static routes, default gateways, and routing policies.
- DNS Configuration: Configure name resolution and DNS servers.
- Advanced Features: Implement network bonding, VLANs, and bridges.
- Troubleshooting: Use network diagnostic tools and performance monitoring.


Practice


Display all network interfaces and their configurations.
SOLUTION:
ip addr show
Show routing table information.
SOLUTION:
ip route show
Display network interface statistics.
SOLUTION:
ip -s link show


Check connectivity to a remote host.
SOLUTION:
ping -c 4 8.8.8.8
Perform DNS lookup using dig.
SOLUTION:
dig google.com
Or nslookup google.com


Show DNS configuration.
SOLUTION:
cat /etc/resolv.conf
Display network connections and listening ports.
SOLUTION:
ss -tuln
Trace route to a destination.
SOLUTION:
traceroute 8.8.8.8 || tracepath 8.8.8.8
Create a temporary IP alias on an interface.
SOLUTION:
sudo ip addr add 192.168.100.10/24 dev lo label lo:test
Add a temporary static route.
SOLUTION:
sudo ip route add 10.10.10.0/24 via 192.168.1.1 dev eth0 2>/dev/null  sudo ip route add 10.10.10.0/24 via 127.0.0.1 dev lo


Check ARP table entries.
SOLUTION:
ip neigh show
Monitor network traffic on an interface.
SOLUTION:
sudo tcpdump -i lo -c 10
Check network interface link status.
SOLUTION:
ip link show | grep -A1 -E "(UP|DOWN)"


Configure a network namespace for testing.
SOLUTION:
sudo ip netns add testns
Execute a command inside the network namespace.
SOLUTION:
sudo ip netns exec testns ip addr show
Create a virtual ethernet pair.
SOLUTION:
sudo ip link add veth0 type veth peer name veth1


Move one end of veth pair to namespace.
SOLUTION:
sudo ip link set veth1 netns testns
Configure IP addresses on veth interfaces.
SOLUTION:
sudo ip addr add 192.168.50.1/24 dev veth0 && sudo ip link set veth0 up
Configure the interface inside the namespace.
SOLUTION:
sudo ip netns exec testns ip addr add 192.168.50.2/24 dev veth1 && sudo ip netns exec testns ip link set veth1 up
Test connectivity between namespace and host.
SOLUTION:
ping -c 2 192.168.50.2
Show network statistics and counters.
SOLUTION:
cat /proc/net/dev
Test bandwidth using iperf3 (if available).
SOLUTION:
which iperf3 >/dev/null && echo "iperf3 available for bandwidth testing" || echo "iperf3 not available - install with: apt-get install iperf3"
Test Your Knowledge
What is the difference between the ip and ifconfig commands?
ip is the modern replacement for ifconfig, part of iproute2 package. It provides more functionality, better performance, and is the recommended tool for network configuration in modern Linux distributions.
How does network bonding improve network reliability?
Network bonding combines multiple network interfaces into a single logical interface, providing redundancy, load balancing, and increased bandwidth through various bonding modes like active-backup or LACP.
What are the differences between static and dynamic routing?
Static routing uses manually configured routes that don't change, while dynamic routing uses protocols like OSPF or BGP to automatically adjust routes based on network topology changes.
How do you troubleshoot DNS resolution issues in Linux?
Use tools like nslookup, dig, host, check /etc/resolv.conf, verify network connectivity to DNS servers, and examine systemd-resolved configuration if applicable.
What is the purpose of the /etc/hosts file?
The /etc/hosts file provides local hostname-to-IP address mapping that takes precedence over DNS lookups, useful for local resolution and overriding DNS entries.
How do VLANs work at the Linux level?
VLANs are configured using VLAN interfaces (like eth0.100) that tag network traffic with VLAN IDs, allowing traffic separation on the same physical network infrastructure.
Lab 20: Web Server Setup
Lab Theory
What is this lab about?
This lab covers comprehensive web server setup and configuration in Linux environments. You'll learn to install and configure both Apache and Nginx web servers, set up virtual hosts, implement SSL/TLS encryption, and optimize server performance for production use.
What will you learn?
- Apache HTTP Server installation, configuration, and modules.
- Nginx installation, configuration, and advanced features.
- Virtual host configuration for multiple websites.
- SSL/TLS certificate installation and HTTPS configuration.
- Web server security hardening and performance optimization.
- Log management and monitoring for web servers.
Process Flow
- Installation: Install Apache and/or Nginx web servers.
- Basic Configuration: Configure basic server settings and document roots.
- Virtual Hosts: Set up multiple websites on the same server.
- SSL/TLS: Implement HTTPS with self-signed or Let's Encrypt certificates.
- Security: Harden server configuration and implement security best practices.
- Performance: Optimize server settings for better performance and scalability.


Practice


Update package repository and install Apache.
SOLUTION:
sudo apt-get update && sudo apt-get install apache2 -y
Start and enable Apache service.
SOLUTION:
sudo systemctl start apache2 && sudo systemctl enable apache2
Check Apache service status.
SOLUTION:
systemctl status apache2
Test Apache default page.
SOLUTION:
curl -s http://localhost | grep -i apache || echo "Apache default page accessible"
Create a custom website directory.
SOLUTION:
sudo mkdir -p /var/www/mysite.com/html
Create a simple HTML page.
SOLUTION:
sudo tee /var/www/mysite.com/html/index.html > /dev/null << EOF
<!DOCTYPE html>
<html>
<head>
    <title>My Custom Site</title>
</head>
<body>
    <h1>Welcome to My Site</h1>
    <p>This is a custom website hosted on Apache.</p>
    <p>Server time: $(date)</p>
</body>
</html>
EOF
Set proper ownership for web files.
SOLUTION:
sudo chown -R www-data:www-data /var/www/mysite.com/


Create Apache virtual host configuration.
SOLUTION:
sudo tee /etc/apache2/sites-available/mysite.com.conf > /dev/null << EOF
<VirtualHost *:80>
    ServerAdmin admin@mysite.com
    ServerName mysite.com
    ServerAlias www.mysite.com
    DocumentRoot /var/www/mysite.com/html
    ErrorLog \${APACHE_LOG_DIR}/mysite.com_error.log
    CustomLog \${APACHE_LOG_DIR}/mysite.com_access.log combined
    
    <Directory /var/www/mysite.com/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF


Enable the new virtual host.
SOLUTION:
sudo a2ensite mysite.com.conf
root@1d9c83dc777e478e:~# sudo a2ensite mysite.com.conf
Enabling site mysite.com.
To activate the new configuration, you need to run:
  systemctl reload apache2

Disable the default Apache site.
SOLUTION:
sudo a2dissite 000-default.conf


Test Apache configuration syntax.
SOLUTION:
sudo apache2ctl configtest
root@1d9c83dc777e478e:~# systemctl reload apache2
root@1d9c83dc777e478e:~# apache2ctl configtest
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 127.0.0.1. Set the 'ServerName' directive globally to suppress this message
Syntax OK
Reload Apache configuration.
SOLUTION:
sudo systemctl reload apache2
Install Nginx alongside Apache (on different port).
SOLUTION:
sudo apt-get install nginx -y
Configure Nginx to run on port 8080.
SOLUTION:
sudo sed -i "s/listen 80/listen 8080/" /etc/nginx/sites-available/default
Create Nginx server block for custom site.
SOLUTION:
sudo tee /etc/nginx/sites-available/mynginxsite.com > /dev/null << EOF
server {
    listen 8081;
    server_name mynginxsite.com www.mynginxsite.com;
    root /var/www/mynginxsite.com/html;
    index index.html index.htm;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    access_log /var/log/nginx/mynginxsite.com_access.log;
    error_log /var/log/nginx/mynginxsite.com_error.log;
}
EOF
Create directory and content for Nginx site.
SOLUTION:
sudo mkdir -p /var/www/mynginxsite.com/html && sudo tee /var/www/mynginxsite.com/html/index.html > /dev/null << EOF
<!DOCTYPE html>
<html>
<head>
    <title>My Nginx Site</title>
</head>
<body>
    <h1>Welcome to My Nginx Site</h1>
    <p>This site is served by Nginx on port 8081.</p>
    <p>Server: Nginx</p>
</body>
</html>
EOF
Enable Nginx site and set permissions.
SOLUTION:
sudo ln -s /etc/nginx/sites-available/mynginxsite.com /etc/nginx/sites-enabled/ && sudo chown -R www-data:www-data /var/www/mynginxsite.com/
Test Nginx configuration.
SOLUTION:
sudo nginx -t
Start Nginx service.
SOLUTION:
sudo systemctl start nginx && sudo systemctl enable nginx
Test both web servers.
SOLUTION:
curl -s http://localhost:80 | grep -i "My Custom Site" && curl -s http://localhost:8081 | grep -i "My Nginx Site"

Generate self-signed SSL certificate.
SOLUTION:
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=mysite.com"
Enable Apache SSL module.
SOLUTION:
sudo a2enmod ssl
root@1d9c83dc777e478e:~# sudo a2enmod ssl
Considering dependency setenvif for ssl:
Module setenvif already enabled
Considering dependency mime for ssl:
Module mime already enabled
Considering dependency socache_shmcb for ssl:
Enabling module socache_shmcb.
Enabling module ssl.
See /usr/share/doc/apache2/README.Debian.gz on how to configure SSL and create self-signed certificates.
To activate the new configuration, you need to run:
  systemctl restart apache2
root@1d9c83dc777e478e:~# systemctl restart apache2
Create HTTPS virtual host.
SOLUTION:
sudo tee /etc/apache2/sites-available/mysite.com-ssl.conf > /dev/null << EOF
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerAdmin admin@mysite.com
    ServerName mysite.com
    ServerAlias www.mysite.com
    DocumentRoot /var/www/mysite.com/html
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt
    SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key
    
    ErrorLog \${APACHE_LOG_DIR}/mysite.com_ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/mysite.com_ssl_access.log combined
</VirtualHost>
</IfModule>
EOF

Enable HTTPS site and reload Apache.
SOLUTION:
sudo a2ensite mysite.com-ssl.conf && sudo systemctl reload apache2
root@1d9c83dc777e478e:~# sudo a2ensite mysite.com-ssl.conf && sudo systemctl reload apache2
Enabling site mysite.com-ssl.
To activate the new configuration, you need to run:
  systemctl reload apache2
root@1d9c83dc777e478e:~# systemctl reload apache2


Test Your Knowledge


What are the main differences between Apache and Nginx?
Apache uses a process-based model with modules, better for dynamic content and .htaccess support. Nginx uses an event-driven model, excels at serving static content, reverse proxying, and handles more concurrent connections with lower memory usage.
What is a virtual host and why is it useful?
A virtual host allows one web server to serve multiple websites/domains from the same server. It's useful for hosting multiple sites, reducing server costs, and managing different configurations per site.
How does SSL/TLS encryption work in web servers?
SSL/TLS creates encrypted connections between clients and servers using public/private key cryptography. The server presents a certificate to prove identity, then establishes an encrypted channel for secure data transmission.
What is a reverse proxy and when would you use Nginx as one?
A reverse proxy sits between clients and backend servers, forwarding requests and responses. Use Nginx as a reverse proxy for load balancing, SSL termination, caching, and serving static content while forwarding dynamic requests to application servers.
How do you troubleshoot web server performance issues?
Monitor server resources (CPU, memory, disk I/O), analyze access and error logs, check network connectivity, optimize configurations, use tools like htop, iotop, and analyze slow query logs for database-backed applications.
What security measures should be implemented for production web servers?
Use HTTPS, keep software updated, configure firewalls, disable unnecessary modules, implement proper file permissions, use security headers, hide server version information, and regularly monitor logs for suspicious activity.


Lab 21: Database Administration
Lab Theory
What is this lab about?
This lab focuses on comprehensive database administration skills for MySQL and PostgreSQL on Linux systems. You'll learn installation procedures, security configuration, user and privilege management, database operations, backup strategies, and performance optimization techniques.
What will you learn?
- MySQL and PostgreSQL installation and initial configuration.
- Database security hardening and authentication setup.
- User management, roles, and privilege assignment.
- Database creation, schema management, and data operations.
- Backup and restore procedures for data protection.
- Performance monitoring and optimization techniques.
Process Flow
- Installation: Install and configure MySQL and PostgreSQL servers.
- Security: Implement security best practices and authentication.
- User Management: Create users, assign roles, and manage privileges.
- Database Operations: Create databases, tables, and perform basic operations.
- Backup/Restore: Implement backup strategies and test restore procedures.
- Monitoring: Set up monitoring and performance optimization.


Practice
Update package repository.
SOLUTION:
sudo apt-get update
Install MySQL server.
SOLUTION:
sudo apt-get install mysql-server -y
Start and enable MySQL service.
SOLUTION:
sudo systemctl start mysql && sudo systemctl enable mysql


Check MySQL service status.
SOLUTION:
systemctl status mysql
Connect to MySQL and show databases.
SOLUTION:
sudo mysql -e "SHOW DATABASES;"
root@0563d9cd62a5f130:~# sudo systemctl start mysql && sudo systemctl enable mysql
Synchronizing state of mysql.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable mysql
root@0563d9cd62a5f130:~# systemctl status mysql
● mysql.service - MySQL Community Server
     Loaded: loaded (/lib/systemd/system/mysql.service; enabled; vendor preset: 
enabled)
     Active: active (running) since Fri 2025-09-12 16:01:16 UTC; 9s a
go
   Main PID: 1899 (mysqld)
     Status: "Server is operational"
      Tasks: 38 (limit: 1172)
     Memory: 365.0M
     CGroup: /system.slice/mysql.service
             └─1899 /usr/sbin/mysqld

Sep 12 16:01:15 0563d9cd62a5f130 systemd[1]: Starting MySQL Community Server...
Sep 12 16:01:16 0563d9cd62a5f130 systemd[1]: Started MySQL Community Server.
root@0563d9cd62a5f130:~# sudo mysql -e "SHOW DATABASES;"
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+


Create a new MySQL database.
SOLUTION:
sudo mysql -e "CREATE DATABASE testdb;"


Create a MySQL user with password.
SOLUTION:
sudo mysql -e "CREATE USER 'testuser'@'localhost' IDENTIFIED BY 'testpass123';"
Grant privileges to the MySQL user.
SOLUTION:
sudo mysql -e "GRANT ALL PRIVILEGES ON testdb.* TO 'testuser'@'localhost';"
Flush MySQL privileges.
SOLUTION:
sudo mysql -e "FLUSH PRIVILEGES;"
Test connection with new user.
SOLUTION:
mysql -u testuser -ptestpass123 testdb -e "SELECT DATABASE(), USER();"

root@0563d9cd62a5f130:~# sudo mysql -e "CREATE DATABASE testdb;"
root@0563d9cd62a5f130:~# sudo mysql -e "CREATE USER 'testuser'@'localhost' IDENTIFIED BY 'testpass123';"
root@0563d9cd62a5f130:~# sudo mysql -e "GRANT ALL PRIVILEGES ON testdb.* TO 'testuser'@'localhost';"
root@0563d9cd62a5f130:~# sudo mysql -e "FLUSH PRIVILEGES;"
root@0563d9cd62a5f130:~# mysql -u testuser -ptestpass123 testdb -e "SELECT DATABASE(), USER();"
mysql: [Warning] Using a password on the command line interface can be insecure.
+------------+--------------------+
| DATABASE() | USER()             |
+------------+--------------------+
| testdb     | testuser@localhost |
+------------+--------------------+
root@0563d9cd62a5f130:~# 

Start and enable PostgreSQL service.
SOLUTION:
sudo systemctl start postgresql && sudo systemctl enable postgresql
Switch to postgres user and access PostgreSQL.
SOLUTION:
sudo -u postgres psql -c "\l"
Create a PostgreSQL database.
SOLUTION:
sudo -u postgres createdb testpgdb

Apt-get install -y postgresql
root@0563d9cd62a5f130:~# sudo systemctl start postgresql &&  sudo systemctl enab
le postgresql
Synchronizing state of postgresql.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable postgresql
root@0563d9cd62a5f130:~# sudo -u postgres psql -c "\l"
could not change directory to "/root": Permission denied
                              List of databases
   Name    |  Owner   | Encoding | Collate |  Ctype  |   Access privileges   
-----------+----------+----------+---------+---------+-----------------------
 postgres  | postgres | UTF8     | C.UTF-8 | C.UTF-8 | 
 template0 | postgres | UTF8     | C.UTF-8 | C.UTF-8 | =c/postgres          +
           |          |          |         |         | postgres=CTc/postgres
 template1 | postgres | UTF8     | C.UTF-8 | C.UTF-8 | =c/postgres          +
           |          |          |         |         | postgres=CTc/postgres
(3 rows)

root@0563d9cd62a5f130:~# sudo -u postgres createdb testpgdb
could not change directory to "/root": Permission denied
Create a PostgreSQL user.
SOLUTION:
sudo -u postgres createuser --interactive --pwprompt testpguser || sudo -u postgres psql -c "CREATE USER testpguser WITH PASSWORD 'testpass123';"

root@0563d9cd62a5f130:~# sudo -u postgres createuser --interactive --pwprompt testpguser || sudo -u postgres psql -c "CREATE USER testpguser WITH PASSWORD 'testpass123';"
could not change directory to "/root": Permission denied
Enter password for new role: 
Enter it again: 
Shall the new role be a superuser? (y/n) y
root@0563d9cd62a5f130:~# 

Grant database privileges to PostgreSQL user.
SOLUTION:
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE testpgdb TO testpguser;"
Create a simple table in MySQL.
SOLUTION:
mysql -u testuser -ptestpass123 testdb -e "CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(50), email VARCHAR(100));"
Insert sample data into MySQL table.
SOLUTION:
mysql -u testuser -ptestpass123 testdb -e "INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com'), ('Jane Smith', 'jane@example.com');"


Query data from MySQL table.
SOLUTION:
mysql -u testuser -ptestpass123 testdb -e "SELECT * FROM users;"


root@0563d9cd62a5f130:/home# mysql -u testuser -ptestpass123 testdb -e "SELECT * FROM users;"
mysql: [Warning] Using a password on the command line interface can be insecure.
+----+------------+------------------+
| id | name       | email            |
+----+------------+------------------+
|  1 | John Doe   | john@example.com |
|  2 | Jane Smith | jane@example.com |
+----+------------+------------------+
Create backup of MySQL database.
SOLUTION:
mysqldump -u testuser -ptestpass123 testdb > /tmp/testdb_backup.sql
Create a PostgreSQL table and insert data.
SOLUTION:
sudo -u postgres psql testpgdb -c "CREATE TABLE products (id SERIAL PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2)); INSERT INTO products (name, price) VALUES ('Laptop', 999.99), ('Mouse', 25.50);"
Create backup of PostgreSQL database.
SOLUTION:
sudo -u postgres pg_dump testpgdb > /tmp/testpgdb_backup.sql
Show MySQL process list.
SOLUTION:
sudo mysql -e "SHOW PROCESSLIST;"
Check PostgreSQL active connections.
SOLUTION:
sudo -u postgres psql -c "SELECT pid, usename, application_name, client_addr, state FROM pg_stat_activity WHERE state = 'active';"

root@0563d9cd62a5f130:/home# sudo -u postgres psql -c "SELECT pid, usename, application_name, client_addr, state FROM pg_stat_activity WHERE state = 'active';"
 pid  | usename  | application_name | client_addr | state  
------+----------+------------------+-------------+--------
 4491 | postgres | psql             |             | active
(1 row)


Test database backup restoration.
SOLUTION:
mysql -u testuser -ptestpass123 -e "CREATE DATABASE testdb_restore;" && mysql -u testuser -ptestpass123 testdb_restore < /tmp/testdb_backup.sql

Test Your Knowledge
What are the main differences between MySQL and PostgreSQL?
MySQL is simpler, faster for read-heavy workloads, and has better replication. PostgreSQL offers advanced features, better compliance with SQL standards, complex data types, and superior handling of concurrent writes and complex queries.
What is the purpose of database normalization?
Database normalization reduces data redundancy, prevents update anomalies, saves storage space, and ensures data consistency by organizing data into properly structured tables with defined relationships.
How do you secure a database server?
Remove default accounts, use strong passwords, enable SSL/TLS, configure firewalls, apply principle of least privilege, keep software updated, monitor access logs, and disable unnecessary features.
What are the different types of database backups?
Full backups (complete database), incremental backups (changes since last backup), differential backups (changes since last full backup), and logical backups (SQL commands) vs physical backups (file copies).
What is a database transaction and ACID properties?
A transaction is a logical unit of work. ACID properties ensure: Atomicity (all or nothing), Consistency (valid state), Isolation (concurrent transactions don't interfere), Durability (committed changes persist).
How do you troubleshoot database performance issues?
Monitor query execution times, analyze slow query logs, check resource utilization (CPU, memory, I/O), optimize queries and indexes, review database configuration, and monitor connection pools.

Lab 22: Container Integration
Lab Theory
What is this lab about?
This lab focuses on advanced container integration within Linux systems, building upon basic Docker knowledge to cover container networking, persistent storage, system integration, monitoring, and production deployment strategies. You'll learn how containers interact with the host system and other services.
What will you learn?
- Advanced Docker container management and lifecycle operations.
- Container networking modes and custom network configuration.
- Volume management for persistent data and host integration.
- Integration with systemd services and system startup.
- Container monitoring, logging, and health checks.
- Multi-container applications and service orchestration basics.
Process Flow
- Container Setup: Install and configure Docker with advanced settings.
- Networking: Configure custom networks and inter-container communication.
- Storage: Implement persistent volumes and bind mounts.
- Integration: Create systemd services for container management.
- Monitoring: Set up container health monitoring and logging.
- Orchestration: Deploy multi-container applications.


Practice


Verify Docker installation and version.
SOLUTION:
docker --version
Display Docker system information.
SOLUTION:
docker system info
Create a custom Docker network.
SOLUTION:
docker network create --driver bridge myapp-network
List all Docker networks.
SOLUTION:
docker network ls


Create a named Docker volume.
SOLUTION:
docker volume create myapp-data


List all Docker volumes.
SOLUTION:
docker volume ls
Run a database container with volume and network.
SOLUTION:
docker run -d --name myapp-db --network myapp-network -v myapp-data:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=rootpass -e MYSQL_DATABASE=appdb mysql:8.0
Create a simple web application container.
SOLUTION:
docker run -d --name myapp-web --network myapp-network -p 8080:80 -v $(pwd)/html:/usr/share/nginx/html nginx:alpine
Create HTML content for the web app.
SOLUTION:

mkdir -p html && echo "<html><body><h1>My Containerized App</h1><p>Running on Docker with custom network!</p></body></html>" > html/index.html
Test web application accessibility.
SOLUTION:
curl -s http://localhost:8080 | grep -o "My Containerized App"

Check container logs.
SOLUTION:
docker logs myapp-web --tail 10
Execute command inside running container.
SOLUTION:
docker exec myapp-db mysql -uroot -prootpass -e "SHOW DATABASES;"
Monitor container resource usage.
SOLUTION:
docker stats --no-stream



Create a Dockerfile for custom application.
SOLUTION:
cat > Dockerfile << EOF
FROM node:alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --only=production
COPY . .
EXPOSE 3000
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:3000/health || exit 1
CMD ["npm", "start"]
EOF



Create a simple Node.js application files.
SOLUTION:
cat > package.json << EOF
{
  "name": "myapp",
  "version": "1.0.0",
  "main": "app.js",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "express": "^4.18.0"
  }
}
EOF

cat > app.js << EOF
const express = require("express");
const app = express();

app.get("/", (req, res) => {
  res.json({ message: "Hello from containerized Node.js app!", timestamp: new Date() });
});

app.get("/health", (req, res) => {
  res.status(200).json({ status: "healthy" });
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
EOF

Build custom Docker image.
SOLUTION:
docker build -t myapp:v1.0 .
Run the custom application container.
SOLUTION:
docker run -d --name myapp-api --network myapp-network -p 3000:3000 myapp:v1.0


Test the custom application health check.
SOLUTION:
curl -s http://localhost:3000/health | grep healthy

Create a Docker Compose file.
SOLUTION:
cat > docker-compose.yml << EOF
version: "3.8"
services:
  web:
    build: .
    ports:
      - "3000:3000"
    depends_on:
      - db
    environment:
      - DB_HOST=db
      - DB_NAME=appdb
    networks:
      - app-network

  db:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=rootpass
      - MYSQL_DATABASE=appdb
    volumes:
      - db-data:/var/lib/mysql
    networks:
      - app-network

volumes:
  db-data:

networks:
  app-network:
EOF

Create systemd service for Docker container.
SOLUTION:
sudo tee /etc/systemd/system/myapp-container.service > /dev/null << EOF
[Unit]
Description=My Application Container
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/docker start myapp-api
ExecStop=/usr/bin/docker stop myapp-api
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

Enable the container systemd service.
SOLUTION:
sudo systemctl daemon-reload && sudo systemctl enable myapp-container.service


Inspect Docker network configuration.
SOLUTION:
docker network inspect myapp-network
View container processes from host.
SOLUTION:
docker top myapp-web

Clean up unused Docker resources.
SOLUTION:
docker system prune -f

Test Your Knowledge


What are the different Docker networking modes and when would you use each?
Bridge (default, isolated networks), Host (container uses host network), None (no networking), Container (share another container's network), and Custom networks (user-defined bridges for better isolation and DNS).
What is the difference between Docker volumes and bind mounts?
Volumes are managed by Docker, stored in Docker's directory, and provide better portability. Bind mounts directly map host directories to containers, offering more control but less portability.
How do you ensure container security in production?
Use non-root users, minimal base images, scan for vulnerabilities, limit resource usage, use read-only filesystems, implement secrets management, and apply security policies with tools like AppArmor or SELinux.
What are the benefits of using multi-stage Docker builds?
Multi-stage builds reduce final image size by separating build dependencies from runtime, improve security by excluding build tools, enable better caching, and create more efficient CI/CD pipelines.
How do you monitor container performance and health?
Use docker stats, implement health checks in Dockerfiles, monitor with tools like cAdvisor, Prometheus, or Grafana, check logs with docker logs, and use orchestration platform monitoring features.
What is container orchestration and why is it important?
Container orchestration automates deployment, scaling, networking, and management of containerized applications across multiple hosts, providing high availability, load balancing, service discovery, and simplified operations.
Lab 23: System Hardening
Lab Theory
What is this lab about?
This lab focuses on comprehensive Linux system hardening techniques to secure systems against threats and ensure compliance with security frameworks. You'll learn to implement defense-in-depth strategies, configure security tools, and establish monitoring for enterprise security requirements.
What will you learn?
- Firewall configuration with iptables and firewalld.
- User access control and privilege management.
- File system security and access controls.
- Audit logging and security monitoring setup.
- Network security and service hardening.
- Compliance with security frameworks like CIS benchmarks.
Process Flow
- Assessment: Evaluate current security posture and vulnerabilities.
- Firewall: Configure network-level security with firewalls.
- Access Control: Implement strict user and file permissions.
- Monitoring: Set up audit logging and intrusion detection.
- Services: Harden running services and disable unnecessary ones.
- Validation: Test security configurations and compliance.


Practice

Check current firewall status.
SOLUTION:
sudo ufw status || sudo firewall-cmd --state || sudo iptables -L
Enable and configure UFW firewall.
SOLUTION:
sudo ufw enable && sudo ufw default deny incoming && sudo ufw default allow outgoing
Allow SSH through the firewall.
SOLUTION:
sudo ufw allow ssh
Allow specific ports for web services.
SOLUTION:
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
Check listening ports and services.
SOLUTION:
sudo netstat -tulpn || sudo ss -tulpn
root@0563d9cd62a5f130:~# sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
Rule added
Rule added (v6)
Rule added
Rule added (v6)
root@0563d9cd62a5f130:~# sudo netstat -tulpn || sudo ss -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1899/mysqld         
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      11649/systemd-resol 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      899/sshd: /usr/sbin 
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      4340/postgres       
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      1899/mysqld         
tcp6       0      0 :::22                   :::*                    LISTEN      899/sshd: /usr/sbin 
udp        0      0 127.0.0.53:53           0.0.0.0:*                           11649/systemd-resol 
Disable unnecessary services.
SOLUTION:
sudo systemctl list-unit-files | grep enabled | head -5 && echo "Review and disable unnecessary services with: sudo systemctl disable <service>"
Configure password policy.
SOLUTION:
sudo apt-get install libpam-pwquality -y && echo "password requisite pam_pwquality.so retry=3 minlen=8 difok=3" | sudo tee -a /etc/pam.d/common-password
Set password aging policy.
SOLUTION:
sudo sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/" /etc/login.defs && sudo sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/" /etc/login.defs
Install and configure fail2ban.
SOLUTION:
sudo apt-get install fail2ban -y && sudo systemctl enable fail2ban && sudo systemctl start fail2ban


Configure fail2ban for SSH protection.
SOLUTION:
sudo tee /etc/fail2ban/jail.local > /dev/null << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF


Install and configure auditd.
SOLUTION:
sudo apt-get install auditd -y && sudo systemctl enable auditd && sudo systemctl start auditd


Configure audit rules for file monitoring.
SOLUTION:
echo "-w /etc/passwd -p wa -k passwd_changes" | sudo tee -a /etc/audit/rules.d/audit.rules && echo "-w /etc/shadow -p wa -k shadow_changes" | sudo tee -a /etc/audit/rules.d/audit.rules
Secure shared memory.
SOLUTION:
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" | sudo tee -a /etc/fstab


Configure kernel parameters for security.
SOLUTION:
sudo tee /etc/sysctl.d/99-security.conf > /dev/null << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
# Log Martians
net.ipv4.conf.all.log_martians = 1
# Enable syn cookies
net.ipv4.tcp_syncookies = 1
EOF

Apply kernel security settings.
SOLUTION:
sudo sysctl -p /etc/sysctl.d/99-security.conf

Secure file permissions for important files.
SOLUTION:
sudo chmod 600 /etc/shadow && sudo chmod 644 /etc/passwd && sudo chmod 400 /boot/grub/grub.cfg 2>/dev/null || echo "GRUB config not found"

Find and secure SUID/SGID files.
SOLUTION:
find /usr -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; | head -5 && echo "Review these SUID/SGID files for necessity"
Configure automatic security updates.
SOLUTION:
sudo apt-get install unattended-upgrades -y && echo 'APT::Periodic::Update-Package-Lists "1";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades && echo 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades


Setup log monitoring.
SOLUTION:
sudo apt-get install logwatch -y 2>/dev/null || echo "Install logwatch for log monitoring: apt-get install logwatch"
Check for rootkits and malware.
SOLUTION:
sudo apt-get install rkhunter chkrootkit -y 2>/dev/null && echo "Run: sudo rkhunter --update && sudo rkhunter --check" || echo "Install rkhunter and chkrootkit for security scanning"

Configure SSH hardening.
SOLUTION:
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup && sudo sed -i "s/#PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config && sudo sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
Test SSH configuration.
SOLUTION:
sudo sshd -t && echo "SSH configuration is valid"
Check system for security compliance.
SOLUTION:
sudo lynis audit system --quick || echo "Install lynis for security auditing: apt-get install lynis"


Review security status summary.
SOLUTION:

echo "=== Security Hardening Summary ==="; echo "Firewall: $(sudo ufw status | grep -o Status:.*)"; echo "Fail2ban: $(sudo systemctl is-active fail2ban)"; echo "Audit: $(sudo systemctl is-active auditd)"; echo "Last login attempts: $(sudo tail -5 /var/log/auth.log | grep -i "authentication failure" | wc -l) recent failures"

Test Your Knowledge
What is the principle of least privilege and how do you implement it in Linux?
Least privilege means granting only the minimum access rights needed for users/processes to perform their functions. Implement through proper user/group management, sudo configuration, file permissions, and service account restrictions.


What are the key differences between iptables and firewalld?
iptables is a low-level netfilter interface requiring manual rule management. firewalld is a higher-level dynamic firewall with zones, services, and runtime/permanent configurations, making it easier to manage complex firewall rules.
How does Linux audit system (auditd) help with security?
Auditd provides detailed logging of system events including file access, process execution, network connections, and user activities. It helps with compliance, forensics, intrusion detection, and monitoring privilege escalation attempts.
What is SELinux and how does it enhance security?
SELinux (Security-Enhanced Linux) is a mandatory access control system that enforces policies beyond traditional permissions. It provides fine-grained control over process capabilities and file access, preventing privilege escalation and containing breaches.
How do you secure SSH access to a Linux server?
Disable root login, use key-based authentication, change default port, implement fail2ban, configure AllowUsers/Groups, disable password authentication, use strong ciphers, and implement connection rate limiting.
What are some key indicators of a compromised Linux system?
Unusual network traffic, unexpected processes, modified system files, new user accounts, suspicious log entries, performance degradation, unknown cron jobs, and unauthorized file modifications.









Lab 24: Performance Tuning
Lab Theory
What is this lab about?
This lab focuses on comprehensive Linux performance tuning and optimization techniques for enterprise environments. You'll learn to identify performance bottlenecks, optimize system resources, tune kernel parameters, and implement monitoring solutions for sustained high performance.
What will you learn?
- Advanced system monitoring and performance analysis tools.
- CPU, memory, disk, and network performance optimization.
- Kernel parameter tuning for specific workloads.
- Process scheduling and priority management.
- I/O optimization and storage performance tuning.
- Performance monitoring automation and alerting systems.
Process Flow
- Baseline: Establish performance baselines and identify bottlenecks.
- Analysis: Use profiling tools to understand resource utilization.
- Optimization: Apply kernel tuning and system-level optimizations.
- Monitoring: Implement continuous performance monitoring.
- Validation: Measure improvements and validate optimizations.
- Automation: Set up automated performance monitoring and alerting.


Practice

Monitor real-time system resources.
SOLUTION:
top -n 1
Check memory usage details.
SOLUTION:
free -h
Analyze disk I/O statistics.
SOLUTION:
iostat -x 1 3
Monitor virtual memory statistics.
SOLUTION:
vmstat 1 5


Check network interface statistics.
SOLUTION:
sar -n DEV 1 3
List processes by CPU usage.
SOLUTION:
ps aux --sort=-%cpu | head -10
List processes by memory usage.
SOLUTION:
ps aux --sort=-%mem | head -10
Check file descriptor usage.
SOLUTION:
lsof | wc -l && echo "Current open files" && cat /proc/sys/fs/file-max && echo "Maximum file descriptors"
Monitor system calls for a process.
SOLUTION:
strace -c -p $$ 2>&1 | head -10 || echo "Run strace -c -p PID to monitor system calls for a specific process"
Check current I/O scheduler.
SOLUTION:
cat /sys/block/*/queue/scheduler | head -3
Tune kernel parameters for performance.
SOLUTION:
sudo tee /etc/sysctl.d/99-performance.conf > /dev/null << EOF
# Increase file descriptor limits
fs.file-max = 2097152
# Optimize network performance
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
# Virtual memory tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

Apply performance kernel settings.
SOLUTION:
sudo sysctl -p /etc/sysctl.d/99-performance.conf


Check current swappiness setting.
SOLUTION:
cat /proc/sys/vm/swappiness
Create a CPU stress test.
SOLUTION:
timeout 10 yes > /dev/null &
Monitor CPU usage during stress test.
SOLUTION:
sleep 2 && top -n 1 | grep -E "(Cpu|%CPU)" | head -5


Check process nice values and priorities.
SOLUTION:
ps axo pid,comm,nice,pri | head -10
Change process priority using nice.
SOLUTION:
nice -n 10 sleep 300 & echo "Started sleep with nice value 10, PID: $!"
Monitor disk usage and find large files.
SOLUTION:
du -sh /* 2>/dev/null | sort -hr | head -5


Check filesystem inode usage.
SOLUTION:
df -i


Create performance monitoring script.
SOLUTION:
cat > /tmp/performance_monitor.sh << EOF
#!/bin/bash
echo "=== System Performance Report ==="
echo "Date: $(date)"
echo "Uptime: $(uptime)"
echo ""
echo "=== CPU Usage ==="
top -bn1 | grep "Cpu(s)" | awk "{print \$2 \$3 \$4 \$5}"
echo ""
echo "=== Memory Usage ==="
free -h
echo ""
echo "=== Disk Usage ==="
df -h / | tail -1
echo ""
echo "=== Top 5 CPU Processes ==="
ps aux --sort=-%cpu | head -6
EOF
chmod +x /tmp/performance_monitor.sh
Run the performance monitoring script.
SOLUTION:
/tmp/performance_monitor.sh
Set up system resource limits.
SOLUTION:
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf && echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
Check network buffer sizes.
SOLUTION:
sysctl net.core.rmem_default net.core.wmem_default net.core.rmem_max net.core.wmem_max
Profile system performance with perf.
SOLUTION:
which perf >/dev/null && sudo perf stat sleep 1 || echo "Install perf tools: apt-get install linux-tools-common linux-tools-generic"
Check interrupt distribution across CPUs.
SOLUTION:
cat /proc/interrupts | head -10
Monitor context switches.
SOLUTION:
vmstat 1 3 | awk "NR>2 {print \"Context switches: \" \$12}"
Create system performance baseline.
SOLUTION:
echo "=== Performance Baseline $(date) ===" > /tmp/baseline.txt && echo "Load: $(uptime | awk -F"load average:" "{print \$2}")" >> /tmp/baseline.txt && echo "Memory: $(free | grep Mem: | awk "{printf \"%.1f%%\", \$3/\$2 * 100.0}")" >> /tmp/baseline.txt && echo "Disk: $(df -h / | tail -1 | awk "{print \$5}")" >> /tmp/baseline.txt && cat /tmp/baseline.txt


Test Your Knowledge
What are the main system resources you monitor for performance issues?
CPU utilization, memory usage (RAM and swap), disk I/O (IOPS, throughput, latency), network throughput and latency, and system load averages. Each can become a bottleneck affecting overall system performance.
How do you identify if a system is CPU-bound, I/O-bound, or memory-bound?
CPU-bound: high CPU usage with low I/O wait. I/O-bound: high I/O wait times with moderate CPU. Memory-bound: high memory usage, swapping activity, and page faults. Use tools like top, iostat, and vmstat to analyze.
What is the difference between load average and CPU utilization?
Load average shows the average system load over time (processes ready to run + running + waiting for I/O). CPU utilization shows the percentage of time CPU is busy. High load with low CPU utilization often indicates I/O bottlenecks.
How do you optimize disk I/O performance in Linux?
Choose appropriate I/O schedulers, optimize filesystem choices, tune read-ahead settings, configure proper RAID levels, use SSDs for high-IOPS workloads, and implement proper partitioning and alignment.
What kernel parameters commonly need tuning for performance?
vm.swappiness for memory management, net.core parameters for networking, I/O scheduler settings, TCP buffer sizes, file descriptor limits, and process scheduling parameters depending on workload characteristics.
How do you monitor performance continuously in production?
Use monitoring tools like Prometheus, Grafana, Nagios, or Zabbix. Implement automated alerting, establish baseline metrics, set up log aggregation, and create performance dashboards for proactive monitoring.





Citation Reference Links:

https://linux-commands.labex.io/- 400+ linux commands how to use
https://makelinux.github.io/kernel/map/ - Linux kernel architecture map and inter linkage to programs.
https://labex.io/labs/ - Practice real time from browser directly
https://www.redhat.com/en/interactive-labs - practice labs virtually

