# Welcome to my repo 

### The contents of this repo are:
* All the courses in one PDF
* All extra readings one PDF
* A cheatsheet
* A theory synthesis
* 2 books for starting with UNIX
* A link for MCQ practice
* A link for bourne shell scripting
* A whole compleet detailed list chaptered with all commands syntax, frequently specifiers and what they do, example and general short theory about the command
#### I have made a website where you can self test and prepare for Mr Professor Zota's exam using his previous year's MCQs, he is a great person and I love both him and Clim they are the best
## Link is: [MCQ TEST ZOTA](https://firedmosquito831.github.io/OS-Year1-Sem2/)


## Bourne scripting tutorial:
#### [Bourne shell scripting tutorial online](https://zota.ase.ro/os/so_000.html)

# EXTRA THEORY
Useful stuff for OS year 1 sem 2


# Linux Command Reference Guide  
## Categories 1–20 (Based on Your Pasted File)

---

### 1. Directory Management

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| ls | Lists files and directories in the current or specified directory | -l : Long listing format<br>-a : Show hidden files<br>-h : Human-readable file sizes<br>-R : Recursively list subdirectories<br>-t : Sort by modification time<br>-S : Sort by file size | `ls -alh` | N/A (non-destructive command) | You can combine options, e.g., `ls -lh` |
| pwd | Prints the current working directory | (No major specifiers, simple command) | `pwd` | N/A (informational command) | Helpful for scripting when absolute paths are needed |
| cd | Changes the current working directory | (No direct specifiers; path is argument) | `cd /home/user` | N/A (navigation only) | Use `cd ..` to go up one directory level |
| cp | Copies files and directories | -r : Copy directories recursively<br>-i : Prompt before overwrite<br>-u : Copy only when source is newer<br>-v : Verbose output<br>-p : Preserve file attributes<br>-a : Archive mode (preserve all) | `cp -r ~/Documents ~/Backup` | Manually remove the copied files or directory using `rm -r [destination]` | Use `-a` for backups to preserve file metadata |
| mv | Moves or renames files and directories | -i : Prompt before overwrite<br>-v : Verbose output<br>-f : Force move without prompt | `mv oldname.txt newname.txt` | Move back manually if needed | Can be used to rename files as well |
| rm | Removes files or directories | -r : Remove directories recursively<br>-f : Force deletion without prompt<br>-i : Prompt before deletion | `rm -rf temp_folder` | Recovery may be difficult; use carefully | Be cautious with `-rf`, especially as root |
| mkdir | Creates new directories | -p : Create parent directories as needed<br>-m : Set permissions<br>-v : Verbose output | `mkdir -p project/{src,bin}` | Manually delete using `rm -r` | Useful for creating nested directory structures |
| rmdir | Removes empty directories | -p : Remove parent directories if also empty<br>-v : Verbose output | `rmdir temp_dir` | Re-create the directory manually | Only works on empty directories |

---

### 2. Text Processing

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| cat | Concatenates and displays file content | -n : Number all output lines<br>-b : Number non-blank output lines<br>-s : Squeeze multiple blank lines into one<br>-T : Show tabs as ^I<br>-v : Display control characters<br>-A : Show all (including line endings) | `cat -n notes.txt` | N/A (read-only operation) | Can combine multiple files using redirection (`cat file1 file2 > combined.txt`) |
| head | Displays the first few lines of a file | -n N : Output the first N lines<br>-c N : Output the first N bytes<br>-q : Never print headers<br>-v : Always print headers | `head -n 10 logfile.log` | N/A (display-only command) | Useful for previewing large files or checking logs quickly |
| tail | Displays the last few lines of a file | -n N : Output the last N lines<br>-f : Follow file as it grows<br>-c N : Output the last N bytes<br>-q : Suppress headers<br>-v : Always output headers | `tail -f /var/log/syslog` | N/A (display-only command) | Commonly used with `-f` to monitor log files live |
| grep | Searches for patterns in files using regular expressions | -i : Ignore case<br>-v : Invert match (show non-matching lines)<br>-r : Recursive search<br>-n : Show line numbers<br>-l : List filenames only<br>-c : Count matching lines | `grep -i "error" server.log` | Use `grep -v` to find lines that don't match a pattern | Extremely fast and works well with pipes; supports regex |
| sed | Stream editor for modifying file contents on the fly | -i : Edit files in place<br>-e : Add multiple commands<br>-n : Suppress automatic printing<br>-r : Use extended regex<br>-f : Read commands from a file | `sed -i 's/apple/orange/g' fruits.txt` | Undo changes manually or revert from backup | Powerful for batch text editing, especially in scripts |
| awk | Pattern scanning and processing language | -F fs : Set field separator<br>-v var=value : Assign variable before execution<br>'{print $1}' : Print specific columns<br>NR == n : Process specific record number | `awk '{print $1}' data.csv` | N/A (text parsing tool) | Great for column-based data manipulation and extraction |
| less | View file content page by page | -N : Show line numbers<br>-S : Disable line wrapping<br>-i : Ignore case in searches<br>-X : Do not clear screen after exit<br>+G : Start at end of file | `less -N server.log` | N/A (read-only viewer) | Supports backward/forward navigation and searching with `/` |
| more | View file content page by page (older tool) | -d : Prompt before scrolling<br>-f : Count logical lines<br>-p : Clear screen then display page<br>-s : Squeeze blank lines<br>-u : Suppress underlining<br>+n : Start at line n | `more +20 notes.txt` | N/A (read-only viewer) | Older than `less`, but still found on minimal systems |
| cut | Removes sections from each line of files | -d : Delimiter<br>-f : Fields to extract<br>-c : Characters to extract<br>--complement : Exclude selected fields | `cut -d',' -f1 data.csv` | N/A (text extraction utility) | Good for slicing out specific columns from structured text |
| sort | Sorts lines of text files | -n : Numeric sort<br>-r : Reverse order<br>-k : Sort by key/column<br>-u : Unique entries only<br>-t : Field delimiter | `sort -nr scores.txt` | Re-sort with opposite flags if needed | Used frequently with pipelines to organize output |
| uniq | Reports or omits repeated lines | -c : Prefix lines by count<br>-d : Only print duplicate lines<br>-u : Only print unique lines<br>-i : Ignore case | `uniq -c names.txt` | N/A (analysis tool) | Works best when input is already sorted; often paired with `sort` |
| paste | Merges lines of files | -d : Delimiter<br>-s : Serial concatenation<br>--delimiters= : Specify delimiters | `paste file1.txt file2.txt` | N/A (file merging utility) | Opposite of `cut`; useful for combining parallel outputs |
| join | Joins lines of two files on a common field | -1 FIELD : Join on this field from file 1<br>-2 FIELD : Join on this field from file 2<br>-t CHAR : Field separator | `join -1 2 -2 1 file1 file2` | N/A (data joining utility) | Similar to SQL JOINs; works best with sorted input |

---

### 3. Process Management

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| ps | Displays information about active processes | -e : Show all processes<br>-f : Full-format listing<br>-u user : Filter by user | `ps -ef` | N/A (snapshot only) | Often used with `grep` to filter specific processes |
| top | Displays real-time system info and running processes | -u user : Show processes for a user<br>-p pid : Monitor specific PID<br>-d secs : Delay between updates | `top` | Exit with `q` | Interactive: Press `k` to kill a process directly from interface |
| htop | Enhanced interactive process viewer | -u user : Show processes for a user<br>-p pid : Monitor specific PID<br>-d delay : Set update interval | `htop` | Exit with `F10` or `q` | Supports mouse navigation and color-coded resource usage |
| kill | Sends signals to processes (usually to terminate) | -9 : Force kill (SIGKILL)<br>-15 : Graceful termination (SIGTERM)<br>-l : List available signals | `kill 1234` | Restart process manually if needed | Use `kill -9` for unresponsive processes |
| pkill | Kills processes by name or other attributes | -f : Match full command line<br>-u user : Kill processes of a user<br>-n : Most recently started process<br>-o : Oldest process | `pkill firefox` | Restart process manually if needed | More flexible than `killall`; supports pattern matching |
| killall | Kills processes by name | -v : Verbose output<br>-i : Ask for confirmation before killing<br>-s : Send specific signal | `killall httpd` | Restart service or app manually | Works differently on Solaris vs Linux; ensure compatibility |
| bg | Resumes a suspended job in the background | %jobid : Resume a specific job | `bg %1` | Bring back to foreground with `fg %1` | Useful after suspending a process with `Ctrl+Z` |
| fg | Brings a background job to the foreground | %jobid : Bring specific job to front | `fg %1` | Send back to background with `bg %1` | Only one job can be in the foreground at a time |
| jobs | Lists active background jobs | -l : Show PIDs<br>-n : Show status-changed jobs only<br>-p : Show only PIDs | `jobs` | N/A (informational) | Helps manage multiple running background tasks |
| nice | Runs a command with adjusted scheduling priority | -n value : Set niceness (-20 to 19) | `nice -n 10 ./heavy_script.sh` | Rerun with different priority if needed | Lower values mean higher priority; default is 0 |
| renice | Changes priority of a running process | -n value : Adjust niceness<br>-p PID : Target process ID | `renice 15 -p 1234` | Reset to previous value if known | Can be used to adjust performance impact of long-running tasks |
| uptime | Shows how long the system has been running | No major specifiers | `uptime` | N/A (informational) | Also shows load averages and number of users |

---

### 4. Network Management

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| ping | Tests network connectivity to a host | -c N : Send N packets<br>-i N : Interval between packets (seconds)<br>-s N : Packet size | `ping -c 4 google.com` | N/A (diagnostic tool) | Basic tool to check if a host is reachable |
| traceroute | Shows the route packets take to reach a host | -n : Display IP addresses only<br>-w N : Time to wait for response<br>-m N : Maximum number of hops | `traceroute google.com` | N/A (diagnostic tool) | Useful for identifying routing issues or bottlenecks |
| netstat | Displays network connections, routing tables, and interface statistics | -t : TCP connections<br>-u : UDP connections<br>-n : No DNS lookup<br>-l : Listening ports<br>-p : Show PID and name<br>-a : All connections | `netstat -tulnp` | N/A (diagnostic tool) | Deprecated in favor of `ss`, but still widely used |
| ss | Investigates sockets (like netstat) | -t : TCP connections<br>-u : UDP connections<br>-n : No DNS lookup<br>-l : Listening ports<br>-p : Show process info<br>-a : All sockets | `ss -tulnp` | N/A (diagnostic tool) | Faster and more modern than `netstat` |
| ifconfig | Configures and displays network interfaces | up/down : Enable/disable interface<br>add/del : Add/remove IP address<br>netmask : Set subnet mask<br>broadcast : Set broadcast address | `ifconfig eth0 up` | Reverse configuration manually (e.g., `ifconfig eth0 down`) | Considered deprecated; use `ip` command instead |
| ip | Manages network interfaces, routes, tunnels, etc. | addr : Manage IP addresses<br>link : Manage interfaces<br>route : Manage routing table<br>neigh : ARP table management | `ip addr show`<br>`ip link set eth0 up` | Use inverse commands like `ip link set eth0 down` | Modern replacement for `ifconfig`; supports IPv6 |
| arp | Manages Address Resolution Protocol cache | -a : Show all entries<br>-d : Delete entry<br>-s : Add static entry | `arp -a` | Remove with `arp -d [host]` | Used to view or manipulate MAC address mappings |
| hostname | Shows or sets the system's hostname | (No major specifiers; pass new hostname as argument) | `hostname myserver` | Change back to original hostname manually | Hostname resets on reboot unless saved in config file |
| nslookup | Queries DNS servers to look up domain information | -type=mx : Lookup MX records<br>-type=ns : Lookup NS records<br>@server : Query specific DNS server | `nslookup google.com` | N/A (DNS lookup tool) | Can be replaced by `dig` or `host` |
| dig | Flexible DNS lookup utility | +short : Compact output<br>+trace : Trace DNS delegation path<br>@server : Query specific DNS server | `dig A google.com` | N/A (DNS lookup tool) | More powerful and flexible than `nslookup` |
| curl | Transfers data from or to a server using URLs | -X : Request method (GET/POST/etc.)<br>-H : Add header<br>-d : Data to POST<br>--insecure : Allow insecure SSL/TLS connections<br>-o : Save output to file | `curl -O https://example.com/file.txt` | Depends on what was transferred or posted | Supports many protocols including HTTP, FTP, SFTP |
| wget | Retrieves content from web servers | -c : Resume interrupted download<br>-O : Output filename<br>-r : Recursive download<br>--limit-rate : Throttle speed<br>--no-check-certificate : Ignore SSL errors | `wget https://example.com/file.zip` | Delete downloaded file manually if needed | Great for downloading files non-interactively |
| ssh | Securely connects to remote hosts | -p : Custom port<br>-i : Identity file (private key)<br>-L : Local port forwarding<br>-R : Remote port forwarding<br>-N : Do not execute remote command | `ssh user@remote_host` | Exit session with `exit` or Ctrl+D | Uses public-key cryptography for authentication |
| scp | Securely copies files between hosts | -P : Port number<br>-i : Identity file<br>-r : Recursively copy directories | `scp file.txt user@remote:/path/` | Copy back from remote host if needed | Based on SSH protocol; secure alternative to rcp |
| sftp | Interactive secure file transfer over SSH | get/put : Download/upload files<br>ls/lls : List remote/local directory<br>cd/lcd : Change remote/local dir<br>mkdir/rmdir : Create/delete dirs | `sftp user@remote` | Upload/delete files accordingly | Safer than regular FTP; uses encryption |
| tcpdump | Captures and analyzes network traffic | -i INTERFACE : Interface to capture on<br>-w FILE : Write to file<br>-r FILE : Read from file<br>-nn : Don’t resolve names<br>-v : Verbosity level | `tcpdump -i eth0 -w capture.pcap` | Analyze capture later or stop capture | Powerful packet analyzer for troubleshooting |
| nmap | Scans networks and discovers hosts and services | (No major specifiers listed) | `nmap google.com` | Avoid scanning unauthorized networks | Often used for security auditing and mapping |
| iptables | Administers firewall rules | -A : Append rule<br>-D : Delete rule<br>-I : Insert rule<br>-L : List rules<br>-F : Flush rules<br>-j : Jump target (ACCEPT/DROP/REJECT) | `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` | Reverse by deleting or modifying rules | Low-level firewall control; consider `ufw` for simplicity |
| ufw | Uncomplicated Firewall (frontend for iptables) | allow/deny : Permit/block traffic<br>status : Show current status<br>enable/disable : Toggle firewall<br>delete : Remove a rule | `ufw allow OpenSSH` | Disable or remove rules as needed | Easier-to-use firewall manager for Ubuntu/Debian systems |

---

### 5. Disk Management

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| df | Displays disk space usage for mounted filesystems | -h : Human-readable sizes<br>-T : Show filesystem type<br>-i : Show inode usage<br>--total : Display total usage at the end | `df -h` | N/A (informational command) | Useful for checking available disk space and mounted devices |
| du | Shows the size of directories and files | -h : Human-readable sizes<br>-s : Summary only<br>-c : Total at the end<br>--max-depth=N : Limit directory depth | `du -sh /home/user` | N/A (read-only operation) | Helps identify large directories consuming disk space |
| fdisk | Manages disk partitions (MBR style) | -l : List all partitions<br>-u : Show sizes in sectors<br>-b : Specify sector size | `sudo fdisk -l` | Use inverse operations within interactive mode to delete or resize partitions | Older tool; use `parted` or `gdisk` for GPT disks |
| parted | Manages disk partitions (supports MBR and GPT) | mklabel : Create partition table<br>print : Display partition info<br>mkpart : Create a new partition | `sudo parted /dev/sda print` | Undo with reverse commands inside parted | More modern than `fdisk`, supports larger disks and GPT |
| lsblk | Lists block devices (disks and partitions) | -f : Show filesystem info<br>-o : Customize output columns | `lsblk -f` | N/A (informational command) | Great for quickly viewing disk layout and mount points |
| blkid | Displays block device attributes | -s : Show specific tag<br>--match-tag : Limit to certain tags | `blkid /dev/sdb1` | N/A (read-only command) | Used often in scripts to get UUIDs or verify filesystem types |
| mount | Mounts a filesystem to a directory | -t : Filesystem type<br>-o : Mount options<br>--bind : Bind mount a directory<br>--remount : Remount an already mounted filesystem | `mount /dev/sdb1 /mnt/usb` | Unmount with `umount /mnt/usb` | Essential for mounting external drives, ISOs, or shares |
| umount | Unmounts a mounted filesystem | -l : Lazy unmount (detach after use)<br>-f : Force unmount | `umount /mnt/usb` | Remount using `mount` again | Always unmount before removing hardware to prevent data loss |
| mkfs | Creates a filesystem on a partition | -t : Filesystem type<br>-L : Set volume label | `mkfs -t ext4 /dev/sdb1` | Formatting is irreversible — requires reformatting or recovery tools | Must be used carefully; erases all data on target device |
| tune2fs | Adjusts ext2/ext3/ext4 filesystem parameters | -l : Show filesystem info<br>-c : Max mount count<br>-i : Interval between checks<br>-L : Change volume label | `tune2fs -l /dev/sda1` | Most changes can be reverted using same command with previous values | Advanced users can optimize performance or enable features |
| fsck | Checks and repairs filesystems | -t : Specify filesystem type<br>-r : Interactive repair<br>-y : Assume yes to prompts<br>-n : Assume no to prompts | `fsck /dev/sdb1` | Repairs may not recover all data; backups recommended | Should be run when filesystem is unmounted or during boot |

---

### 6. User and Group Management

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| useradd | Adds a new user to the system | -m : Create home directory<br>-d : Specify home directory<br>-s : Set login shell<br>-g : Primary group<br>-G : Supplementary groups<br>-u : UID<br>-p : Encrypted password | `sudo useradd -m john` | Remove user with `userdel john` | Creates user account and related files in `/etc/passwd`, `/etc/shadow`, etc. |
| usermod | Modifies user account settings | -l : Change username<br>-d : Change home directory<br>-s : Change login shell<br>-aG : Add to supplementary groups<br>-g : Change primary group<br>-L : Lock account<br>-U : Unlock account | `sudo usermod -aG sudo john` | Reverse changes using same command with original values | Useful for updating user info without deleting/recreating |
| userdel | Deletes a user account | -r : Remove home directory and mail spool<br>-f : Force removal of running processes | `sudo userdel -r john` | Recreate user manually if needed | Be cautious with `-r` as it permanently deletes user data |
| passwd | Sets or changes user passwords | -l : Lock account<br>-u : Unlock account<br>-d : Delete password (disable)<br>--stdin : Read password from stdin | `sudo passwd john` | Reset password or unlock with same command | Used interactively or in scripts for automated setups |
| groupadd | Adds a new group to the system | -g : GID<br>-r : Create system group<br>-f : Force; use when GID exists | `sudo groupadd developers` | Remove group with `groupdel developers` | Adds entry to `/etc/group` |
| groupmod | Modifies group settings | -n : Rename group<br>-g : Change GID | `sudo groupmod -n devteam developers` | Reverse renaming or GID change with same command | Useful for maintaining consistent group names/IDs |
| groupdel | Removes a group from the system | (No major specifiers) | `sudo groupdel devteam` | Recreate group manually if needed | Cannot remove group if it's a user’s primary group |
| id | Displays user and group IDs | -u : Show UID only<br>-g : Show GID only<br>-n : Show names instead of numeric IDs<br>-G : Show all group memberships | `id john` | N/A (read-only command) | Helps verify user/group mappings, especially in LDAP environments |
| su | Switches to another user account | - : Start login shell<br>-c : Run single command<br>-l : Same as `-` | `su - root` | Exit with `exit` or Ctrl+D | Commonly used to switch to root or other users temporarily |
| sudo | Executes a command with elevated privileges | -i : Start interactive shell<br>-u : Run as specified user<br>-l : List allowed commands<br>-k : Invalidate timestamp<br>-b : Run in background | `sudo systemctl restart nginx` | Depends on executed command | Requires proper configuration in `/etc/sudoers` |
| whoami | Displays the current effective user name | (No major specifiers) | `whoami` | N/A (informational) | Often used in scripts to check execution context |
| chage | Changes password expiry information | -l : List current settings<br>-M : Max days before password change<br>-m : Min days between changes<br>-W : Warning days<br>-I : Inactive days after expiry<br>-E : Account expiration date | `sudo chage -M 90 john` | Adjust again with `chage` | Enforces password policies and account expiration |
| lastlog | Displays most recent login of all users | -u : Filter by user<br>-b DAYS : Logins older than DAYS<br>-t DAYS : Logins within last DAYS | `lastlog` | N/A (informational) | Reads from `/var/log/lastlog`; useful for auditing |
| groups | Displays the groups a user belongs to | (Pass username as argument) | `groups john` | N/A (informational) | Shows both primary and supplementary group memberships |
| finger | Displays user information | (Pass username as argument) | `finger john` | N/A (informational) | May not be installed by default; can expose sensitive info |
| getent | Gets entries from Name Service Switch libraries | passwd : Show user info<br>group : Show group info<br>hosts : Show host info | `getent passwd john` | N/A (lookup tool) | Works with local files, LDAP, NIS, and other databases |
| adduser | Interactive tool to add a new user (wrapper for useradd) | (Same as useradd but more user-friendly) | `sudo adduser jane` | Remove with `deluser` or `userdel` | Preferred on Debian/Ubuntu systems for its simplicity |
| deluser | Removes a user (Debian/Ubuntu alternative to userdel) | --remove-home : Delete home directory<br>--remove-all-files : Remove all user-owned files | `sudo deluser --remove-home jane` | Recreate user manually if needed | More intuitive than raw `userdel` on some distros |

---

### 7. Security and Encryption

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| chmod | Changes file permissions | -R : Recursive<br>-v : Verbose output | `chmod u+rwx file.txt` | Remove permissions with `chmod u-rwx file.txt` | Permissions can be symbolic or numeric (644, 755) |
| chown | Changes file owner and/or group | -R : Recursive<br>-v : Verbose output | `sudo chown user:group file.txt` | Change back using same command with original owner/group | Must have root privileges to change ownership |
| sudo | Executes a command with elevated privileges | -i : Start interactive shell<br>-u : Run as specified user<br>-l : List allowed commands<br>-k : Invalidate timestamp<br>-b : Run in background | `sudo systemctl restart nginx` | Depends on executed command | Requires proper configuration in `/etc/sudoers` |
| su | Switches to another user account | - : Start login shell<br>-c : Run single command<br>-l : Same as `-` | `su - root` | Exit shell with `exit` or Ctrl+D | Often used to switch to root or other users temporarily |
| passwd | Sets or changes user passwords | -l : Lock account<br>-u : Unlock account<br>-d : Delete password (disable)<br>--stdin : Read password from stdin | `sudo passwd john` | Reset password or unlock with same command | Used interactively or in scripts for automation |
| ssh | Securely connects to remote hosts | -p : Custom port<br>-i : Identity file (private key)<br>-L : Local port forwarding<br>-R : Remote port forwarding<br>-N : Do not execute remote command | `ssh user@remote_host` | Exit session with `exit` or Ctrl+D | Uses public-key cryptography; supports tunnels and X11 forwarding |
| scp | Securely copies files between hosts | -P : Port number<br>-i : Identity file<br>-r : Recursively copy directories | `scp file.txt user@remote:/path/` | Copy back from remote host if needed | Based on SSH protocol; secure alternative to rcp |
| sftp | Interactive secure file transfer over SSH | get/put : Download/upload files<br>ls/lls : List remote/local directory<br>cd/lcd : Change remote/local dir<br>mkdir/rmdir : Create/delete dirs | `sftp user@remote` | Upload/delete files accordingly | Safer than regular FTP; uses encryption |
| iptables | Administers firewall rules | -A : Append rule<br>-D : Delete rule<br>-I : Insert rule<br>-L : List rules<br>-F : Flush rules<br>-j : Jump target (ACCEPT/DROP/REJECT) | `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` | Reverse by deleting or modifying rules | Low-level firewall control; consider `ufw` for simplicity |
| ufw | Uncomplicated Firewall (frontend for iptables) | allow/deny : Permit/block traffic<br>status : Show current status<br>enable/disable : Toggle firewall<br>delete : Remove a rule | `ufw allow OpenSSH` | Disable or remove rules as needed | Easier-to-use firewall manager for Ubuntu/Debian systems |
| fail2ban | Bans IPs after failed login attempts | -x : Stop service<br>-r : Reload config<br>--set jail action ban/unban IP | `fail2ban-client set sshd banip 192.168.1.100` | Manually unban with `fail2ban-client set sshd unbanip` | Helps prevent brute-force attacks on SSH and other services |
| openssl | Toolkit for SSL/TLS protocols | enc : Encrypt/decrypt files<br>genrsa : Generate RSA private key<br>req : Create certificate requests<br>x509 : Self-signed cert generation<br>dgst : Message digest calculation | `openssl enc -aes-256-cbc -in secret.txt -out encrypted.bin` | Decrypt using same command with `-d` flag | Supports many cryptographic operations including signing and hashing |
| gpg | GNU Privacy Guard – encrypting and signing data | -c : Symmetric encryption<br>-e : Encrypt for recipient<br>-d : Decrypt file<br>-s : Sign file<br>--verify : Verify signature<br>--import/export : Manage keys | `gpg -c secret.txt` | Decrypt using `gpg -d secret.txt.gpg` | Used for secure communication, software verification, and file encryption |
| ssh-keygen | Generates, manages, and converts SSH keys | -t : Key type<br>-b : Bits for RSA keys<br>-f : Filename for generated key<br>-N : Passphrase<br>-l : Show fingerprint of existing key | `ssh-keygen -t ed25519 -C "user@example.com"` | Delete key manually; regenerate if needed | Essential for setting up passwordless SSH access |

---

### 8. Monitoring and Troubleshooting

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| top | Displays real-time system information and running processes | -u user : Show only a specific user's processes<br>-p pid : Monitor specific PID<br>-d secs : Delay between updates<br>-n number : Number of updates to show | `top` | Exit with `q` | Interactive: Press `k` to kill a process directly from interface |
| htop | Enhanced interactive process viewer | -u user : Show processes for a user<br>-p pid : Monitor specific PID<br>-d delay : Set update interval | `htop` | Exit with `F10` or `q` | Supports mouse navigation, color coding, and better UI than `top` |
| iotop | Displays I/O usage by processes | -o : Only show processes doing I/O<br>-b : Batch mode<br>-d SEC : Delay between iterations | `iotop` | Exit with `q` | Similar to `top`, but focused on disk I/O activity |
| vmstat | Reports virtual memory statistics | -s : Display memory summary<br>-d : Disk statistics<br>-m : Slab memory info | `vmstat 1 5` | N/A (snapshot or interval-based) | Useful for monitoring system performance and bottlenecks |
| free | Displays amount of free and used memory | -h : Human-readable format<br>-m/g/k : Output in MB/GB/KB<br>-l : Show detailed low/high memory stats | `free -h` | N/A (informational command) | Shows RAM and swap space usage; useful in scripts |
| sar | Collects, reports, or saves system activity information | -u : CPU usage<br>-r : Memory usage<br>-d : Disk I/O<br>-n DEV : Network stats<br>-A : All available reports | `sar -u 1 5` | N/A (system activity reporter) | Part of sysstat package; logs can be saved and analyzed later |
| dmesg | Prints or controls the kernel ring buffer | -T : Show human-readable timestamps<br>--level : Filter log levels<br>-C : Clear ring buffer | `dmesg` | Depends on what was cleared or filtered | Useful for viewing hardware/driver messages and boot logs |
| journalctl | Query systemd journal (system logs) | -b : Boot logs only<br>-u service : Filter by unit<br>--since/--until : Time range<br>-f : Follow live output<br>-x : Add explanatory text | `journalctl -u ssh.service` | Depends on logged events | Centralized logging in modern Linux systems using systemd |
| lastlog | Displays most recent login of all users | -u : Filter by user<br>-b DAYS : Logins older than DAYS<br>-t DAYS : Logins within last DAYS | `lastlog` | N/A (informational) | Reads from `/var/log/lastlog`; useful for auditing |
| last | Shows listing of last logged-in users | -n NUM : Show NUM lines<br>-x : Show system shutdown/reboot events<br>-F : Full date/time format | `last -n 10` | N/A (informational) | Reads from `/var/log/wtmp`; good for historical login tracking |
| logwatch | Analyzes and reports log summaries | --range : Time range (Today, Yesterday, All)<br>--service : Specific service to report on<br>--detail : Level of detail | `logwatch --detail High --service sshd` | N/A (reporting tool) | Useful for daily security monitoring and intrusion detection |

---

### 🗂️ Category 9: File Compression and Archiving

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| tar | Archives multiple files into a single file (tape archive) | -c : Create new archive<br>-x : Extract files<br>-v : Verbose output<br>-f : Specify filename<br>-z : Compress with gzip<br>-j : Compress with bzip2<br>-J : Compress with xz | `tar -czvf archive.tar.gz folder/` | Use `-x` to extract the archive | Commonly used for backups and distributing source code |
| gzip | Compresses files using GZIP format | -d : Decompress<br>-r : Recursively compress directories<br>-l : List compressed file info<br>-k : Keep original file<br>-v : Verbose output | `gzip file.txt` | Decompress with `gzip -d file.txt.gz` or `gunzip file.txt.gz` | Reduces file size significantly; often used with `tar` |
| gunzip | Decompresses GZIP-compressed files | -r : Recursively decompress directories<br>-l : List compressed file info<br>-v : Verbose output | `gunzip file.txt.gz` | Re-compress with `gzip file.txt` | Equivalent to `gzip -d` |
| zip | Compresses files into a ZIP archive | -r : Recursively add directories<br>-d : Delete entries from archive<br>-u : Update existing archive<br>-v : Verbose output | `zip -r backup.zip folder/` | Unzip with `unzip backup.zip` | Widely compatible across operating systems |
| unzip | Extracts files from ZIP archives | -l : List contents without extracting<br>-q : Quiet mode<br>-d : Extract to specific directory | `unzip backup.zip` | Recompress with `zip` command | Useful for unpacking downloaded software or assets |
| bzip2 | Compresses files using BZIP2 algorithm | -d : Decompress<br>-k : Keep original file<br>-v : Verbose output<br>-z : Force compression | `bzip2 file.txt` | Decompress with `bzip2 -d file.txt.bz2` or `bunzip2 file.txt.bz2` | Offers better compression than gzip, but slower |
| bunzip2 | Decompresses BZIP2-compressed files | -k : Keep original file<br>-v : Verbose output | `bunzip2 file.txt.bz2` | Re-compress with `bzip2 file.txt` | Equivalent to `bzip2 -d` |
| xz | Compresses files using LZMA/XZ compression | -d : Decompress<br>-k : Keep original file<br>-z : Compress (default)<br>-v : Verbose output | `xz file.txt` | Decompress with `xz -d file.txt.xz` or `unxz file.txt.xz` | High compression ratio, ideal for large static files |
| unxz | Decompresses XZ-compressed files | -k : Keep original file<br>-v : Verbose output | `unxz file.txt.xz` | Re-compress with `xz file.txt` | Equivalent to `xz -d` |
| 7z | Creates and extracts 7-Zip archives | a : Add files to archive<br>x : Extract with full paths<br>e : Extract without paths<br>-t : Set archive type<br>-m : Set compression method<br>-p : Set password | `7z a archive.7z folder/` | Extract with `7z x archive.7z` | Supports many formats including 7z, ZIP, RAR, ISO |
| rsync | Efficient remote and local file copying and syncing tool | -a : Archive mode (recursive, preserves permissions)<br>-v : Verbose output<br>-z : Compress during transfer<br>--delete : Remove files not in source<br>-e ssh : Use SSH as transport | `rsync -avz folder/ user@remote:/path/` | Reverse by swapping source and destination | Great for backups and mirroring data between machines |
| dd | Converts and copies files (often used for disk imaging) | if=FILE : Input file<br>of=FILE : Output file<br>bs=BYTES : Block size<br>count=BLOCKS : Number of blocks | `dd if=/dev/sda of=disk.img bs=64K` | Depends on what was copied — image can be restored or deleted | Used for creating bootable USB drives, cloning disks |
| split | Splits large files into smaller chunks | -b SIZE : Split by byte size<br>-l LINES : Split by line count<br>-a NUM : Use NUM suffix digits | `split -b 100M largefile.tar.gz chunk_` | Combine with `cat` or `cat > combinedfile` | Useful when transferring large files through limited-size storage |
| cat (with redirection) | Concatenates and combines files | (No direct specifiers) | `cat chunk_* > combinedfile.tar.gz` | N/A (reversal depends on how it was used) | Often used with `split` to reassemble large archives |



---

### 🧑‍💻 Category 10: Development and Programming

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| gcc | Compiles C and C++ programs | -o : Specify output filename<br>-c : Compile without linking<br>-Wall : Enable all warnings<br>-g : Generate debug info<br>-O : Optimize code (e.g., -O2, -O3) | `gcc -o hello hello.c` | N/A (compilation process) | Part of the GNU Compiler Collection; supports multiple languages |
| g++ | Compiles C++ programs | -o : Output filename<br>-c : Compile only<br>-std=C++11 : Use specific standard<br>-I : Include directory<br>-L : Library path<br>-l : Link library | `g++ -std=c++17 -o app main.cpp` | N/A (compilation process) | Works similarly to `gcc`, but defaults to C++ mode |
| make | Builds projects using Makefiles | -f : Specify a Makefile<br>-C : Change directory before reading Makefile<br>-j : Parallel jobs (e.g., `-j4`)<br>-k : Continue despite errors<br>--dry-run : Show what would be done | `make` | Run `make clean` (if defined in Makefile) | Automates build processes; often used with C/C++ projects |
| gdb | Debugs programs | -q : Quiet mode<br>--args : Pass arguments to program<br>-ex : Execute command at startup<br>--batch : Run non-interactively | `gdb ./myprogram` | N/A (debugging tool) | Supports breakpoints, stepping, memory inspection, and more |
| valgrind | Detects memory leaks and profiling issues | --leak-check= : Level of leak checking<br>--track-origins=yes : Track uninitialized values<br>--tool= : Choose tool (memcheck, callgrind, etc.) | `valgrind --leak-check=full ./app` | N/A (analysis tool) | Slows down execution significantly; use for debugging and testing |
| cmake | Cross-platform build system generator | -S : Source directory<br>-B : Build directory<br>--build : Build project<br>--target : Build specific target<br>--clean-first : Clean before building | `cmake -S . -B build` | Remove build directory manually | Used to generate Makefiles, Ninja files, Visual Studio projects |
| clang | LLVM-based compiler for C/C++/Objective-C | -Weverything : Enable all warnings<br>--analyze : Static analysis mode<br>-fsanitize= : Enable sanitizers (address, undefined, etc.)<br>-o : Output file | `clang -o app main.c` | N/A (compilation process) | Known for better error messages than GCC; supports modern standards |
| javac | Java compiler | -d : Destination directory for class files<br>-source : Language version<br>-target : Target JVM version<br>-cp : Classpath<br>-g : Generate debug info | `javac -d bin src/*.java` | N/A (compilation process) | Compiles `.java` files into bytecode `.class` files |
| java | Runs compiled Java applications | -jar : Run from JAR file<br>-cp : Set classpath<br>-Xmx / -Xms : Memory settings<br>--module-path : For Java modules<br>--add-modules : Add required modules | `java -cp bin MainClass` | N/A (runtime command) | Requires compiled `.class` or `.jar` files |
| python | Interprets Python scripts | -m : Run module as script<br>-c : Execute code inline<br>--version : Show Python version<br>-i : Interactive after script<br>--help : Show help | `python3 script.py` | N/A (interpreted language) | Default interpreter for running `.py` files; versions vary (2.x vs 3.x) |
| pip | Installs and manages Python packages | install : Install package<br>uninstall : Remove package<br>freeze : List installed packages<br>list : Show installed packages<br>upgrade : Update package | `pip install requests` | Uninstall with `pip uninstall package` | Package manager for Python; works with virtual environments |
| node | Executes JavaScript on the server-side (Node.js) | -v : Show version<br>-e : Evaluate script inline<br>--inspect : Enable debugger<br>--experimental-specifier-resolution : Resolve imports | `node app.js` | N/A (script execution) | Built on V8 engine; enables backend development in JS |
| npm | Node.js package manager | install : Install package<br>uninstall : Remove package<br>start : Run start script<br>run : Run custom script<br>init : Initialize new package.json | `npm install express` | Uninstall with `npm uninstall package` | Manages dependencies for Node.js projects |
| yarn | Alternative Node.js package manager | add : Install package<br>remove : Uninstall package<br>run : Run script<br>init : Create package.json<br>cache clean : Clear cache | `yarn add react` | Remove with `yarn remove package` | Faster and more deterministic than npm; uses `yarn.lock` |
| ruby | Interprets Ruby scripts | -e : Execute code inline<br>-n : Assume loop over input lines<br>-p : Print result of each line<br>--version : Show Ruby version | `ruby script.rb` | N/A (interpreted language) | Popular for web development via Ruby on Rails framework |
| gem | Ruby package manager | install : Install gem<br>uninstall : Remove gem<br>update : Update gem<br>list : Show installed gems<br>search : Find gems | `gem install bundler` | Uninstall with `gem uninstall gemname` | Manages Ruby libraries and tools |
| perl | Interprets Perl scripts | -e : Execute code inline<br>-n : Loop over input<br>-p : Loop and print<br>-w : Enable warnings<br>-c : Syntax check only | `perl script.pl` | N/A (interpreted language) | Often used for text processing, sysadmin tasks, and CGI scripting |
| rustc | Rust compiler | -o : Output executable<br>--crate-type : Set crate type<br>--edition : Use specific edition (2015, 2018, 2021)<br>-C opt-level= : Optimization level | `rustc main.rs` | N/A (compilation process) | Safe systems programming language; compiles to native binaries |
| cargo | Rust build system and package manager | new : Create new project<br>build : Build project<br>run : Build and run<br>test : Run tests<br>clippy : Linting tool<br>fmt : Format code | `cargo new myproject` | Delete project folder manually | Central tool for managing Rust projects and dependencies |
| go | Go compiler and toolchain | run : Compile and run<br>build : Build binary<br>get : Download packages<br>test : Run tests<br>fmt : Format source code<br>mod : Module management | `go run main.go` | N/A (compiled or interpreted) | Statically typed, garbage-collected; emphasizes simplicity and concurrency |
| gradle | Build automation system (especially for Java/Kotlin) | build : Build project<br>clean : Clean build outputs<br>tasks : List available tasks<br>--info/--debug : Verbose logging | `gradle build` | Run `gradle clean` | Uses Groovy or Kotlin DSL for build scripts; popular in Android dev |
| maven | Project management and comprehension tool (Java) | compile : Compile sources<br>package : Build JAR/WAR<br>clean : Remove build files<br>install : Install in local repo<br>dependency:tree : Show dependency tree | `mvn package` | Run `mvn clean` | Based on POM.xml; widely used in enterprise Java apps |


---

### ⚙️ Category 11: System and Kernel Management

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| uname | Displays system information | -a : Display all info<br>-r : Kernel release<br>-s : Kernel name<br>-v : Kernel version<br>-m : Machine hardware name | `uname -a` | N/A (informational) | Useful for checking system architecture and kernel version |
| hostname | Shows or sets the system's hostname | -f : Show FQDN<br>-i : Show IP address<br>-d : Show domain name<br>-I : Show all IPs | `hostname`<br>`hostname newname` | Change back manually with same command | Hostname is used in networking and logs |
| lsmod | Lists loaded kernel modules | (No major specifiers) | `lsmod` | N/A (informational) | Shows which drivers and features are currently active |
| modprobe | Adds or removes kernel modules | -r : Remove module<br>--first-time : Only insert if not already loaded<br>--ignore-install : Skip install commands<br>--show-depends : Show dependency actions only | `sudo modprobe vboxdrv`<br>`sudo modprobe -r vboxdrv` | Use `-r` to remove a module | Automatically handles dependencies when loading/unloading |
| rmmod | Removes a module from the kernel | -f : Force removal<br>-w : Wait until module is not in use | `sudo rmmod usb_storage` | Load again with `modprobe` or `insmod` | More low-level than `modprobe`; doesn’t handle dependencies |
| insmod | Inserts a module into the kernel | (Pass module path as argument) | `sudo insmod /lib/modules/.../module.ko` | Remove with `rmmod` or `modprobe -r` | Requires full path to `.ko` file; does not resolve dependencies |
| dmesg | Prints or controls the kernel ring buffer | -T : Show human-readable timestamps<br>--level : Filter by log level<br>-C : Clear ring buffer<br>-c : Clear after printing | `dmesg` | Depends on what was cleared or filtered | Used to view hardware/driver messages and boot logs |
| sysctl | Configures kernel parameters at runtime | -a : Show all settings<br>-w : Write value temporarily<br>-p : Load settings from config file<br>--system : Load all system config files | `sysctl vm.swappiness=10` | Revert by writing original value or rebooting | Settings changed this way are temporary unless saved |
| systemctl | Controls the systemd system和服务管理器 | start : Start service<br>stop : Stop service<br>restart : Restart service<br>status : Show status<br>enable : Enable at boot<br>disable : Disable at boot<br>reboot/poweroff/halt : System control | `sudo systemctl restart nginx` | Reverse using inverse command (e.g., `stop`, `disable`) | Central tool for managing services, units, and system state |
| journalctl | Query systemd journal (system logs) | -b : Boot logs only<br>-u service : Filter by unit<br>--since/--until : Time range<br>-f : Follow live output<br>-x : Add explanatory text | `journalctl -u ssh.service` | Depends on logged events | Centralized logging in modern Linux systems using systemd |
| timedatectl | Queries and sets system time and date | set-time : Set system time<br>set-timezone : Set timezone<br>set-local-rtc : Configure RTC mode | `timedatectl`<br>`sudo timedatectl set-time "2025-01-01 12:00:00"` | Adjust again with `timedatectl` | Manages time synchronization and localization settings |
| hwclock | Accesses the hardware clock | -r : Read hardware clock<br>-w : Write system time to hardware clock<br>-s : Set system time from hardware clock | `hwclock -r` | Correct with `hwclock --set` or `--w` | Ensures correct time across reboots, especially useful without NTP |
| reboot | Reboots the system | -f : Force reboot without shutdown<br>-n : Don't sync before reboot | `sudo reboot` | Cancel pending shutdown/reboot if any | Should be used carefully on production systems |
| poweroff | Shuts down and powers off the system | -f : Force poweroff without shutdown<br>-n : Don't sync before poweroff | `sudo poweroff` | Power on manually again | Similar to `shutdown -h now` but more direct |
| halt | Stops the system but does not power it off | -f : Force halt<br>-p : Also power off | `sudo halt` | Power on manually again | Older systems may stay powered on unless `-p` is used |
| perf | Performance analysis tool | stat : Get overall stats<br>record : Record performance data<br>report : Display recorded data<br>top : Live profiling<br>annotate : Disassemble annotated instructions | `perf stat ./myapp` | Depends on what was measured | Requires kernel support; useful for CPU usage and optimization |
| cpufreq-set | Sets CPU frequency scaling parameters | -c : CPU core number<br>-g : Governor to use<br>-u : Upper frequency limit<br>-d : Lower frequency limit | `sudo cpufreq-set -c 0 -f 2.0GHz` | Reset to default governor or frequency | Used for tuning performance or saving power |
| cpupower | CPU frequency and power management utility | frequency-info : Show current settings<br>frequency-set : Change frequency<br>info : General CPU power info | `cpupower frequency-info` | Revert by setting previous frequency or governor | Works with cpufreq drivers to manage CPU behavior |
| kexec | Loads and boots another kernel without rebooting | -l : Load new kernel<br>--reuse-cmdline : Use current cmdline<br>-e : Execute loaded kernel | `sudo kexec -l /boot/vmlinuz --initrd=/boot/initrd.img --command-line="$(cat /proc/cmdline)"` | Reboot normally if needed | Advanced feature for fast reboots, often used in kernel testing |


---


### 📜 Category 12: Log Management

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| journalctl | Query systemd journal (system logs) | -b : Boot logs only<br>-u service : Filter by unit<br>--since / --until : Time range<br>-f : Follow live output<br>-x : Add explanatory text | `journalctl -u ssh.service` | Depends on logged events | Centralized logging in modern Linux systems using systemd |
| dmesg | Prints or controls the kernel ring buffer | -T : Show human-readable timestamps<br>--level : Filter log level<br>-C : Clear ring buffer<br>-c : Clear after printing | `dmesg` | Depends on what was cleared or filtered | Useful for viewing hardware/driver messages and boot logs |
| tail | Displays the last few lines of a file | -n N : Output the last N lines<br>-f : Follow new lines as file grows<br>-c N : Output last N bytes<br>-q : Suppress headers<br>-v : Always print headers | `tail -f /var/log/syslog` | N/A (display-only command) | Commonly used with `-f` to monitor log files live |
| less | View file content one page at a time | -N : Show line numbers<br>-S : Disable line wrapping<br>-i : Ignore case in searches<br>-X : Do not clear screen after exit<br>+G : Start at end of file | `less -N server.log` | N/A (read-only viewer) | Supports backward/forward navigation and searching with `/` |
| cat | Concatenates and displays file content | -n : Number all output lines<br>-b : Number non-blank output lines<br>-s : Squeeze multiple blank lines into one<br>-T : Show tabs as ^I<br>-v : Display control characters | `cat /var/log/auth.log` | N/A (read-only operation) | Often used to read small log files quickly |
| grep | Searches for patterns in files using regular expressions | -i : Ignore case<br>-v : Invert match<br>-r : Recursive search<br>-n : Show line numbers<br>-l : List filenames only<br>-c : Count matching lines | `grep -i "error" /var/log/syslog` | N/A (search-only command) | Extremely fast and works well with pipes; supports regex |
| awk | Pattern scanning and processing language | '{print $1}' : Print specific columns<br>-F fs : Set field separator<br>NR == n : Process specific record number | `awk '/error/ {print $1,$3}' /var/log/syslog` | N/A (text parsing tool) | Great for structured log analysis and extraction |
| sed | Stream editor for modifying file contents on the fly | -i : Edit files in place<br>-e : Add multiple commands<br>-n : Suppress automatic printing<br>-r : Use extended regex | `sed -i 's/error/warning/g' logfile.log` | Undo changes manually or restore from backup | Useful for batch editing logs or redacting sensitive data |
| logger | Adds custom entries to the system log | -t TAG : Tag the message<br>-p : Priority (e.g., user.notice)<br>--server : Send to remote syslog server | `logger -t myscript "Custom log message"` | N/A (once logged, can't be undone) | Useful for testing or adding script-generated logs |
| logrotate | Manages log rotation and compression | -f : Force rotation<br>-d : Debug mode<br>-v : Verbose output<br>--status : Show status file | `logrotate /etc/logrotate.conf` | Rotate logs back manually if backups exist | Automates log cleanup, prevents disk overfilling |
| rsyslogd | Enhanced multi-threaded syslog daemon | (Configured via `/etc/rsyslog.conf`) | `rsyslogd` | Stop with `systemctl stop rsyslog` or edit config | Handles centralized logging and forwarding |
| syslog-ng | Advanced logging daemon with filtering and forwarding | (Configured via `/etc/syslog-ng/syslog-ng.conf`) | `syslog-ng` | Stop with `systemctl stop syslog-ng` or edit config | Offers more flexibility than traditional syslogd |
| fail2ban | Bans IPs after failed login attempts | -x : Stop service<br>-r : Reload config<br>--set jail action ban/unban IP | `fail2ban-client set sshd banip 192.168.1.100` | Manually unban with `fail2ban-client set sshd unbanip` | Helps prevent brute-force attacks on SSH and other services |
| auditctl | Configures Linux audit system rules | -w path -p [rwa] : Watch file/path for read/write/attribute changes<br>-l : List current rules<br>-d : Delete rule<br>-D : Delete all rules | `auditctl -w /etc/passwd -p wa -k user-modify` | Remove rule using same syntax with `-d` | Part of Linux Audit Framework; logs captured via `ausearch` or `aureport` |
| ausearch | Searches the audit log for specific events | -k KEY : Search by key name<br>--start/-end : Time range<br>-i : Interpret numeric fields into readable format | `ausearch -k user-modify` | N/A (analysis tool) | Used with `auditctl` to review security-related events |
| aureport | Generates summary reports from audit logs | -i : Interpret numeric fields<br>--start/--end : Time range<br>-au : Auth report<br>-x : Executable report | `aureport -au` | N/A (reporting tool) | Helps generate high-level views of audit events |
| logwatch | Analyzes and reports log summaries | --range : Time range (Today, Yesterday, All)<br>--service : Specific service to report on<br>--detail : Level of detail | `logwatch --detail High --service sshd` | N/A (reporting tool) | Useful for daily security monitoring and intrusion detection |
| multitail | Views multiple log files side-by-side in real-time | -s : Split screen layout<br>-i : Input file or command<br>C : Color highlighting<br>f : Add filter | `multitail /var/log/syslog /var/log/auth.log` | Exit with `q` | Excellent for comparing logs from different sources |
| lnav | Log file navigator with auto-detection and analysis | -f : Follow mode<br>-t : Set log format<br>-d : Debug SQL parsing<br>-c : Execute command on startup | `lnav /var/log/*.log` | Exit with `q` | Interactive tool with syntax highlighting and search features |




---


### 📦 Category 13: Package Management

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| apt | Advanced Package Tool – manages packages on Debian/Ubuntu systems | update : Update package list<br>upgrade : Upgrade installed packages<br>install : Install a package<br>remove : Remove a package<br>autoclean : Remove outdated upgrades<br>autoremove : Remove unused dependencies<br>search : Search for a package<br>show : Show package details | `sudo apt update && sudo apt upgrade` | Reverse with `apt remove package_name` or `apt install previous_version` | Uses `/etc/apt/sources.list` and repositories in `/etc/apt/sources.list.d/` |
| apt-get | Older CLI interface for APT (still widely used) | update : Refresh package index<br>upgrade : Upgrade all upgradable packages<br>dist-upgrade : Smart upgrade with dependency changes<br>install : Install package<br>remove : Remove package<br>purge : Remove package + config files<br>source : Download source package | `sudo apt-get install curl` | Uninstall with `apt-get remove curl` or purge configs | Often preferred in scripts due to predictable behavior |
| apt-cache | Query APT’s package cache | search : Search for packages<br>show : Display package info<br>depends : List dependencies<br>rdepends : List reverse dependencies<br>policy : Show package installation policy | `apt-cache search nginx` | N/A (search/query tool) | Useful for checking available versions and dependencies |
| dpkg | Low-level package manager for Debian-based systems | -i : Install package<br>-r : Remove package<br>-P : Purge package (remove + configs)<br>-l : List installed packages<br>-L : List files owned by package<br>--configure : Configure unpacked packages | `sudo dpkg -i package.deb` | Remove with `dpkg -r package_name` or `dpkg -P` to purge | Used when installing `.deb` files directly |
| yum | Yellowdog Updater Modified – RPM-based package manager (used in CentOS/RHEL 7 and earlier) | install : Install package<br>update : Update package<br>remove : Remove package<br>list : List available packages<br>search : Search for a package<br>clean all : Clear cache<br>makecache : Generate metadata cache | `sudo yum install httpd` | Remove with `yum remove httpd` | Automatically resolves dependencies; deprecated by DNF |
| dnf | Dandified YUM – next-generation RPM package manager (used in Fedora, RHEL 8+, CentOS Stream) | install : Install package<br>update : Update package<br>remove : Remove package<br>reinstall : Reinstall package<br>list : List packages<br>info : Show package info<br>history : View transaction history | `sudo dnf install git` | Remove with `dnf remove git` | Faster than yum; supports modular content and better dependency resolution |
| rpm | RPM Package Manager – low-level tool for managing `.rpm` packages | -i : Install package<br>-U : Upgrade package<br>-e : Erase (uninstall) package<br>-q : Query package<br>-l : List files in package<br>-V : Verify package integrity<br>--import : Import GPG key | `sudo rpm -ivh package.rpm` | Uninstall with `rpm -e package_name` | Should be used carefully; doesn’t handle dependencies automatically |
| pacman | Package manager for Arch Linux and derivatives | -S : Sync and install packages<br>-Syu : Update system<br>-R : Remove package<br>-Rs : Remove package and dependencies<br>-Qs : Search installed packages<br>-Qii : Show package info<br>-Sw : Download only (no install) | `sudo pacman -Syu` | Remove with `pacman -R package_name` | Simple and fast; all operations are handled with one tool |
| emerge | Portage package manager for Gentoo Linux | sync : Update repository<br>install : Install package<br>unmerge : Remove package and files<br>update : Update system<br>--search : Search for package<br>--info : Show package details | `sudo emerge --sync && sudo emerge firefox` | Remove with `emerge --unmerge firefox` | Source-based package manager; compiles from source by default |
| zypper | Package manager for openSUSE and SUSE Linux Enterprise | refresh : Update repo metadata<br>update : Upgrade packages<br>install : Install package<br>remove : Remove package<br>search : Search for package<br>info : Show package info<br>patch : Apply patches<br>patches : List available patches | `sudo zypper install vim` | Remove with `zypper remove vim` | Supports patches, service packs, and enterprise features |
| flatpak | Universal package manager across Linux distributions | install : Install app from remote<br>uninstall : Remove app<br>update : Update apps<br>remote-add : Add new software source<br>list : List installed apps<br>info : Show app details | `flatpak install flathub com.example.App` | Remove with `flatpak uninstall com.example.App` | Runs sandboxed applications; works across distros |
| snap | Canonical's universal package format with auto-updates | install : Install a snap<br>remove : Remove a snap<br>refresh : Update snap<br>enable/disable : Toggle auto-refresh<br>find : Search available snaps<br>info : Show snap details | `sudo snap install code --classic` | Remove with `snap remove code` | Self-contained apps with confinement; auto-updates by default |
| nix | Functional package manager supporting multiple platforms | install : Install package<br>uninstall : Remove package<br>env : Create isolated environments<br>build : Build from expression<br>profile : Manage user/system profiles | `nix install nixpkgs#hello` | Uninstall with `nix uninstall hello` | Purely functional; allows rollbacks and multi-version installs |
| guix | GNU Guix package manager based on Scheme | install : Install package<br>remove : Remove package<br>package : Install for current user<br>system : Manage system configuration<br>search : Find packages<br>describe : Show package origin | `guix install hello` | Remove with `guix remove hello` | Reproducible builds; integrates with GNU/Linux system management |



---


### 🧠 Category 14: Scripting and Automation

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| bash | Executes shell commands and scripts | -c : Run a command string<br>-x : Print commands as they are executed<br>-v : Print input lines as read<br>-n : Syntax check only<br>--login : Start as login shell | `bash script.sh` | Depends on what the script does | Default shell for many Linux systems; supports scripting, pipes, functions |
| sh | Bourne shell – used for executing shell scripts | -c : Execute command string<br>-x : Debug mode (show commands)<br>-n : Syntax check only<br>-s : Read from stdin<br>-- : End of options | `sh legacy_script.sh` | Depends on what the script does | More POSIX-compliant than bash; often symlinked to dash or bash |
| zsh | Z Shell – advanced shell with scripting and customization features | -c : Run command<br>-x : Debug output<br>-l : Login shell<br>-s : Read from stdin<br>-o : Set option | `zsh myscript.sh` | Depends on script behavior | Offers better tab completion, globbing, and theme support |
| ksh | KornShell – enhanced version of Bourne shell with scripting enhancements | -c : Execute command<br>-x : Trace execution<br>-n : Syntax check only<br>-s : Read from stdin | `ksh script.ksh` | Depends on script logic | Widely used in enterprise environments for portability and robustness |
| csh | C Shell – uses syntax similar to C language | -c : Run command<br>-f : Don't execute startup file<br>-b : Force batch execution | `csh script.csh` | Depends on script actions | Popular among developers familiar with C-style syntax |
| tcsh | Enhanced version of C Shell with interactive features | -c : Execute command<br>-f : Skip .tcshrc<br>-m : Merge stderr into stdout | `tcsh script.tcsh` | Depends on script behavior | Adds command-line editing, history, and filename completion |
| perl | Practical Extraction and Reporting Language – powerful scripting tool | -e : Execute inline code<br>-n : Loop over input lines<br>-p : Loop and print result<br>-w : Enable warnings<br>-c : Syntax check only | `perl -e 'print "Hello\n"'` | N/A (interpreted language) | Often used for text processing, sysadmin tasks, and CGI scripting |
| awk | Pattern scanning and processing language | '{print $1}' : Print specific columns<br>-F fs : Set field separator<br>NR == n : Process specific record number | `awk '/error/ {print $1,$3}' /var/log/syslog` | N/A (text parsing tool) | Great for structured log analysis and extraction |
| sed | Stream editor for modifying file contents on the fly | -i : Edit files in place<br>-e : Add multiple commands<br>-n : Suppress automatic printing<br>-r : Use extended regex | `sed -i 's/apple/orange/g' fruits.txt` | Undo changes manually or revert from backup | Powerful for batch text editing, especially in scripts |
| cut | Removes sections from each line of files | -d : Delimiter<br>-f : Fields to extract<br>-c : Characters to extract<br>--complement : Exclude selected fields | `cut -d',' -f1 data.csv` | N/A (text extraction utility) | Good for slicing out specific columns from structured text |
| paste | Merges lines of files | -d : Delimiter<br>-s : Serial concatenation<br>--delimiters= : Specify delimiters | `paste file1.txt file2.txt` | N/A (file merging utility) | Opposite of `cut`; useful for combining parallel outputs |
| join | Joins lines of two files on a common field | -1 FIELD : Join on this field from file 1<br>-2 FIELD : Join on this field from file 2<br>-t CHAR : Field separator | `join -1 2 -2 1 file1 file2` | N/A (data joining utility) | Similar to SQL JOINs; works best with sorted input |
| sort | Sorts lines of text files | -n : Numeric sort<br>-r : Reverse order<br>-k : Sort by key/column<br>-u : Unique entries only<br>-t : Field delimiter | `sort -nr scores.txt` | Re-sort with opposite flags if needed | Used frequently with pipelines to organize output |
| uniq | Reports or omits repeated lines | -c : Prefix lines by count<br>-d : Only print duplicate lines<br>-u : Only print unique lines<br>-i : Ignore case | `uniq -c names.txt` | N/A (analysis tool) | Works best when input is already sorted; often paired with `sort` |
| tr | Translates or deletes characters | -d : Delete specified characters<br>-s : Squeeze repeated characters<br>-c : Complement SET1<br>-t : Truncate SET1 | `echo "hello" | tr 'a-z' 'A-Z'` | Reapply `tr` with inverse sets if needed | Useful for cleaning input, converting cases, removing CR chars |
| xargs | Builds and executes command lines from standard input | -n N : Use N arguments per command<br>-d DELIM : Input delimiter<br>-I {} : Replace placeholder in command<br>--max-procs=N : Run N processes in parallel | `cat files.txt | xargs rm` | Backup list first; recovery may be difficult after delete | Useful for handling long lists of files or arguments |
| tee | Reads standard input and writes it to both stdout and files | -a : Append to file<br>-i : Ignore interrupts | `ls -l | tee listing.txt` | Remove the file manually if needed | Useful in scripts to log outputs while still seeing them live |
| eval | Evaluates and executes arguments as a shell command | (No direct specifiers) | `eval "$command"` | N/A (executes command dynamically) | Useful for dynamic command execution in scripts |
| seq | Prints a sequence of numbers | -s : Separator between numbers<br>-w : Equal width output<br>--format : Custom format<br>-f : Same as --format | `seq 1 5` | N/A (generates sequence) | Useful in loops and iterations |
| yes | Outputs a string repeatedly until killed | (Pass string as argument) | `yes`<br>`yes no` | Exit with Ctrl+C | Often used to automate responses |
| sleep | Delays execution for a specified amount of time | (No major specifiers) | `sleep 5` | N/A (simple delay) | Supports seconds, minutes, hours, days |
| timeout | Runs a command with a time limit | -s : Send signal on timeout<br>-k : Kill command after timeout | `timeout 5 ping google.com` | N/A (runs until time or completion) | Useful for enforcing time limits on scripts or commands |
| watch | Executes a command repeatedly at intervals | -n sec : Interval in seconds<br>-d : Highlight differences between updates<br>-g : Exit if output changes | `watch -n 1 'ps -ef \| grep python'` | Ctrl+C to stop | Great for monitoring live changes like logs or system stats |
| logger | Adds custom entries to the system log | -t TAG : Tag the message<br>-p : Priority (e.g., user.notice)<br>--server : Send to remote syslog server | `logger -t myscript "Custom log message"` | N/A (once logged, can't be undone) | Useful for testing or adding script-generated logs |
| source | Executes commands from a file in the current shell | (No major specifiers) | `source ~/.bashrc` | Depends on what was sourced | Changes environment variables, aliases, etc. in current shell |
| read | Reads a line from standard input | -p : Prompt message<br>-s : Silent input (for passwords)<br>-n : Read N characters<br>-t : Timeout after N seconds | `read -p "Enter name: " name` | N/A (interactive input) | Useful in scripts for user interaction |
| exec | Replaces the current shell with a specified command | (No major specifiers) | `exec /bin/bash` | N/A (replaces shell) | Can also be used to redirect file descriptors |
| mkfifo | Creates named pipes (FIFOs) | -m : Set permissions | `mkfifo mypipe` | Remove with `rm mypipe` | Useful for inter-process communication |
| wait | Waits for background processes to complete | (Pass PID as argument) | `wait $!` | N/A (waits for process) | Often used in scripts to synchronize background jobs |
| trap | Specifies actions on receipt of signals | 0 : On exit<br>1 : SIGHUP<br>2 : SIGINT (Ctrl+C)<br>9 : SIGKILL<br>15 : SIGTERM | `trap 'echo Exiting' 0` | Depends on how cleanup is defined | Useful for graceful script termination and cleanup |
| declare | Declares shell variables with attributes | -i : Integer variable<br>-r : Readonly variable<br>-a : Array variable<br>-x : Export variable | `declare -i count=5` | Unset with `unset` or reassign | Controls variable type and scope in scripts |




---



### 📥 Category 15: I/O and Redirection

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| echo | Displays a line of text or variables | -n : Don’t output trailing newline<br>-e : Enable interpretation of backslash escapes | `echo "Hello, World!"` | N/A (output-only command) | Frequently used in shell scripts for displaying messages |
| read | Reads a line from standard input | -p : Prompt message<br>-s : Silent input (for passwords)<br>-n : Read N characters<br>-t : Timeout after N seconds | `read -p "Enter name: " name` | N/A (interactive input) | Useful in scripts for capturing user input |
| cat | Concatenates and displays file content | -n : Number all output lines<br>-b : Number non-blank output lines<br>-s : Squeeze multiple blank lines into one<br>-T : Show tabs as ^I<br>-v : Display control characters | `cat file.txt` | N/A (read-only operation) | Can also be used with pipes to pass content to other commands |
| tee | Reads standard input and writes it to both stdout and files | -a : Append to file instead of overwriting<br>-i : Ignore interrupts | `ls -l | tee listing.txt` | Remove the file manually if needed | Useful in scripts to log outputs while still seeing them live |
| > | Redirects standard output to a file (overwrites) | No direct specifiers | `echo "Hello" > file.txt` | Manually restore previous content if backed up | Basic redirection operator; useful for writing output to files |
| >> | Redirects standard output and appends to a file | No direct specifiers | `echo "More text" >> file.txt` | Manually remove added content if needed | Used to add content without losing existing data |
| < | Redirects standard input from a file | No direct specifiers | `sort < input.txt` | Depends on how input is processed | Allows reading from files instead of keyboard input |
| << | Here document – redirects input until a specified delimiter | No direct specifiers (delimiter-based) | `cat << EOF > file.txt`<br>`This is content`<br>`EOF` | Depends on what was written | Useful for embedding multi-line input directly in scripts |
| <<< | Here string – passes a string as input | No direct specifiers | `grep "pattern" <<< "test string"` | Depends on processing logic | Similar to `echo`, but avoids subshell |
| \| (pipe) | Sends the output of one command as input to another | No direct specifiers | `ps aux | grep sshd` | Reverse order of commands if applicable | Fundamental for chaining commands together |
| exec | Replaces the current shell with a specified command | (No major specifiers) | `exec /bin/bash` | N/A (replaces shell) | Can also be used to redirect file descriptors |
| xargs | Builds and executes command lines from standard input | -n N : Use N arguments per command<br>-d DELIM : Input delimiter<br>-I {} : Replace placeholder in command<br>--max-procs=N : Run N processes in parallel | `cat files.txt | xargs rm` | Backup list first; recovery may be difficult after delete | Useful for handling long lists of files or arguments |
| split | Splits large files into smaller chunks | -b SIZE : Split by byte size<br>-l LINES : Split by line count<br>-a NUM : Use NUM suffix digits | `split -b 100M largefile.tar.gz chunk_` | Combine using `cat chunk_* > combinedfile.tar.gz` | Useful when transferring large files through limited-size storage |
| cat (with redirection) | Concatenates and combines files | (No direct specifiers) | `cat chunk_* > combinedfile.tar.gz` | N/A (reversal depends on usage) | Often used with `split` to reassemble large archives |
| mkfifo | Creates named pipes (FIFOs) | -m : Set permissions | `mkfifo mypipe` | Remove with `rm mypipe` | Useful for inter-process communication |
| wait | Waits for background processes to complete | (Pass PID as argument) | `wait $!` | N/A (waits for process) | Often used in scripts to synchronize background jobs |
| eval | Evaluates and executes arguments as a shell command | (No major specifiers) | `eval "$command"` | N/A (executes command dynamically) | Useful for dynamic command execution in scripts |
| logger | Adds custom entries to the system log | -t TAG : Tag the message<br>-p : Priority (e.g., user.notice)<br>--server : Send to remote syslog server | `logger -t myscript "Custom log message"` | N/A (once logged, can't be undone) | Useful for testing or adding script-generated logs |
| source | Executes commands from a file in the current shell | (No major specifiers) | `source ~/.bashrc` | Depends on what was sourced | Changes environment variables, aliases, etc. in current shell |
| cmp | Compares two files byte-by-byte | -l : List differing bytes<br>-n N : Compare only N bytes<br>-i SKIP : Skip initial bytes | `cmp file1.bin file2.bin` | N/A (comparison tool only) | Faster than `diff` for binary files |
| diff | Shows differences between files | -u : Unified format<br>-r : Recursive comparison<br>-q : Quiet output<br>-b : Ignore whitespace<br>-w : Ignore all whitespace | `diff -u file1.txt file2.txt` | N/A (informational) | Commonly used in version control and patching |
| comm | Compares sorted files line by line | -1 : Suppress lines unique to file1<br>-2 : Suppress lines unique to file2<br>-3 : Suppress lines common to both | `comm -12 file1.txt file2.txt` | N/A (analysis tool) | Good for comparing word lists, logs, and sorted datasets |



---



### 🐳 Category 16: Container and Virtualization

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| docker | Manages Docker containers | run : Run a new container<br>ps : List running containers<br>stop : Stop a container<br>rm : Remove a container<br>images : List images<br>build : Build an image from Dockerfile<br>exec : Execute command in running container<br>pull : Pull image from registry | `docker run -d nginx` | Stop and remove with `docker stop` and `docker rm` | Central tool for managing Docker-based applications |
| docker-compose | Manages multi-container Docker applications using YAML files | up : Start services<br>down : Stop and remove containers<br>build : Build or rebuild services<br>logs : View logs<br>ps : List running services | `docker-compose up` | Stop and delete with `docker-compose down` | Uses `docker-compose.yml` for defining services, networks, volumes |
| podman | Container engine (alternative to Docker) | run : Run a container<br>ps : List containers<br>stop : Stop container<br>rm : Remove container<br>images : List images<br>build : Build image<br>exec : Execute command in container | `podman run -d httpd` | Stop and remove with `podman stop` and `podman rm` | Rootless by default; no daemon required |
| buildah | Builds OCI container images | from : Create working container from image<br>run : Run command in container<br>commit : Commit container to image<br>copy : Copy files into container<br>add : Add remote file or directory | `buildah from ubuntu` | Delete container/image manually if needed | Works well with Podman for building and modifying images |
| kubectl | Kubernetes command-line tool for managing clusters | get : List resources<br>describe : Show detailed resource info<br>create : Create resource<br>apply : Apply configuration<br>delete : Remove resource<br>logs : View container logs<br>exec : Execute command in pod | `kubectl get pods` | Undo changes via `kubectl delete` or revert config | Essential for managing Kubernetes workloads |
| minikube | Runs a local Kubernetes cluster for development | start : Start the cluster<br>stop : Stop the cluster<br>delete : Remove the cluster<br>status : Check current status<br>ip : Get cluster IP<br>dashboard : Open dashboard | `minikube start` | Stop and delete with `minikube stop && minikube delete` | Great for testing Kubernetes locally without cloud costs |
| kubeadm | Tool to create and manage Kubernetes clusters | init : Initialize master node<br>join : Join worker node to cluster<br>reset : Reset node to pristine state<br>token : Manage tokens for joining nodes | `sudo kubeadm init` | Reset with `sudo kubeadm reset` | Used for setting up production-like Kubernetes clusters |
| ctr | Low-level CLI for interacting with containerd | containers list : Show all containers<br>image pull : Pull image<br>task kill : Kill task<br>snapshot mounts : Show mounted snapshots | `ctr image pull docker.io/library/ubuntu:latest` | Depends on what was pulled or created | More technical than Docker CLI; used when debugging containerd |
| virsh | Manages virtual machines and hypervisors (libvirt) | list : List VMs<br>start : Start VM<br>shutdown : Graceful shutdown<br>destroy : Force stop VM<br>define : Define VM from XML<br>undefine : Remove VM definition | `virsh start myvm` | Shutdown or undefine with `virsh shutdown` and `virsh undefine` | Works with KVM/QEMU and other virtualization backends |
| virt-install | Command-line tool to create virtual machines | --name : VM name<br>--ram : Memory size<br>--vcpus : Number of CPUs<br>--disk : Disk path/size<br>--network : Network settings<br>--os-variant : OS type optimization | `virt-install --name testvm --ram 2048 --disk path=/var/lib/libvirt/images/testvm.img,size=10 --network network=default --cdrom /isos/ubuntu.iso` | Delete VM with `virsh undefine` and remove disk file | Used for scripting VM creation |
| qemu-system-x86_64 | QEMU full system emulation for x86_64 architecture | -hda : Hard disk image<br>-cdrom : Bootable CD-ROM image<br>-m : Memory size<br>-cpu : CPU model<br>-smp : Number of CPUs<br>-net : Network configuration | `qemu-system-x86_64 -hda disk.img -cdrom ubuntu.iso -m 2048` | Exit QEMU session with Ctrl+Alt+2 then quit | Emulates full hardware stack; useful for cross-platform testing |
| kvm | Kernel-based Virtual Machine launcher (uses QEMU) | -m : Memory size<br>-smp : Number of CPUs<br>-hda : Hard disk image<br>-cdrom : Bootable CD image<br>-boot : Boot device order | `kvm -m 2048 -hda disk.img -cdrom ubuntu.iso` | Exit with Ctrl+Alt+2 then quit | Requires hardware virtualization support enabled in BIOS |
| vboxmanage | Command-line interface for Oracle VirtualBox | createvm : Create new VM<br>modifyvm : Configure VM settings<br>startvm : Start VM<br>controlvm : Control running VM<br>list vms : Show existing VMs | `VBoxManage createvm --name "MyVM" --register` | Delete VM with `VBoxManage unregistervm` and `--delete` | Useful for scripting VM automation tasks |
| lxc | Linux Containers – lightweight system containers | launch : Create and start container<br>list : Show containers<br>stop : Stop container<br>start : Start container<br>exec : Run command inside container<br>delete : Remove container | `lxc launch ubuntu:22.04 mycontainer` | Delete with `lxc delete mycontainer` | OS-level virtualization; faster and lighter than VMs |
| lxd | LXC enhanced with REST API and better UX | init : Setup LXD environment<br>launch : Create and start container<br>list : Show containers<br>stop/start : Control lifecycle<br>exec : Run commands inside container | `lxd init --auto`<br>`lxc launch ubuntu:22.04 mycontainer` | Delete with `lxc delete mycontainer` | Designed for production use; integrates with networking and storage |
| multipass | Lightweight VM manager for Ubuntu instances | launch : Start new instance<br>list : Show running instances<br>stop : Stop instance<br>delete : Remove instance<br>exec : Run command in instance<br>shell : Access shell | `multipass launch --name devbox --mem 2G` | Delete with `multipass delete devbox` | Great for developers needing quick Ubuntu environments |
| vagrant | Tool for building and managing virtual machine environments | up : Create and configure VM<br>ssh : SSH into VM<br>halt : Shut down VM<br>destroy : Remove VM<br>reload : Restart VM<br>status : Check VM status | `vagrant up` | Destroy with `vagrant destroy` | Works with VirtualBox, VMware, AWS, and more |
| screen | Terminal multiplexer for managing multiple sessions | -S : Start named session<br>-ls : List active sessions<br>-r : Resume session<br>-d : Detach session<br>-X : Send command to session | `screen -S mysession` | Detach with `Ctrl+A D` or kill with `Ctrl+C` | Allows persistent terminal sessions across disconnects |
| tmux | Terminal multiplexer with modern features | new-session : Start new session<br>attach-session : Attach to session<br>detach : Detach from session<br>split-window : Split view<br>rename-session : Rename session | `tmux new -s dev` | Detach with `Ctrl+B D` or kill with `Ctrl+C` | Offers panes, windows, and advanced scripting capabilities |


---



### ⏰ Category 17: Time and Date Management

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| date | Displays or sets the system date and time | -u : Display or set UTC time<br>+%FORMAT : Custom output format (e.g., `+%Y-%m-%d`)<br>-s "DATE" : Set date/time manually | `date`<br>`date +"%A, %B %d, %Y"` | N/A (time is irreversible) | Can be used to format timestamps in scripts |
| timedatectl | Queries and sets system time and date (systemd-based systems) | set-time : Set system time<br>set-timezone : Set timezone<br>--adjust-system-clock : Adjust RTC accordingly | `timedatectl`<br>`sudo timedatectl set-time "2025-01-01 12:00:00"` | Adjust again with `timedatectl` using correct values | Manages time synchronization and localization settings |
| hwclock | Accesses the hardware clock (RTC) | -r : Read current time from hardware clock<br>-w : Write system time to hardware clock<br>-s : Set system time from hardware clock | `hwclock -r` | Correct with `hwclock --set` or `--w` | Ensures correct time across reboots; important when dual-booting |
| ntpdate | Sets the system time from an NTP server (deprecated) | -u : Use UDP instead of TCP<br>-b : Set time using `adjtime` instead of `settimeofday` | `sudo ntpdate pool.ntp.org` | N/A (one-time sync only) | Replaced by `chronyd` or `systemd-timesyncd`; use for manual sync |
| timedatectl (synchronize) | Enables/disables automatic time synchronization via systemd-timesyncd | set-ntp true/false : Enable/disable NTP | `sudo timedatectl set-ntp true` | Disable with `sudo timedatectl set-ntp false` | Works well with network connectivity and configured NTP servers |
| chronyc | Controls the Chrony NTP implementation | tracking : Show current sync status<br>sources : List configured sources<br>makestep : Force immediate sync<br>online/offline : Toggle source availability | `chronyc sources` | Reverse action depending on what was changed | More flexible than `ntpd`, supports intermittent connections |
| adjtimex | Adjusts kernel time variables | -p : Print current time adjustment<br>-t TICK : Set tick value<br>-f FREQ : Set frequency offset | `adjtimex -p` | Restore original values if recorded | Used for fine-tuning time adjustments and syncing clocks |
| zdump | Shows current time in specified time zones | -v : Verbose mode showing transitions<br>ZONE : Time zone name (e.g., America/New_York) | `zdump America/New_York` | N/A (informational) | Useful for checking daylight saving changes and time zone data |
| tzselect | Helps user select and configure time zone | (Interactive command, no direct specifiers) | `tzselect` | Change again using same tool or edit `/etc/localtime` | Guides users through selecting region and location for local time |
| date (formatting) | Formats timestamps according to locale or custom format | +%FORMAT : Format output (e.g., `%H:%M:%S`, `%Y-%m-%d`) | `date "+Today is %A, %B %d"` | N/A (display-only) | Very useful in shell scripts for logging and filenames |
| sleep | Delays execution for a specified amount of time | (No major specifiers) | `sleep 5` | N/A (simple delay) | Supports seconds, minutes (`sleep 1m`), hours (`sleep 1h`) |
| timeout | Runs a command with a time limit | -s : Send signal on timeout<br>-k : Kill command after timeout | `timeout 5 ping google.com` | N/A (runs until time or completion) | Useful for enforcing time limits on scripts or commands |
| at | Schedules one-time tasks at a specific time | -l : List pending jobs<br>-c JOB : View job details<br>-r JOB : Remove scheduled job | `echo "tar cf /backup.tar /data" | at midnight` | Cancel with `atrm JOB_ID` | Requires `atd` service running; ideal for delayed operations |
| batch | Executes commands when system load is low | (No major specifiers; input via stdin) | `echo "find / -name core | xargs rm -f" | batch` | Depends on job execution status | Similar to `at`, but runs based on system load level |
| watch | Executes a command repeatedly at intervals | -n SEC : Interval in seconds<br>-d : Highlight differences between updates<br>-g : Exit if output changes | `watch -n 1 'ps -ef \| grep python'` | Ctrl+C to stop | Great for monitoring live changes like logs or system stats |
| crontab | Edits and manages recurring scheduled tasks | -l : List cron entries<br>-e : Edit cron entries<br>-r : Remove all cron entries<br>-u USER : Manage another user's crontab | `crontab -e` | Remove or modify entry in editor | Uses syntax: `MIN HOUR DOM MON DOW CMD`; essential for automation |
| anacron | Runs daily, weekly, and monthly jobs even if system was off | -s : Serialize execution<br>-f : Run jobs even if already run today<br>-d : Debug mode | `anacron -d` | Stop with Ctrl+C or disable configuration | Designed for laptops/desktops that aren't always online |
| rtcwake | Enters a system sleep state until a specified alarm time | -m : Sleep mode (standby, mem, disk)<br>-t TIME : Alarm in seconds since epoch<br>-s SEC : Sleep for SEC seconds | `rtcwake -m mem -s 3600` | Wake up automatically at set time | Combines power-saving with scheduling |
| date (epoch conversion) | Converts Unix timestamp to human-readable date | @TIMESTAMP : Convert epoch time | `date -d @1717182000` | N/A (conversion tool) | Also works in reverse: `date +%s -d "2024-06-01"` |


---


### 🔐 Category 18: File Integrity and Backup

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| rsync | Efficient remote and local file copying and syncing tool | -a : Archive mode (recursive, preserves permissions)<br>-v : Verbose output<br>-z : Compress during transfer<br>--delete : Remove files not in source<br>-e ssh : Use SSH as transport | `rsync -avz folder/ user@remote:/path/` | Reverse by swapping source and destination | Great for backups and mirroring data between machines |
| tar | Archives multiple files into a single file (tape archive) | -c : Create new archive<br>-x : Extract files<br>-v : Verbose output<br>-f : Specify filename<br>-z : Compress with gzip<br>-j : Compress with bzip2<br>-J : Compress with xz | `tar -czvf backup.tar.gz folder/` | Use `-x` to extract the archive | Commonly used for backups and distributing source code |
| dd | Copies files, converts data, and performs low-level disk operations | if=FILE : Input file<br>of=FILE : Output file<br>bs=BYTES : Block size<br>count=BLOCKS : Number of blocks | `dd if=/dev/sda of=disk.img bs=64K` | Depends on what was copied — image can be restored or deleted | Often used to create disk images, clone drives, or wipe disks |
| cp | Copies files and directories | -r : Copy directories recursively<br>-i : Prompt before overwrite<br>-u : Copy only when source is newer<br>-v : Verbose output<br>-p : Preserve file attributes<br>-a : Archive mode (preserve all) | `cp -r ~/Documents ~/Backup` | Manually remove the copied files or directory using `rm -r [destination]` | Use `-a` for backups to preserve file metadata |
| scp | Securely copies files between hosts | -P : Port number<br>-i : Identity file<br>-r : Recursively copy directories | `scp file.txt user@remote:/path/` | Copy back from remote host if needed | Based on SSH protocol; secure alternative to rcp |
| sftp | Interactive secure file transfer over SSH | get/put : Download/upload files<br>ls/lls : List remote/local directory<br>cd/lcd : Change remote/local dir<br>mkdir/rmdir : Create/remove dirs | `sftp user@remote` | Upload/delete files accordingly | Safer than regular FTP; uses encryption |
| dump | Backs up ext2/ext3/ext4 filesystems | -0-9 : Backup level (0 = full, 1–9 = incremental)<br>-f : Output file/device<br>-u : Update `/etc/dumpdates`<br>-z : Compress level (for level 0 only) | `dump -0uf /backup/full.dump /home` | Restore with `restore` command | Old-school Unix/Linux backup utility; works at filesystem level |
| restore | Restores files backed up with `dump` | -r : Restore entire filesystem<br>-t : List contents of dump<br>-C : Compare dump with filesystem<br>-i : Interactive restore mode | `restore -rf /backup/full.dump` | N/A (reverse of restore) | Works only with dumps created by `dump` |
| rsnapshot | Filesystem snapshot utility based on rsync | configtest : Check config<br>alpha/beta/daily/etc. : Predefined intervals<br>--noexec : Dry run<br>-v : Verbose<br>-q : Quiet | `rsnapshot daily` | Roll back to previous snapshot manually | Excellent for incremental backups using hard links |
| sha256sum | Computes SHA-256 cryptographic checksums | (No major specifiers) | `sha256sum file.txt > checksum.sha256` | N/A (checksum generation) | Used to verify file integrity before/after transfers |
| md5sum | Computes MD5 hash for files | (No major specifiers) | `md5sum file.iso > checksum.md5` | N/A (hashing tool) | Less secure than SHA, but still widely used for verification |
| cksum | Generates CRC32 checksum and byte count | (No major specifiers) | `cksum largefile.tar.gz` | N/A (integrity check only) | Fast but less reliable than SHA or MD5 |
| diff | Compares two files line by line | -u : Unified format<br>-r : Recursive comparison<br>-q : Quiet output<br>-b : Ignore whitespace<br>-w : Ignore all whitespace | `diff -u file1.txt file2.txt` | N/A (informational) | Useful for checking differences after restoration |
| cmp | Compares two files byte-by-byte | -l : List differing bytes<br>-n N : Compare only N bytes<br>-i SKIP : Skip initial bytes | `cmp file1.bin file2.bin` | N/A (comparison tool only) | Faster than `diff` for binary files |
| gpg | GNU Privacy Guard – encrypting and signing data | -c : Symmetric encryption<br>-e : Encrypt for recipient<br>-d : Decrypt file<br>-s : Sign file<br>--verify : Verify signature<br>--import/export : Manage keys | `gpg -c secret.txt` | Decrypt using `gpg -d secret.txt.gpg` | Used for securing backups or verifying their authenticity |
| openssl | Toolkit for SSL/TLS protocols and cryptography | enc : Encrypt/decrypt files<br>dgst : Message digest calculation<br>rsautl : RSA operation<br>rand : Generate random data | `openssl enc -aes-256-cbc -in secret.txt -out encrypted.bin` | Decrypt using same command with `-d` flag | Supports many cryptographic operations including hashing and signing |
| cryptsetup | Manages encrypted volumes (like LUKS) | luksFormat : Initialize LUKS partition<br>open : Unlock volume<br>close : Lock volume<br>isLuks : Check if device is LUKS<br>addKey/removeKey : Manage encryption keys | `sudo cryptsetup luksFormat /dev/sdb1` | Destroy or reformat encrypted volume to reverse | Used for full-disk encryption and secure backups |
| veracrypt | Mounts and creates VeraCrypt encrypted volumes | create : Create new volume<br>mount : Mount volume<br>dismount : Unmount volume<br>list : Show mounted volumes | `veracrypt --mount /dev/sdb1 /mnt/secure` | Dismount and optionally delete encrypted container | Cross-platform FDE solution; successor to TrueCrypt |
| lvm | Logical Volume Manager for flexible storage management | pvcreate : Create physical volume<br>vgcreate : Create volume group<br>lvcreate : Create logical volume<br>lvextend : Extend volume size<br>lvreduce : Shrink volume<br>lvremove : Delete logical volume | `lvcreate -L 10G -n myvol mygroup` | Reverse using `lvremove`, `vgremove`, `pvremove` | Enables snapshots, dynamic resizing, and advanced disk management |
| lvcreate (with snapshot) | Creates LVM snapshots for point-in-time backups | -s : Snapshot mode<br>-L : Size of snapshot | `lvcreate -L 10G -s -n snap_vol /dev/mygroup/myvol` | Remove snapshot with `lvremove /dev/mygroup/snap_vol` | Allows safe backups without unmounting live systems |
| find | Locates files matching criteria | -name/-iname : Match name (case-sensitive/insensitive)<br>-mtime/-ctime/-atime : Time-based filtering<br>-type f/d : File/directory type<br>-exec : Execute command on found items<br>-delete : Delete matched files | `find /var/log -name "*.log" -mtime +7 -delete` | Depends on action taken (e.g., deletion vs view-only) | Powerful for managing old logs, temp files, and orphaned data |
| logrotate | Manages log rotation and compression | -f : Force rotation<br>-d : Debug mode<br>-v : Verbose output<br>--status : Show status file | `logrotate /etc/logrotate.conf` | Rotate logs back manually if backups exist | Automates log cleanup, prevents disk overflow |
| duplicity | Encrypted bandwidth-efficient backup tool | full/incremental : Full or incremental backup<br>--encrypt-key : GPG key ID<br>--sign-key : Signing key ID<br>--include/--exclude : Selective backup | `duplicity /home scp://user@remote//backup` | Restore using `duplicity restore` | Uses GnuPG and rsync logic for secure offsite backups |
| timeshift | System restore tool for Linux (similar to Windows System Restore) | setup : Configure settings<br>backup : Create snapshot<br>restore : Recover system state<br>delete : Remove snapshot<br>list : Show available snapshots | `timeshift-setup`<br>`timeshift backup` | Restore to earlier snapshot via GUI or CLI | Ideal for restoring system after failed updates or misconfigurations |
| restic | Fast, secure, and efficient backup program | init : Initialize repository<br>backup : Create snapshot<br>restore : Restore files<br>snapshots : List backups<br>forget/prune : Clean old data | `restic -r /media/backup init`<br>`restic -r /media/backup backup /home` | Restore from backup using `restic restore` | Supports deduplication, encryption, and cloud storage |
| borg | Deduplicating backup program with compression and encryption | init : Initialize repo<br>create : Make backup archive<br>extract : Restore files<br>list : Show archives<br>delete : Remove archive<br>prune : Remove old archives | `borg init /media/backup`<br>`borg create /media/backup::archive /home` | Restore with `borg extract` | Space-efficient; great for long-term archival |
| rsnapshot | Filesystem snapshot utility based on rsync | configtest : Validate config<br>daily/weekly/monthly : Preset intervals<br>--noexec : Dry run<br>-v : Verbose<br>-q : Quiet | `rsnapshot daily` | Manually revert to previous snapshot | Uses hard links to save space; ideal for incremental backups |
| amanda | Client-server network backup tool | configcheck : Validate config<br>amcheck : Check configuration sanity<br>amdump : Run scheduled backups<br>amrecover : Restore files interactively | `amdump` | Restore using `amrecover` | Designed for enterprise environments with multiple servers |
| bacula | Network backup and recovery system | console : Access control interface<br>dir : Director service<br>fd : File daemon<br>sd : Storage daemon | `bconsole` | Restore via Bacula console or GUI | Suitable for large-scale backup and disaster recovery |
| duplicity | Encrypted backups using GnuPG and librsync | full/incremental : Backup types<br>--encrypt-key : GPG key<br>--include/--exclude : File filters | `duplicity full /home file:///backup` | Restore with `duplicity restore` | Supports SFTP, Rsync, Amazon S3, and more |
| tar (with compression) | Archives files with optional compression | -z : GZIP compression<br>-j : BZIP2 compression<br>-J : XZ compression<br>--use-compress-program : Custom compressor | `tar -cJf backup.tar.xz /data` | Extract with matching decompression flag (`-xJf`) | Flexible way to compress backups efficiently |
| ddrescue | Data recovery tool for damaged media | -f : Overwrite output file<br>-r N : Retry N times on read errors<br>-n : No truncate, no split | `ddrescue /dev/cdrom image.iso rescue.log` | Depends on what was recovered | Tries hard to recover data from failing drives |
| testdisk | Partition table and boot sector recovery tool | (Interactive menu-driven interface) | `testdisk /dev/sda` | Undo changes within TestDisk before writing | Helps recover lost partitions and repair MBR/GPT |
| photorec | File recovery tool for deleted files | (Runs interactively; select disk/partition) | `photorec /dev/sdb1` | Recovered files cannot be "undone" easily | Recovers deleted files even from formatted disks |


---


### 🔍 Category 19: Text and Binary File Manipulation

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| tr | Translates or deletes characters | -d : Delete specified characters<br>-s : Squeeze repeated characters<br>-c : Complement SET1<br>-t : Truncate SET1 | `echo "hello" | tr 'a-z' 'A-Z'` | Reapply `tr` with inverse sets if needed | Useful for cleaning input, converting cases, removing CR chars |
| sed | Stream editor for modifying file contents on the fly | -i : Edit files in place<br>-e : Add multiple commands<br>-n : Suppress automatic printing<br>-r : Use extended regex | `sed -i 's/apple/orange/g' fruits.txt` | Undo changes manually or restore from backup | Powerful for batch text editing, especially in scripts |
| awk | Pattern scanning and processing language | '{print $1}' : Print specific columns<br>-F fs : Set field separator<br>NR == n : Process specific record number | `awk '/error/ {print $1,$3}' /var/log/syslog` | N/A (text parsing tool) | Great for structured log analysis and extraction |
| cut | Removes sections from each line of files | -d : Delimiter<br>-f : Fields to extract<br>-c : Characters to extract<br>--complement : Exclude selected fields | `cut -d',' -f1 data.csv` | N/A (text extraction utility) | Good for slicing out specific columns from structured text |
| paste | Merges lines of files | -d : Delimiter<br>-s : Serial concatenation<br>--delimiters= : Specify delimiters | `paste file1.txt file2.txt` | N/A (file merging utility) | Opposite of `cut`; useful for combining parallel outputs |
| join | Joins lines of two files on a common field | -1 FIELD : Join on this field from file 1<br>-2 FIELD : Join on this field from file 2<br>-t CHAR : Field separator | `join -1 2 -2 1 file1 file2` | N/A (data joining utility) | Similar to SQL JOINs; works best with sorted input |
| sort | Sorts lines of text files | -n : Numeric sort<br>-r : Reverse order<br>-k : Sort by key/column<br>-u : Unique entries only<br>-t : Field delimiter | `sort -nr scores.txt` | Re-sort with opposite flags if needed | Used frequently with pipelines to organize output |
| uniq | Reports or omits repeated lines | -c : Prefix lines by count<br>-d : Only print duplicate lines<br>-u : Only print unique lines<br>-i : Ignore case | `uniq -c names.txt` | N/A (analysis tool) | Works best when input is already sorted; often paired with `sort` |
| grep | Searches for patterns in files using regular expressions | -i : Ignore case<br>-v : Invert match (show non-matching lines)<br>-r : Recursive search<br>-n : Show line numbers<br>-l : List filenames only<br>-c : Count matching lines | `grep -i "error" server.log` | Use `grep -v` to find lines that don't match a pattern | Extremely fast and works well with pipes; supports regex |
| diff | Compares two files line by line | -u : Unified format<br>-r : Recursive comparison<br>-q : Quiet output<br>-b : Ignore whitespace<br>-w : Ignore all whitespace | `diff -u file1.txt file2.txt` | N/A (informational) | Commonly used in version control and patching |
| cmp | Compares two files byte-by-byte | -l : List differing bytes<br>-n N : Compare only N bytes<br>-i SKIP : Skip initial bytes | `cmp file1.bin file2.bin` | N/A (comparison tool only) | Faster than `diff` for binary files |
| cat | Concatenates and displays file content | -n : Number all output lines<br>-b : Number non-blank output lines<br>-s : Squeeze multiple blank lines into one<br>-T : Show tabs as ^I<br>-v : Display control characters | `cat file.txt` | N/A (read-only operation) | Often used with pipes to pass content to other commands |
| head | Displays the first few lines of a file | -n N : Output the first N lines<br>-c N : Output the first N bytes<br>-q : Never print headers<br>-v : Always print headers | `head -n 10 logfile.log` | N/A (display-only command) | Useful for previewing large files or checking logs quickly |
| tail | Displays the last few lines of a file | -n N : Output the last N lines<br>-f : Follow new lines in real time<br>-c N : Output the last N bytes<br>-q : Suppress headers<br>-v : Always print headers | `tail -f /var/log/syslog` | N/A (display-only command) | Commonly used with `-f` to monitor log files live |
| rev | Reverses lines of a file or input | (No major specifiers) | `rev file.txt` | Apply `rev` again to reverse back | Simple utility for reversing strings or lines |
| od | Dumps files in octal, hex, or other formats | -x : Hexadecimal two-byte display<br>-b : Octal byte display<br>-c : Character display with C-style escapes<br>-t : Custom output format<br>-A : Address base (dec, hex, etc.) | `od -c file.txt` | Depends on what was analyzed | Useful for inspecting binary files or debugging raw data |
| xxd | Creates a hex dump of a file or reverses it | -h : Help<br>-g N : Bytes per group<br>-b : Binary instead of hex<br>-r : Reverse operation (convert hex back to binary) | `xxd file.txt`<br>`xxd -r hexdump.txt original.bin` | Convert back using `-r` flag | Hex editor-friendly format; can convert binary ↔ hex |
| strings | Extracts printable strings from binary files | -n N : Minimum string length (default 4)<br>-f : Show filename before strings<br>-o : Print offset in file | `strings binary.exe` | N/A (extraction tool only) | Useful for analyzing compiled binaries or core dumps |
| iconv | Converts text between different character encodings | -f : From encoding<br>-t : To encoding<br>-o : Output file<br>--list : Show supported encodings | `iconv -f latin1 -t utf8 file.txt -o newfile.txt` | Convert back using same command with reversed encodings | Essential for fixing encoding issues or preparing data for export |
| fold | Wraps text to fit a specified width | -w N : Wrap at N characters<br>-s : Break at spaces<br>-b : Count bytes instead of columns | `fold -w 80 longline.txt` | Unfold using `tr -d '\n'` or similar tools | Helps format plain text to fixed-width displays or terminals |
| expand | Converts tabs to spaces in files | -t N : Tab stop every N columns<br>--initial : Don’t convert leading tabs<br>-i : Convert only tabs after non-blank characters | `expand -t 4 code.py > code_expanded.py` | Use `unexpand` to revert | Useful for code formatting or standardizing indentation |
| unexpand | Converts spaces to tabs where possible | -t N : Tab stops every N columns<br>--first-only : Convert only leading spaces<br>-a : Convert all spaces | `unexpand -t 4 code_expanded.py > code_tabs.py` | Use `expand` to revert | Useful for reducing file size or preserving tab-based indentation |
| fmt | Simple text formatter | -w N : Set maximum line width<br>-s : Split long lines only<br>-u : Uniform spacing<br>-p : Paragraph prefix | `fmt -w 75 essay.txt` | Formatting is irreversible unless original preserved | Good for reflowing paragraphs or adjusting prose layout |
| column | Formats input into multiple columns | -t : Determine column alignment from headers<br>-s SEPARATOR : Specify delimiter<br>-c WIDTH : Output width in characters | `column -t -s ',' data.csv` | N/A (formatting tool) | Useful for making flat files more readable |
| nl | Numbers lines of files | -b : Line numbering mode (a=all, t=non-empty, n=none)<br>-s : Separator between number and text<br>-w : Width of number field | `nl -b a script.sh` | Remove line numbers via `cut` or `sed` | Good for reviewing code or log files with line numbers |
| tac | Concatenates and displays files in reverse order | (No major specifiers) | `tac file.txt` | Run again to reverse back | Reverse of `cat`; useful for reversing logs or sequences |
| comm | Compares sorted files line by line | -1 : Suppress lines only in file1<br>-2 : Suppress lines only in file2<br>-3 : Suppress lines common to both | `comm -12 file1.txt file2.txt` | N/A (analysis tool) | Shows differences and overlaps between two datasets |
| pr | Paginates or formats text for printing | +N : Start at page N<br>-l N : Page length in lines<br>-w N : Page width in characters<br>-d : Double-space output<br>-n : Add line numbers | `pr -l 60 report.txt` | N/A (formatting tool) | Useful for preparing documents for printing or review |
| split | Splits large files into smaller chunks | -b SIZE : Split by byte size<br>-l LINES : Split by line count<br>-a NUM : Use NUM suffix digits | `split -b 100M largefile.tar.gz chunk_` | Combine using `cat chunk_* > combinedfile.tar.gz` | Useful when transferring large files through limited-size storage |
| cat (with redirection) | Concatenates and combines files | (No direct specifiers) | `cat chunk_* > combinedfile.tar.gz` | N/A (reversal depends on usage) | Often used with `split` to reassemble large archives |
| od (octal dump) | Dumps files in octal, hex, or other formats | -x : Hexadecimal two-byte display<br>-b : Octal byte display<br>-c : Character display with C-style escapes<br>-t : Custom output format | `od -c file.txt` | Depends on what was analyzed | Useful for inspecting binary files or debugging raw data |
| hexdump | Displays or converts files to hexadecimal dump | -C : Canonical hex+ASCII display<br>-x : Two-byte hexadecimal display<br>-b : One-byte octal display<br>-n LENGTH : Limit dump to N bytes<br>-s OFFSET : Skip N bytes before dumping | `hexdump -C binary.bin` | Reconstruct using `xxd -r` or manual conversion | Detailed view of binary structures and file formats |
| iconv | Converts text between different character encodings | -f : From encoding<br>-t : To encoding<br>-o : Output file<br>--list : Show supported encodings | `iconv -f latin1 -t utf8 file.txt -o newfile.txt` | Convert back using same command with reversed encodings | Essential for fixing encoding issues or preparing data for export |
| recode | Converts file content to different character set | (Use encoding syntax like `utf-8..latin1`) | `recode utf-8..latin1 file.txt` | Convert back using same command with reversed encodings | Older alternative to `iconv`, still widely available |
| fold | Wraps text to fit a specified width | -w N : Wrap at N characters<br>-s : Break at spaces<br>-b : Count bytes instead of columns | `fold -w 80 longline.txt` | Unfold using `tr -d '\n'` or similar tools | Helps format plain text to fixed-width displays or terminals |
| dos2unix | Converts Windows/DOS text files to Unix format | -n : Convert file and write to new file<br>-u : Force Unix to DOS conversion<br>-q : Quiet mode<br>-b : Make backup before conversion | `dos2unix file.txt` | Convert back using `unix2dos` | Removes carriage return (`\r`) characters from Windows files |
| unix2dos | Converts Unix text files to Windows/DOS format | -n : Convert file and write to new file<br>-d : Convert line breaks only<br>-q : Quiet mode<br>-b : Make backup before conversion | `unix2dos file.txt` | Convert back using `dos2unix` | Adds carriage return (`\r`) characters for Windows compatibility |
| file | Determines file type | -b : Brief output<br>-L : Follow symlinks<br>-z : Try decompressing compressed files<br>--mime : Output MIME type | `file image.jpg` | N/A (informational) | Identifies file types beyond extension, including ASCII, binary, archive, etc. |
| strings | Extracts printable strings from binary files | -n N : Minimum string length<br>-f : Show filename before strings<br>-o : Print offset in file | `strings binary.exe` | N/A (extraction tool only) | Useful for analyzing compiled binaries or core dumps |
| od | Dumps files in octal, hex, or other formats | -x : Hexadecimal two-byte display<br>-b : Octal byte display<br>-c : Character display with C-style escapes<br>-t : Custom output format | `od -c file.txt` | Depends on what was analyzed | Useful for inspecting binary files or debugging raw data |
| base64 | Encodes/decodes files in Base64 format | -d : Decode<br>--wrap=N : Set line wrapping limit<br>--ignore-garbage : When decoding, ignore invalid characters | `base64 file.txt > encoded.b64`<br>`base64 -d encoded.b64 > decoded.txt` | Decode using `base64 -d` | Useful for embedding binary in text protocols (JSON, XML, etc.) |
| uuencode/uudecode | Legacy Base64-like encoding and decoding | (Pass input/output file paths) | `uuencode file.txt file.txt > encoded.uu`<br>`uudecode encoded.uu` | Decode with `uudecode` | Older than base64; found in legacy systems |
| hd | Hex dump utility | -n : Stop after N bytes<br>-s : Skip N bytes before dumping<br>-v : Verbose mode<br>--help : Show help | `hd file.bin` | Reconstruct using `xxd -r` or manual conversion | More compact and faster than `hexdump` in some cases |
| cmp | Compares two files byte-by-byte | -l : List differing bytes<br>-n N : Compare only N bytes<br>-i SKIP : Skip initial bytes | `cmp file1.bin file2.bin` | N/A (comparison tool only) | Faster than `diff` for binary files |
| expand | Converts tabs to spaces in files | -t N : Tab stop every N columns<br>--initial : Don’t convert leading tabs<br>-i : Convert only tabs after non-blank characters | `expand -t 4 code.py > code_expanded.py` | Use `unexpand` to revert | Useful for code formatting or standardizing indentation |
| unexpand | Converts spaces to tabs where possible | -t N : Tab stops every N columns<br>--first-only : Convert only leading spaces<br>-a : Convert all spaces | `unexpand -t 4 code_expanded.py > code_tabs.py` | Use `expand` to revert | Useful for reducing file size or preserving tab-based indentation |
| col | Filters reverse line feeds from input | -b : Do not output any backspaces<br>-f : Fine (half-line) movement<br>-p : Pass unknown control sequences<br>-x : Output tabs as spaces | `col < formatted.txt > clean.txt` | N/A (filtering tool) | Useful for cleaning terminal captures and formfeeds |
| colrm | Removes columns from input | [start] [end] : Column range to remove<br>If end not given, removes from start onward | `colrm 10 20 < input.txt` | N/A (column removal tool) | Useful for trimming fixed-width data or logs |
| fmt | Simple text formatter | -w N : Wrap at N characters<br>-s : Split long lines only<br>-u : Uniform spacing<br>-p : Paragraph prefix | `fmt -w 75 essay.txt` | Formatting is irreversible unless original preserved | Good for reflowing paragraphs or adjusting prose layout |
| look | Displays lines beginning with a given string | -b : Binary comparison<br>-f : Ignore case<br>-t DELIM : Set field delimiter | `look "prefix" wordlist.txt` | N/A (search tool) | Fast way to filter dictionary-style files |
| nl | Numbers lines of files | -b : Line numbering mode (a=all, t=non-empty, n=none)<br>-s : Separator between number and text<br>-w : Width of number field | `nl -b a script.sh` | Remove line numbers via `cut` or `sed` | Good for reviewing code or logs with line numbers |
| column | Formats input into multiple columns | -t : Auto-detect table<br>-s : Separator<br>-c : Column width<br>-x : Fill rows before columns | `column -t -s ',' data.csv` | N/A (formatting tool) | Useful for viewing CSVs, logs, and flat tables |
| pr | Paginates or formats text for printing | +N : Start at page N<br>-l N : Page length in lines<br>-w N : Page width in characters<br>-d : Double-space output<br>-n : Add line numbers | `pr -l 60 report.txt` | N/A (formatting tool) | Useful for printing or paginating long documents |
| od | Dumps files in octal, hex, or other formats | -x : Hexadecimal two-byte display<br>-b : Octal byte display<br>-c : Character display with C-style escapes<br>-t : Custom output format | `od -c file.txt` | Depends on what was analyzed | Useful for inspecting binary files or debugging raw data |
| hexdump | Displays or converts files to hexadecimal dump | -C : Canonical hex+ASCII display<br>-x : Two-byte hexadecimal display<br>-b : One-byte octal display<br>-n LENGTH : Limit dump to N bytes<br>-s OFFSET : Skip N bytes before dumping | `hexdump -C binary.bin` | Reconstruct using `xxd -r` or manual conversion | Detailed view of binary structures and file formats |


---



### 🌐 Category 20: Advanced Networking Tools  
*(Based strictly on the content from your pasted file)*

| Command | What It Does | Specifiers | Example | Reversal if Possible | Other Information |
|--------|---------------|------------|---------|----------------------|--------------------|
| tcpdump | Captures and analyzes network packets | -i : Specify interface<br>-w : Write packets to file<br>-r : Read packets from file<br>-n : Don't resolve hostnames<br>-v : Verbose output | `tcpdump -i eth0 -w capture.pcap` | Analyze or stop capture manually | Useful for diagnosing network issues |
| nmap | Scans networks and discovers hosts and services | (No major specifiers listed) | `nmap google.com` | Avoid scanning unauthorized networks | Often used for security auditing and mapping |
| ip | Manages IP addresses, routes, tunnels, etc. | addr : Manage IP addresses<br>link : Manage interfaces<br>route : Manage routing table<br>neigh : ARP table management | `ip addr show`<br>`ip link set eth0 up` | Use inverse commands like `ip link set eth0 down` | Modern replacement for `ifconfig`; supports IPv6 |
| ss | Investigates sockets (like netstat) | -t : TCP connections<br>-u : UDP connections<br>-n : No DNS lookup<br>-l : Listening ports<br>-p : Show process info<br>-a : All sockets | `ss -tulnp` | N/A (diagnostic tool) | Faster and more modern than `netstat` |
| arp | Manipulates the system ARP cache | -a : Display all entries<br>-d : Delete an entry<br>-s : Set an entry | `arp -a` | N/A (informational) | Useful for resolving IP addresses to MAC addresses |
| ethtool | Displays and changes Ethernet device settings | -i : Show driver info<br>-S : Display statistics<br>--speed : Set speed manually<br>--duplex : Set duplex mode<br>--autoneg : Enable/disable auto-negotiation | `ethtool eth0` | Reset with same command using original values | Helps diagnose and configure NIC performance |
| route | Displays and modifies the IP routing table | -n : Show numerical addresses<br>add : Add a route<br>del : Delete a route | `route -n` | Remove route manually | Critical for defining static routes |
| mtr | Combines traceroute and ping in one network diagnostic tool | -r : Report mode<br>-c : Number of pings<br>-i : Interval between pings<br>-n : No DNS resolution | `mtr google.com` | N/A (informational) | Continuously traces path and measures latency |
| nethogs | Monitors network bandwidth usage by process | -d : Delay between updates<br>-p : Show ports | `nethogs` | Exit with Ctrl+C | Great for identifying bandwidth hogs |
| iftop | Displays bandwidth usage on an interface | -i : Specify interface<br>-n : Don't resolve hostnames<br>-P : Show ports | `iftop -i eth0` | Exit with `q` | Shows real-time bandwidth usage per connection |
| dhclient | Acquires an IP address via DHCP | -r : Release lease<br>-v : Verbose mode<br>-nw : No daemonize<br>-pf : PID file location | `dhclient eth0` | Release with `dhclient -r eth0` | Commonly used when bringing up interfaces manually |
| nmcli | Manages network connections (part of NetworkManager) | device wifi connect SSID password PASSWORD : Connect to WiFi<br>connection up/down : Activate/deactivate connection<br>radio wifi on/off : Toggle WiFi radio | `nmcli device wifi connect MyWiFi password mypass` | Disconnect with `nmcli device disconnect wifi` | Used in desktop and mobile Linux environments |
| tracepath | Traces path to destination showing MTU info | (Pass destination as argument) | `tracepath google.com` | N/A (diagnostic tool) | Like `traceroute`, but does not require superuser privileges |
| sslscan | Tests SSL/TLS support on a server | --no-failed : Hide unsupported ciphers<br>--xml=FILE : Export results to XML | `sslscan --no-failed example.com` | N/A (security scanner) | Identifies weak TLS versions and cipher suites |
| openssl s_client | Connects to a TLS server and displays certificate details | -connect HOST:PORT : Target host and port<br>-servername NAME : SNI support | `openssl s_client -connect example.com:443` | N/A (diagnostic tool) | Useful for inspecting certificates and TLS handshake |
| iptraf-ng | Colorful console-based IP LAN monitor | -i IFACE : Interface to monitor<br>-g : General interface stats<br>-d : Dashboard mode | `iptraf-ng -i eth0` | Exit with `q` | Visualizes traffic flows and network activity |
| lsof | Lists open files, including network connections | -i : Show internet connections<br>-P : Show port numbers<br>-n : Don’t resolve hostnames | `lsof -i :80` | Depends on what's connected | Shows which processes are using which ports |
| tshark | CLI version of Wireshark for packet capture | -i INTERFACE : Capture interface<br>-w FILE : Write to file<br>-r FILE : Read from file | `tshark -i eth0 -w capture.pcap` | Analyze capture later or stop capture | Full-featured packet analyzer |
| wireshark | GUI-based packet analyzer | (Run without arguments to start GUI) | `wireshark` | Stop capture manually | Offers deep inspection of network traffic; ideal for advanced debugging |
| tc | Traffic control (QoS and shaping) | qdisc : Manage queuing disciplines<br>class : Manage classes<br>filter : Packet filters<br>rate : Bandwidth limits<br>delay : Add artificial delay | `tc qdisc add dev eth0 root tbf rate 1mbit burst 10kb latency 70ms` | Undo QoS settings manually | Advanced feature for simulating slow links or enforcing bandwidth limits |
| ipset | Manages IP sets for iptables | create : Create new set<br>add/del : Add/remove entries<br>test : Test membership<br>list : Show contents<br>flush : Clear set | `ipset create blacklist hash:ip`<br>`ipset add blacklist 192.16


---

