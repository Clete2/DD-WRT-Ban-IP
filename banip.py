import re
import time
import os
from subprocess import Popen, PIPE
from sets import Set

class BanIPs:
    # Configure this group
    log_filename = "/var/log/cleteRouterSyslog.log"
    router_host = "192.168.1.1"
    do_not_bans = ["192.168.1.", "98.25.7.58", "98.215.114.73"]

    # Settings
    stderr_to_stdout = False
    stdout_to_stdout = False

    # Do not change below this line
    stderr = None if stderr_to_stdout else PIPE
    stdout = None if stdout_to_stdout else PIPE

    ipv4_regex = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    bad_regex = "bad\spassword.*?"

    ssh_command = "/usr/bin/ssh root@"+ router_host
    scp_command = "/usr/bin/scp /tmp/new_firewall.txt root@"+ router_host +":/tmp/new_firewall.txt"

    def ban_ips(self):
        now = time.strftime("%Y-%m-%d %H:%M")

        existing_ips = self.retrieve_existing_ips()

        potential_bad_logins = self.retrieve_potential_bad_logins()

        bad_logins = self.filter_bad_ips(potential_bad_logins, self.do_not_bans)

        ips_to_ban = [x for x in bad_logins if x not in existing_ips]

        if(len(ips_to_ban) == 0):
                print now +" Nothing to do."
                exit(0)
        else:
                print now +" Adding "+ str(len(ips_to_ban)) +" IPs to the ban list."
                print "Banning: "+ str(ips_to_ban)

        iptables_commands = []

        for ip_to_ban in ips_to_ban:
                iptables_commands.append("iptables -I INPUT -s "+ ip_to_ban +" -j DROP")

        current_firewall_popen = Popen(self.ssh_command +" 'nvram get rc_firewall'", shell=True, stdout=PIPE, stderr=self.stderr)

        firewall = current_firewall_popen.stdout.read()

        if(self.stdout_to_stdout):
            print firewall

        firewall = firewall.rstrip()

        for iptables_command in iptables_commands:
                firewall = firewall +"\n"+ iptables_command

        with open("/tmp/new_firewall.txt", "w") as temp_file:
                temp_file.write(firewall)

        Popen(self.scp_command, shell=True, stdout=self.stdout, stderr=self.stderr).communicate()

        Popen(self.ssh_command +" 'nvram set rc_firewall=\"$(cat /tmp/new_firewall.txt)\" && nvram commit && rm /tmp/new_firewall.txt'", shell=True, stdout=self.stdout, stderr=self.stderr).communicate()

        print now +" Updated iptables for next boot. Now updating current iptables."

        for i, iptables_command in enumerate(iptables_commands):
            Popen(self.ssh_command +" '"+ iptables_command +"'", shell=True, stdout=self.stdout, stderr=self.stderr).communicate()
            #print str(i + 1) +" of "+ str(len(iptables_commands)) +" complete."

    def retrieve_existing_ips(self):
        existing_ips = Set()

        firewall_lines = None

        if os.path.isfile("/tmp/new_firewall.txt"):
            with open("/tmp/new_firewall.txt", "r") as file:
                firewall_lines = file.readlines()
        else:
            iptables = Popen(self.ssh_command +" 'nvram get rc_firewall'", shell=True, stdout=PIPE, stderr=self.stderr)

            firewall_lines = iptables.stdout.read().split("\n")

            if(self.stdout_to_stdout):
                print '\n'.join(map(str, firewall_lines))

        for firewall_line in firewall_lines:
            m = re.search(self.ipv4_regex, firewall_line, re.IGNORECASE)
            if(m):
                existing_ips.add(m.group(0))

        return existing_ips

    def retrieve_potential_bad_logins(self):
        potential_bad_logins = Set()

        with open(self.log_filename, "r") as log_file:
            for line in log_file:
                m = re.search(self.bad_regex + self.ipv4_regex, line, re.IGNORECASE)
                if(m):
                    potential_bad_logins.add(m.group(1))

        return potential_bad_logins

    def filter_bad_ips(self, potential_bad_ips, do_not_bans):
        bad_ips = Set()

        for potential_bad_ip in potential_bad_ips:
            if self.is_bad_ip(potential_bad_ip, do_not_bans):
                bad_ips.add(potential_bad_ip)

        return bad_ips

    def is_bad_ip(self, ip, do_not_bans):
        for do_not_ban in do_not_bans:
            if ip.startswith(do_not_ban):
                return False

        return True


ban_ips = BanIPs()
ban_ips.ban_ips()
