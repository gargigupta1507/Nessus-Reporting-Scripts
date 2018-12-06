#!/bin/bash

cat <<EOF > fixports.rb
ips = \`cat #{ARGV[0]} | sort -u -V\`
ips = ips.split("\n")
singleIPlines = {}
def getIP line
  return line.split(' ')[0]
end
lines = []
ips.each do |line|
  if singleIPlines.key?(getIP(line) )
    singleIPlines[getIP(line)] = singleIPlines[getIP(line)].split(')')[0] + ',' + line.split('TCP ')[1]
  else
    singleIPlines[getIP(line)] = line
  end
end
singleIPlines.each do |ip, line|
  puts " - " + line
end
EOF

function xml_extract(){
    if [ -z "$3" ]; then echo "$1"; else echo "$3"; fi
    if [ -z "$2" ]; 
        then 
            for f in *.nessus; do cat $f | tr -d '\n'  | tr -d '\r' | xmlstarlet sel --noblanks -T -t -m "//ReportItem[contains(@pluginName, '$1')]" -v 'ancestor::ReportHost/@name' -o ' (TCP ' -v './@port' -o ')' -n;  done | ruby fixports.rb;
        else
            for f in *.nessus; do cat $f | tr -d '\n'  | tr -d '\r' | xmlstarlet sel --noblanks -T -t -m "//ReportItem[contains(@pluginName, '$1')]" -v 'ancestor::ReportHost/@name' -o ' (TCP ' -v './@port' -o ')' -o ';' -v './plugin_output' -n;  done | sh -c "$2" | cut -d ';' -f 1 | ruby fixports.rb;
        fi
}

xml_extract "Terminal Services Encryption Level is Medium"
xml_extract "Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness"
xml_extract "Use Network Level Authentication (NLA) Only" "grep ''" "Terminal Services Doesn't Use Network Level Authentication (NLA) Only"
xml_extract "SMB Signing Disabled" 
xml_extract "Server Message Block (SMB) Protocol Version 1 Enabled" 
xml_extract "Microsoft Windows SMB NULL Session Authentication"
xml_extract "Samba Badlock Vulnerability" 
xml_extract "SSH Weak MAC Algorithms Enabled"
xml_extract "SSH Server CBC Mode Ciphers Enabled"
xml_extract "SSH Weak Algorithms Supported"
xml_extract "SSH Protocol Version 1 Session Key Retrieval"
xml_extract "OpenSSH MaxAuthTries Bypass"
xml_extract "PHP expose_php Information Disclosure"
xml_extract "Web Application Potentially Vulnerable to Clickjacking"
xml_extract "Browsable Web Directories"
xml_extract "Apache Multiviews Arbitrary Directory Listing"
xml_extract "NFS Shares World Readable"
xml_extract "LDAP Crafted Search Request Server Information Disclosure"
xml_extract "Network Time Protocol Daemon (ntpd) monlist Command Enabled DoS"
xml_extract "DNS Server Cache Snooping Remote Information Disclosure"

echo "[+] Unencrypted connection"
xml_extract "Unencrypted Telnet Server"
xml_extract "Web Server Transmits Cleartext Credentials"
xml_extract "Web Server Uses Basic Authentication over HTTPS"
xml_extract "VNC Server Unencrypted Communication Detection"
xml_extract "FTP Server Detection"
xml_extract "LDAP Server Detection"
xml_extract "X Display Manager Control Protocol (XDMCP) Detection"

echo "[+] Insecure SSL configuration"
xml_extract "SSL Anonymous Cipher Suites Supported"
xml_extract "SSL RC4 Cipher Suites Supported"
xml_extract "SSL 64-bit Block Size Cipher Suites Supported (SWEET32)"
xml_extract "SSL / TLS Versions Supported" "grep SSLv2" "SSLv2 ciphers supported"
xml_extract "SSL / TLS Versions Supported" "grep SSLv3" "SSLv3 ciphers supported"
xml_extract "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)"
xml_extract "SSL / TLS Versions Supported" "grep -v 'TLSv1.2'" "No TLS1.2 support"
xml_extract "SSL Cipher Suites Supported" "grep export" "Export ciphers supported"
xml_extract "SSL Cipher Suites Supported" "grep -E 'Low Strength Cipher|Medium Strength Cipher'" "Weak strength ciphers supported"
xml_extract "Transport Layer Security (TLS) Protocol CRIME Vulnerability"
xml_extract "SSL/TLS EXPORT_RSA <= 512-bit Cipher" "" "Vulnerable to FREAK"
xml_extract "SSL DROWN Attack Vulnerability"
xml_extract "SSL Null Cipher"
xml_extract "SSL Certificate Chain Contains RSA Keys Less Than" "" "SSL Certificate Chain Contains Weak RSA Keys"
xml_extract "SSL / TLS Renegotiation Handshakes" "" "Insecure renegotiation"
xml_extract "OpenSSL SSL_OP_NETSCAPE_REUSE_CIPHER" "" "Insecure session resumption"
xml_extract "SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)" "" "Vulnerable to Logjam"

echo "[+] Weaknesses in SSL certificate"
xml_extract "SSL Certificate Cannot Be Trusted" "grep 'signed by an unknown'"
xml_extract "SSL Certificate Expiry"
xml_extract "SSL Self-Signed Certificate"
xml_extract "SSL Certificate Signed Using Weak Hashing Algorithm" "grep 'MD5 With'" "SSL Certificate signed with MD5"
xml_extract "SSL Certificate Signed Using Weak Hashing Algorithm" "grep 'SHA-1 With'" "SSL Certificate signed with SHA1"
xml_extract "SSL Certificate with Wrong Hostname"
xml_extract "SSL Certificate Information" "grep 'Common Name: *.d'" "Wildcard SSL Certificates"

