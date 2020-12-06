# Public Mikrotik Rules

`
###########################################################################################################################
#### SynFlood, ICMP Flood, Port Scan, Email Spam Block                                                                 ####
###########################################################################################################################
/ip firewall filter
add action=add-src-to-address-list address-list=Syn_Flooder address-list-timeout=30m chain=input \
comment="Add Syn Flood IP to the list" connection-limit=30,32 disabled=no protocol=tcp tcp-flags=syn
add action=drop chain=input comment="Drop to syn flood list" disabled=no src-address-list=Syn_Flooder
add action=add-src-to-address-list address-list=Port_Scanner address-list-timeout=1w chain=input comment="Port Scanner Detect"\
disabled=no protocol=tcp psd=21,3s,3,1
add action=drop chain=input comment="Drop to port scan list" disabled=no src-address-list=Port_Scanner
add action=jump chain=input comment="Jump for icmp input flow" disabled=no jump-target=ICMP protocol=icmp
add action=drop chain=input\
add action=jump chain=forward comment="Jump for icmp forward flow" disabled=no jump-target=ICMP protocol=icmp
add action=drop chain=forward comment="Drop to bogon list" disabled=no dst-address-list=bogons
add action=add-src-to-address-list address-list=spammers address-list-timeout=3h chain=forward comment="Add Spammers to the list for 3 hours"\
connection-limit=30,32 disabled=no dst-port=25,587 limit=30/1m,0 protocol=tcp
add action=drop chain=forward comment="Avoid spammers action" disabled=no dst-port=25,587 protocol=tcp src-address-list=spammers
add action=accept chain=input comment="Accept DNS - UDP" disabled=no port=53 protocol=udp
add action=accept chain=input comment="Accept DNS - TCP" disabled=no port=53 protocol=tcp
add action=accept chain=input comment="Accept to established connections" connection-state=established\
disabled=no
add action=accept chain=input comment="Accept to related connections" connection-state=related disabled=no
add action=accept chain=input comment="Full access to SUPPORT address list" disabled=no src-address-list=support
add action=accept chain=ICMP comment="Echo request - Avoiding Ping Flood, adjust the limit as needed" disabled=no icmp-options=8:0 limit=2,5 protocol=icmp
add action=accept chain=ICMP comment="Echo reply" disabled=no icmp-options=0:0 protocol=icmp
add action=accept chain=ICMP comment="Time Exceeded" disabled=no icmp-options=11:0 protocol=icmp
add action=accept chain=ICMP comment="Destination unreachable" disabled=no icmp-options=3:0-1 protocol=icmp
add action=accept chain=ICMP comment=PMTUD disabled=no icmp-options=3:4 protocol=icmp
add action=drop chain=ICMP comment="Drop to the other ICMPs" disabled=no protocol=icmp
add action=jump chain=output comment="Jump for icmp output" disabled=no jump-target=ICMP protocol=icmp
###########################################################################################################################
#### Detect & Manage High Connection Rates                                                                             ####
###########################################################################################################################
/ip firewall filter
add action=add-src-to-address-list address-list="(WAN High Connection Rates)" chain=input comment="Add WAN High Connections to Address List" connection-limit=100,32 protocol=tcp
add action=add-src-to-address-list address-list="(LAN High Connection Rates)" chain=forward comment="Add LAN High Connections to Address List" connection-limit=100,32 protocol=tcp
###########################################################################################################################
#### Bos Connect Olası Saldırı ALL Drop Rule                                                                           ####
###########################################################################################################################
/ip firewall filter
add action=accept chain=input connection-state=established
add action=accept chain=input connection-state=related
add action=drop chain=input connection-state=invalid
add action=drop chain=forward comment="TCP flags and Port 0 attacks" protocol=tcp tcp-flags=!fin,!syn,!rst,!ack
add action=drop chain=forward protocol=tcp tcp-flags=fin,syn
add action=drop chain=forward protocol=tcp tcp-flags=fin,rst
add action=drop chain=forward protocol=tcp tcp-flags=fin,!ack
add action=drop chain=forward protocol=tcp tcp-flags=fin,urg
add action=drop chain=forward protocol=tcp tcp-flags=syn,rst
add action=drop chain=forward protocol=tcp tcp-flags=rst,urg
add action=drop chain=forward protocol=tcp src-port=0
add action=drop chain=forward dst-port=0 protocol=tcp
add action=drop chain=forward protocol=udp src-port=0
add action=drop chain=forward dst-port=0 protocol=udp
add action=accept chain=forward connection-state=established
add action=accept chain=forward connection-state=related
add action=drop chain=forward connection-state=invalid
add action=accept chain=output connection-state=established
add action=accept chain=output connection-state=related
add action=drop chain=output connection-state=invalid
/ip firewall address-list
add address=0.0.0.0/8 comment="RFC 1122 \"This host on this network\"" disabled=yes list=bogons
add address=10.0.0.0/8 comment="RFC 1918 (Private Use IP Space)" disabled=no list=bogons
add address=100.64.0.0/10 comment="RFC 6598 (Shared Address Space)" disabled=no list=bogons
add address=127.0.0.0/8 comment="RFC 1122 (Loopback)" disabled=no list=bogons
add address=169.254.0.0/16 comment="RFC 3927 (Dynamic Configuration of IPv4 Link-Local Addresses)" disabled=no list=bogons
add address=172.16.0.0/12 comment="RFC 1918 (Private Use IP Space)" disabled=no list=bogons
add address=192.0.0.0/24 comment="RFC 6890 (IETF Protocol Assingments)" disabled=no list=bogons
add address=192.0.2.0/24 comment="RFC 5737 (Test-Net-1)" disabled=no list=bogons
add address=192.168.0.0/16 comment="RFC 1918 (Private Use IP Space)" disabled=no list=bogons
add address=198.18.0.0/15 comment="RFC 2544 (Benchmarking)" disabled=no list=bogons
add address=198.51.100.0/24 comment="RFC 5737 (Test-Net-2)" disabled=no list=bogons
add address=203.0.113.0/24 comment="RFC 5737 (Test-Net-3)" disabled=no list=bogons
add address=224.0.0.0/4 comment="RFC 5771 (Multicast Addresses) - Will affect OSPF, RIP, PIM, VRRP, IS-IS, and others. Use with caution.)" disabled=yes list=bogons
add address=240.0.0.0/4 comment="RFC 1112 (Reserved)" disabled=no list=bogons
add address=192.31.196.0/24 comment="RFC 7535 (AS112-v4)" disabled=no list=bogons
add address=192.52.193.0/24 comment="RFC 7450 (AMT)" disabled=no list=bogons
add address=192.88.99.0/24 comment="RFC 7526 (Deprecated (6to4 Relay Anycast))" disabled=no list=bogons
add address=192.175.48.0/24 comment="RFC 7534 (Direct Delegation AS112 Service)" disabled=no list=bogons
add address=255.255.255.255 comment="RFC 919 (Limited Broadcast)" disabled=no list=bogons

add list=local-addr address=192.168.0.0/16 comment="my local network, all NATed"

######################################################################
# Setup NAT

/ip firewall nat

# Setup srcnat
add chain=srcnat action=masquerade out-interface=WAN

# Setup dstnat
add chain=dstnat in-interface=WAN dst-port=8000 action=dst-nat protocol=tcp to-addresses=192.168.50.200 to-ports=8000

######################################################################
# Setup firewall rules

/ip firewall mangle
add chain=prerouting in-interface=WAN dst-address-list=local-addr action=mark-packet new-packet-mark=nat-traversal passthrough=no comment="Detect NAT Traversal"

/ip firewall filter 

add chain=output connection-state=established action=accept comment="Allow established connections"
add chain=output connection-state=related action=accept comment="Allow related connections"
add chain=output connection-state=invalid action=jump jump-target=drop comment="Drop invalid connections"

add chain=forward action=jump jump-target=sanity-check comment="Sanity Check Forward"
add chain=sanity-check packet-mark=nat-traversal action=jump jump-target=drop comment="Deny illegal NAT traversal"
add chain=sanity-check protocol=tcp psd=20,3s,3,1 action=add-src-to-address-list address-list=blocked-addr address-list-timeout=1d disabled=yes comment="Block port scans"
add chain=sanity-check protocol=tcp tcp-flags=fin,psh,urg,!syn,!rst,!ack action=add-src-to-address-list address-list=blocked-addr address-list-timeout=1d comment="Block TCP Null scan"
add chain=sanity-check protocol=tcp tcp-flags=!fin,!syn,!rst,!psh,!ack,!urg action=add-src-to-address-list address-list=blocked-addr address-list-timeout=1d comment="Block TCP Xmas scan"
add chain=sanity-check protocol=tcp tcp-flags=!fin,!syn,!rst,!ack action=jump jump-target=drop comment="TCP flags and Port 0 attacks"
add chain=sanity-check protocol=tcp src-address-list=blocked-addr action=jump jump-target=drop comment="Drop addresses from blocked-addr list"
add chain=sanity-check protocol=tcp tcp-flags=fin,syn action=jump jump-target=drop comment="Drop TCP SYN+FIN"
add chain=sanity-check protocol=tcp tcp-flags=fin,rst action=jump jump-target=drop comment="Drop TCP FIN+RST"
add chain=sanity-check protocol=tcp tcp-flags=fin,!ack action=jump jump-target=drop comment="Drop TCP FIN+!ACK"
add chain=sanity-check protocol=tcp tcp-flags=fin,urg action=jump jump-target=drop comment="Drop TCP FIN+URG"
add chain=sanity-check protocol=tcp tcp-flags=syn,rst action=jump jump-target=drop comment="Drop TCP SYN+RST"
add chain=sanity-check protocol=tcp tcp-flags=rst,urg action=jump jump-target=drop comment="Drop TCP RST+URG"
add chain=sanity-check protocol=tcp src-port=0 action=jump jump-target=drop comment="Drop port 0 src,TCP"
add chain=sanity-check protocol=tcp dst-port=0 action=jump jump-target=drop comment="Drop port 0 dst,TCP"
add chain=sanity-check protocol=udp src-port=0 action=jump jump-target=drop comment="Drop port 0 src,UDP"
add chain=sanity-check protocol=udp dst-port=0 action=jump jump-target=drop comment="Drop port 0 src,UDP"
add chain=sanity-check connection-state=invalid action=jump jump-target=drop comment="Dropping invalid connections at once"
add chain=sanity-check connection-state=established action=accept comment="Accepting already established connections"
add chain=sanity-check connection-state=related action=accept comment="Also accepting related connections"
add chain=sanity-check dst-address-type=broadcast,multicast action=jump jump-target=drop comment="Drop all traffic that goes to multicast or broadcast addresses"
add chain=sanity-check in-interface=LANbridge dst-address-list=bogons dst-address-type=!local action=jump jump-target=drop comment="Drop illegal destination addresses"
add chain=sanity-check in-interface=LANbridge src-address-list=!local-addr action=jump jump-target=drop comment="Drop everything that goes from local interface but not from local address"
add chain=sanity-check in-interface=WAN src-address-list=bogons action=jump jump-target=drop comment="Drop illegal source addresses"
add chain=sanity-check src-address-type=broadcast,multicast action=jump jump-target=drop comment="Drop all traffic that comes from multicast or broadcast addresses"

add chain=input src-address-type=local dst-address-type=local action=accept comment="Allow local traffic (between router applications)"
add chain=input in-interface=LANbridge dst-address=255.255.255.255 dst-port=5678 protocol=udp action=accept comment="Allow The Router to be visible via Neighbor Discovery to WinBox"
add chain=input action=jump jump-target=sanity-check comment="Sanity Check"
add chain=input dst-address-type=!local action=jump jump-target=drop comment="Dropping packets not destined to the router itself, including all broadcast traffic"
add chain=input protocol=icmp icmp-options=8:0-255 limit=5,5 action=accept comment="Allow pings, but at a very limited rate (5 packets per sec)"
add chain=input in-interface=LANbridge action=jump jump-target=local-services comment="Allowing some services to be accessible from the local network"
add chain=input in-interface=WAN action=jump jump-target=public-services comment="Allowing some services to be accessible from the Internet"
add chain=input action=jump jump-target=drop comment="jump -> drop"

add chain=local-services protocol=tcp dst-port=22 action=accept comment="SSH (22/TCP)"
add chain=local-services protocol=udp dst-port=53 action=accept comment="DNS"
add chain=local-services protocol=tcp dst-port=53 action=accept comment="DNS"
add chain=local-services protocol=tcp dst-port=8844 action=accept disabled=no comment="Winbox (8844/TCP)"

add chain=local-services action=accept disabled=no dst-port=123 protocol=udp comment=NTP
add chain=local-services action=accept disabled=no dst-port=5678 protocol=udp comment="Neighbor discovery"
add chain=local-services action=log disabled=no comment="Temporary logging to check for things we should not drop"
add chain=local-services action=drop disabled=yes comment="DROP EVERYTHING | check twice before enabling this"

add chain=public-services protocol=tcp dst-port=8000 action=accept disabled=no comment="DVR/NVR"
add chain=public-services protocol=tcp dst-port=8844 action=accept disabled=no comment="Winbox (8844/TCP)"
add chain=public-services action=log  disabled=no comment="Temporary logging to check for things we should not drop"
add chain=public-services action=drop disabled=yes comment="DROP EVERYTHING | check the log twice before enabling this"

add chain=drop action=log disabled=no comment="Temporary logging if we need to see what is actually dropped"
add chain=drop action=drop disabled=yes comment="DROP EVERYTHING | check the log twice before enabling this"


`
