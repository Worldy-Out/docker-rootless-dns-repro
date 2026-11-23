"""Closed CP/DP-A policy. Rendering never performs network or service actions.

The kernel lease controls all measured VPN traffic, including established flows.
This containment mechanism is deliberately not called selective user revocation.
"""
import copy
import ipaddress
import json
import re

ROLES={
    'cp':{'uid':1001,'ip':'11.77.0.5','peer':'11.77.0.1','management':'192.0.2.1','remote':'192.0.2.2'},
    'dp-a':{'uid':1002,'ip':'11.77.0.1','peer':'11.77.0.5','management':'192.0.2.2','remote':'192.0.2.1'},
}
TABLE='uzel_operational'
INTERFACE='wg-uzel-op'
WIREGUARD_UPLINK='ens3'
WIREGUARD_FWMARK='0x555a454c'
VPN_PORTS=[443,8443,9443]
MANAGEMENT_PORT=2222
STANDBY_AUTHORITY_PORT=2223
STANDBY_SERVICE='uzel-standby.service'
LOCAL_DNS_RESOLVER='127.0.0.53'
MAX_TEST_WINDOW_SECONDS=3600


def require(ok,message):
    if not ok:raise ValueError(message)


def public_ipv4(value):
    require(isinstance(value,str),'IPv4 must be a string')
    ip=ipaddress.ip_address(value)
    require(ip.version==4 and ip.is_global and not ip.is_multicast and str(ip)==value,'Canonical global IPv4 required')
    return value


def validate(policy):
    fields={
        'schema','scope','role','epoch','sourceIPv4s','egress','leaseSeconds','publicPorts',
        'wireguardPublicKey','wireguardPeerPublicKey','runtimeUnitSha256'}
    require(isinstance(policy,dict) and fields<=set(policy)<=fields|{'dnsResolver','testWindowMaxSeconds','standbyService'},
            'Unexpected policy fields')
    require(type(policy['schema']) is int and policy['schema']==1 and policy['scope']=='CP_DP_A_CLOSED_OPERATIONAL','Wrong scope')
    require(policy['role'] in ROLES and re.fullmatch('[a-f0-9]{32}',policy['epoch'] or ''),'Role/epoch invalid')
    require(type(policy['leaseSeconds']) is int and 30<=policy['leaseSeconds']<=120,'Kernel lease exceeds closed-test bound')
    require(policy['publicPorts']==VPN_PORTS or policy['role']=='dp-a' and policy['publicPorts']==[443],
            'Only the retained transports or the RAW-only DP-A scope are permitted')
    if 'dnsResolver' in policy:
        require(policy['role']=='dp-a' and policy['publicPorts']==[443] and
                policy['dnsResolver']==LOCAL_DNS_RESOLVER,
                'DNS requires the confirmed DP-A RAW systemd-resolved stub')
    sources=policy['sourceIPv4s']
    require(isinstance(sources,list) and 1<=len(sources)<=4 and len(set(sources))==len(sources),'Bounded distinct test sources required')
    for value in sources:
        public_ipv4(value);require(value not in {r['ip'] for r in ROLES.values()},'Test source must be external')
    if 'testWindowMaxSeconds' in policy:
        require(policy['role']=='dp-a' and policy['publicPorts']==[443] and
                policy.get('dnsResolver')==LOCAL_DNS_RESOLVER and len(sources)==1 and
                type(policy['testWindowMaxSeconds']) is int and
                policy['leaseSeconds']<=policy['testWindowMaxSeconds']<=MAX_TEST_WINDOW_SECONDS,
                'Test window requires one IPv4, RAW TCP/443 and a bounded deadline')
    if 'standbyService' in policy:
        require(policy['standbyService']==STANDBY_SERVICE and
                (policy['role']=='cp' or 'testWindowMaxSeconds' in policy),
                'Standby policy must bind the fixed service and the DP-A deadline')
    destinations=policy['egress']
    require(isinstance(destinations,list) and len(destinations)<=16,'Too many egress destinations')
    seen=set()
    for row in destinations:
        require(isinstance(row,dict) and set(row)=={'ipv4','tcpPorts','purpose'},'Invalid egress row')
        ip=public_ipv4(row['ipv4'])
        require(ip not in {r['ip'] for r in ROLES.values()} and ip not in sources and ip not in seen,'Overlapping/duplicate egress destination')
        seen.add(ip)
        require(row['tcpPorts']==[443] and row['purpose'] in ['nonce','reality','acme','offsite','alerts'],'Only named HTTPS egress purposes allowed')
        require(policy['role']=='cp' or row['purpose'] in ['nonce','reality'],'DP has no control-plane egress')
    for key in ['wireguardPublicKey','wireguardPeerPublicKey']:
        require(isinstance(policy[key],str) and re.fullmatch('[A-Za-z0-9+/]{43}=',policy[key]),'WireGuard public identity malformed')
    require(policy['wireguardPublicKey']!=policy['wireguardPeerPublicKey'],'WireGuard identities overlap')
    require(isinstance(policy['runtimeUnitSha256'],str) and re.fullmatch('[a-f0-9]{64}',policy['runtimeUnitSha256']),'Runtime unit binding missing')
    return policy


def nft_rules(policy):
    p=validate(policy);r=ROLES[p['role']];ports=', '.join(map(str,VPN_PORTS))
    allowed_ports=', '.join(map(str,p['publicPorts']))
    node_in=(f'    iifname "{INTERFACE}" ip saddr {r["remote"]} ip daddr {r["management"]} tcp dport 2222 accept\n'
             if p['role']=='dp-a' else '')
    node_out=(f'    oifname "{INTERFACE}" ip daddr {r["remote"]} tcp dport 2222 accept\n'
              if p['role']=='cp' else
              f'    oifname "{INTERFACE}" ip saddr {r["management"]} ip daddr {r["remote"]} tcp sport 2222 accept\n')
    standby_in=standby_out=''
    if 'standbyService' in p:
        peer=f'ip saddr {r["remote"]} ip daddr {r["management"]}'
        own=f'ip saddr {r["management"]} ip daddr {r["remote"]}'
        direction='dport' if p['role']=='cp' else 'sport'
        reverse='sport' if p['role']=='cp' else 'dport'
        standby_in=(f'    iifname "{INTERFACE}" {peer} tcp {direction} {STANDBY_AUTHORITY_PORT} accept\n'
                    f'    tcp dport {STANDBY_AUTHORITY_PORT} drop\n')
        standby_out=f'    oifname "{INTERFACE}" {own} tcp {reverse} {STANDBY_AUTHORITY_PORT} accept\n'
    vpn_in=(f'    ip saddr @live_sources ip daddr {r["ip"]} tcp dport {{ {allowed_ports} }} accept\n' if p['role']=='dp-a' else '')
    vpn_out=(f'    ip saddr {r["ip"]} ip daddr @live_sources tcp sport {{ {allowed_ports} }} accept\n'
             f'    tcp sport {{ {ports} }} drop\n' if p['role']=='dp-a' else '')
    egress=''.join(f'    ip daddr {d["ipv4"]} tcp dport 443 accept\n' for d in p['egress'])
    # slirp4netns forwards Docker's embedded DNS to the host stub. Keep the
    # allowance inside the runtime UID chain and scoped to the lo DNS socket.
    dns_out=(f'    oifname "lo" ip saddr 127.0.0.1 ip daddr {p["dnsResolver"]} '
             'meta l4proto { tcp, udp } th dport 53 counter accept\n'
             if 'dnsResolver' in p else '')
    # Encrypted WireGuard UDP can retain the original application's socket UID.
    wireguard_out=(f'    oifname "{WIREGUARD_UPLINK}" meta mark {WIREGUARD_FWMARK} '
                   f'ip saddr {r["ip"]} ip daddr {r["peer"]} udp sport 51820 udp dport 51820 counter accept\n')
    # VPN rules precede established acceptance in BOTH directions. An expired
    # kernel set element must not be bypassed by an already accepted connection.
    return f'''table inet {TABLE} {{
  comment "uzel-epoch-{p['epoch']}"
  set live_sources {{ type ipv4_addr; flags timeout; timeout {p['leaseSeconds']}s; }}
  chain input {{
    type filter hook input priority -20; policy accept;
    iifname "lo" accept
    ip saddr {r['peer']} ip daddr {r['ip']} udp dport 51820 accept
    udp dport 51820 drop
{node_in}{standby_in}    tcp dport 2222 drop
{vpn_in}    tcp dport {{ {ports} }} drop
    udp dport {{ {ports}, 2222 }} drop
    tcp dport {{ 2019, 3000, 3001, 5432, 6379, 8080, 8090 }} drop
  }}
  chain output {{
    type filter hook output priority -20; policy accept;
{vpn_out}    meta skuid {r['uid']} jump runtime_egress
  }}
  chain runtime_egress {{
    tcp sport 22 ct state established accept
{wireguard_out}{node_out}{standby_out}{egress}{dns_out}    reject with icmpx type admin-prohibited
  }}
}}
'''


def lease_transaction(policy,enable,*,seconds=None):
    p=validate(policy)
    require(p['role']=='dp-a','Only DP-A has a test-traffic lease')
    text=f'flush set inet {TABLE} live_sources\n'
    require(not enable or ('testWindowMaxSeconds' in p)==(seconds is not None),
            'Window policy requires an explicit kernel element lifetime')
    require(seconds is None or enable and 'testWindowMaxSeconds' in p and
            type(seconds) is int and 30<=seconds<=p['leaseSeconds'],'Invalid kernel element lifetime')
    if enable:
        timeout=p['leaseSeconds'] if seconds is None else seconds
        elements=', '.join(f'{ip} timeout {timeout}s' for ip in p['sourceIPv4s'])
        text+=f'add element inet {TABLE} live_sources {{ {elements} }}\n'
    return text


def stable_table(value,policy):
    """Discard counters/handles and validated expiring elements, not policy.

    This is an identity comparison to a captured empty-set baseline, not an
    authorization validator for arbitrary nft JSON.
    """
    p=validate(policy)

    def lease_set(item):
        require(isinstance(item,dict) and item.get('family')=='inet' and item.get('table')==TABLE and
                item.get('name')=='live_sources','Foreign set')
        require(item.get('type')=='ipv4_addr' and item.get('flags')==['timeout'] and
                type(item.get('timeout')) is int and item['timeout']==p['leaseSeconds'],'Unbounded set timeout')
        elements=item.get('elem',[])
        require(isinstance(elements,list),'Unexpected leased elements')
        seen=set()
        for entry in elements:
            require(isinstance(entry,dict) and set(entry)=={'elem'},'Unexpected leased element')
            e=entry['elem']
            require(isinstance(e,dict) and set(e)<= {'val','timeout','expires'} and
                    e.get('val') in p['sourceIPv4s'],'Foreign leased source')
            require(e['val'] not in seen,'Duplicate leased source');seen.add(e['val'])
            # libnftables JSON uses seconds and omits the inherited timeout.
            timeout=e.get('timeout',item['timeout'])
            require(type(timeout) is int and 0<timeout<=p['leaseSeconds'],'Unbounded element timeout')
            require(type(e.get('expires')) is int and 0<=e['expires']<=timeout,'Invalid remaining lease')
        return {k:v for k,v in item.items() if k!='elem'}

    def clean(obj):
        if isinstance(obj,list):return [clean(x) for x in obj]
        if not isinstance(obj,dict):return obj
        # A nested {"set": [...]} is part of a rule, including every port.
        if set(obj)=={'set'} and isinstance(obj['set'],list):return copy.deepcopy(obj)
        if set(obj)=={'counter'} and isinstance(obj['counter'],dict):
            require(set(obj['counter'])=={'packets','bytes'},'Unexpected counter expression')
            require(all(type(v) is int and v>=0 for v in obj['counter'].values()),'Invalid counter values')
            return {'counter':{'packets':0,'bytes':0}}
        return {k:clean(v) for k,v in obj.items() if k!='handle'}

    require(isinstance(value,dict) and set(value)=={'nftables'} and isinstance(value['nftables'],list),
            'Missing table snapshot')
    rows=[]
    for row in value['nftables']:
        require(isinstance(row,dict) and len(row)==1,'Malformed table row')
        if 'metainfo' in row:continue
        # Only a top-level set declaration is the expiring kernel lease.
        rows.append(clean({'set':lease_set(row['set'])} if 'set' in row else row))
    require(sum('set' in row for row in rows)==1,'Missing or duplicate lease set')
    tables=[row['table'] for row in rows if 'table' in row]
    require(len(tables)==1 and isinstance(tables[0],dict) and tables[0].get('family')=='inet' and tables[0].get('name')==TABLE and
            tables[0].get('comment')=='uzel-epoch-'+p['epoch'],'Table ownership marker differs')
    return {'nftables':rows}


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
