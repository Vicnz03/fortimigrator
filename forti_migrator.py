'''
To do
Clean duplicate address and service group
DNAT in policy, disable/remove original lines
Combine policies
'''

import re
import os
from collections import namedtuple
import jinja2
from ipaddress import IPv4Network
from bidictlist import BidirectionaDict

firewall_component = namedtuple('firewall_component', 'name data template')
asa_acl = namedtuple(
    'asa_acl', 'srcintf dstintf srcip srcport dstip dstport action comments status')

re_ip = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
ip = '{} {}'

obj_net_grp = {}
intf = {}
obj_ser_grp = {}
acl_list = {}
ip_pool = {}
snat_list = []
addr_list = {}
service_list = {}
obj_proto_grp = {}
global_nat_src = {}
global_nat_dst = {}
vip_list = {}
bi_vip_list = BidirectionaDict({})
snat_index = 1
access_group = {}
policy_list = []
asa_port = {}

# convert service from name to port NO
# http -> 80


def check_port(port):
    try:
        int(port)
    except:
        port = asa_port[port]

    return port
# check if port exists in service list, if not , add it
# tcp, 80 -> tcp-80


def check_service(proto, port):
    # tcp-udp
    proto = proto.replace(' ', '-')

    # range 1_2
    ports = [check_port(p) for p in port.split('_')]
    # tcp-1_2
    name = proto+'-'+'_'.join(ports)
    if name not in service_list:
        if '-' in proto:
            pro1 = proto.split('-')[0] + '-range ' + '_'.join(ports)
            pro2 = proto.split('-')[1] + '-range ' + '_'.join(ports)
            service_list[name] = pro1 + '\nset ' + pro2
        else:
            service_list[name] = proto + '-range ' + '_'.join(ports)

    return name

# check if addr exists in addr list, if not, add it
# 192.168.1.1 255.255.255.255 -> h-192.168.1.1


def check_addr(addr):
    pre_len = IPv4Network((0, addr.split()[1])).prefixlen
    if pre_len == 32:
        addr_name = 'h-'+addr.split()[0]
    else:
        addr_name = 'n-' + addr.split()[0]+'_' + str(pre_len)

    if addr_name not in addr_list:
        addr_list[addr_name] = addr

    return addr_name


def analyze_acl(srcintf, acl, permit_only=0):
    srcip = dstip = proto = ''
    nat_commnent = ', Natted from {} to {}'
    result = []
    for line in acl:
        lines = line.split()
        action = lines[3]
        comments = line
        srcport = dstport = '0'
        index = 4
        dstport_details = []
        if lines[index] == 'object-group':
            index += 1
            if lines[index] in obj_proto_grp:
                proto = obj_proto_grp[lines[index]]
            elif lines[index] in obj_ser_grp:
                dstport = lines[index]
        else:
            proto = lines[index]
        src_dst = {}
        for key in ['srcip', 'dstip']:
            index += 1
            if lines[index] == 'any':
                src_dst[key] = 'any'
            elif lines[index] == 'host':
                index += 1
                src_dst[key] = check_addr(
                    ip.format(lines[index], '255.255.255.255'))
            elif lines[index] == 'interface':
                index += 1
                src_dst[key] = check_addr(intf[lines[index]]['ip'])
            elif lines[index] == 'object-group':
                index += 1
                src_dst[key] = lines[index]
            elif re_ip.match(lines[index]):
                src_dst[key] = ip.format(lines[index], lines[index+1])
                index += 1
                src_dst[key] = check_addr(src_dst[key])
            else:
                print(lines[index])

        index += 1
        if proto in ['udp', 'tcp'] and index < len(lines):
            dport_type = lines[index]
            if dport_type == 'eq':
                index += 1
                dstport = check_service(proto, lines[index])
                if proto == 'tcp':
                    dstport_details = [dstport]

            elif dport_type == 'object-group':
                index += 1
                dstport = lines[index]
                if dstport in obj_ser_grp:
                    dstport_details = [
                        ser for ser in obj_ser_grp[dstport].split() if ser.startswith('tcp')]
                else:
                    print('Object {} not in group'.format(dstport))

            elif dport_type == 'range':
                p_range = lines[index+1] + '_' + lines[index+2]
                dstport = check_service(proto, p_range)
                if proto == 'tcp':
                    s_port = dstport.split('-')[1].split('_')[0]
                    e_port = dstport.split('_')[1]
                    dstport_details = [
                        'tcp-'+str(x) for x in range(int(s_port), int(e_port))]

        elif dstport == '0':
            dstport = proto.upper()
            dstport_details = 'all'

        orig_status = 'enable'
        nat_status = 'enable'
        if not src_dst['dstip'].startswith('n-') and src_dst['dstip'] != 'any':
            if src_dst['dstip'].startswith('h-'):
                dips = [src_dst['dstip'].split('-')[1]]
                no_change = 1
            else:
                dips = [net for net in obj_net_grp[src_dst['dstip']
                                                   ].split() if net.startswith('h-')]
                no_change = 0

            for dip in dips:
                NAT_target = srcintf+'#'+dip
                if NAT_target in bi_vip_list:
                    nat_dst_intf = nat_dst_ip = ''
                    nat_to = ' '.join(bi_vip_list[NAT_target])
                    for nat_result in bi_vip_list[NAT_target]:
                        nat_dst_intf += ' ' + nat_result.split('#')[0]
                        nat_dst_ip += ' ' + \
                            check_addr(ip.format(nat_result.split(
                                '#')[1], '255.255.255.255'))
                    result.append(asa_acl(srcintf, nat_dst_intf, src_dst['srcip'], srcport, nat_dst_ip,
                                          dstport, action, comments+nat_commnent.format(NAT_target, nat_to), nat_status))
                    orig_status = 'enable' if no_change else 'disable'
                elif dstport_details != 'all':
                    for dport in dstport_details:
                        PAT_target = NAT_target + '#' + dport.split('-')[1]
                        if PAT_target in bi_vip_list:
                            nat_dst_intf = nat_dst_ip = nat_dst_port = ''
                            pat_to = ' '.join(bi_vip_list[PAT_target])
                            for nat_result in bi_vip_list[PAT_target]:
                                nat_dst_intf += ' ' + nat_result.split('#')[0]
                                nat_dst_ip += ' ' + \
                                    check_addr(ip.format(nat_result.split(
                                        '#')[1], '255.255.255.255'))
                                nat_dst_port += ' ' + \
                                    check_service(
                                        'tcp', nat_result.split('#')[2])
                            result.append(asa_acl(srcintf, nat_dst_intf, src_dst['srcip'], srcport, nat_dst_ip,
                                                  nat_dst_port, action, comments+nat_commnent.format(PAT_target, pat_to), nat_status))
                            orig_status = 'disable'
        test = asa_acl(srcintf, 'any', src_dst['srcip'], srcport,
                       src_dst['dstip'], dstport, action, comments, orig_status)
        result.append(test)
    return result


def prebuild(asa_config):
    global snat_index
    objects = []
    re_obj_grp = re.compile('^object-group ')
    re_intf = re.compile('^interface ')
    re_acl = re.compile('^access-list ')
    re_route = re.compile('^route ')
    re_access_group = re.compile('^access-group ')
    re_static_nat = re.compile('^static ')
    re_global_nat_src = re.compile('^nat ')
    re_global_nat_dst = re.compile('^global ')
    re_subline = re.compile('^ ')
    re_end = re.compile('^!')
    intf_start_flag = obj_start_flag = 0

    for line in asa_config:
        lines = line.split()
        if re_intf.match(line):
            if not intf_start_flag:
                intf_start_flag = 1
                intf_name = lines[1]

        if re_obj_grp.match(line):
            if len(objects) != 0:
                if obj_net_flag:
                    obj_net_grp[ser_name] = ' '.join(objects)
                elif obj_ser_flag:
                    obj_ser_grp[ser_name] = ' '.join(objects)
                elif obj_proto_flag:
                    obj_proto_grp[ser_name] = ' '.join(objects)

            obj_start_flag = 1
            obj_ser_flag = obj_net_flag = obj_proto_flag = 0
            ser_name = lines[2]
            objects = []
            if 'object-group protocol' in line:
                obj_proto_flag = 1
            elif ' service ' in line:
                obj_ser_flag = 1
                if len(line.split()) == 4:
                    l4_type = line.split()[3]
                else:
                    l4_type = 'unknow'
            elif ' network ' in line:
                obj_net_flag = 1

        if re_subline.match(line):
            if intf_start_flag:
                if 'nameif' in line:
                    nameif = lines[1]
                elif 'ip address' in line:
                    intf_ip = ip.format(lines[2], lines[3])

            if obj_start_flag:
                if '-object ' in line:
                    if obj_net_flag:
                        if ' host ' in line:
                            obj = lines[2] + ' 255.255.255.255'
                            obj_name = 'h-'+lines[2]
                            if obj_name not in addr_list:
                                addr_list[obj_name] = obj

                        elif ' group-object ' in line:
                            obj_name = lines[1]
                        else:
                            pre_len = IPv4Network((0, lines[2])).prefixlen
                            obj = lines[1]+' '+lines[2]
                            obj_name = 'n-{}_{}'.format(lines[1], pre_len)
                            if obj_name not in addr_list:
                                addr_list[obj_name] = obj

                        objects.append(obj_name)

                    elif obj_ser_flag:
                        if l4_type == 'unknow' and ' service-object ' in line:
                            l4_type_line = lines[1]
                            offset = 1
                        else:
                            l4_type_line = l4_type
                            offset = 0

                        if ' group-object ' in line:
                            obj_name = line.split()[1]
                            objects.append(obj_name)
                        else:
                            for l4 in l4_type_line.split('-'):
                                if ' eq ' in line:
                                    port_no = check_port(lines[2+offset])
                                    obj_name = l4 + '-' + port_no
                                    if obj_name not in service_list:
                                        service_list[obj_name] = l4 + \
                                            '-portrange ' + port_no

                                elif ' range ' in line:
                                    port_no_start = check_port(lines[2+offset])
                                    port_no_end = check_port(lines[3+offset])
                                    obj_name = '{}-{}_{}'.format(
                                        l4, port_no_start, port_no_end)
                                    if obj_name not in service_list:
                                        service_list[obj_name] = '{}-portrange {}-{}'.format(
                                            l4, port_no_start, port_no_end)

                                objects.append(obj_name)

                    elif obj_proto_flag:
                        objects.append(lines[1])

        if re_end.match(line):
            if intf_start_flag:
                intf[nameif] = {
                    'intf_name': intf_name,
                    'ip': intf_ip
                }
                intf_start_flag = 0

        if not re_subline.match(line) and obj_start_flag and not re_obj_grp.match(line):
            obj_start_flag = 0

        if re_acl.match(line):
            if 'remark' not in line:
                acl_name = lines[1]
                if acl_name not in acl_list:
                    acl_list[acl_name] = []
                else:
                    acl_list[acl_name].append(line)

        if re_global_nat_dst.match(line):
            out_intf = lines[1].strip('(').strip(')')
            seq = lines[2]
            if lines[3] == 'interface':
                pool_ip = intf[out_intf]['ip'].split()[0]

            else:
                pool_ip = lines[3]

            pool_name = 'pool_'+pool_ip
            if pool_name not in ip_pool:
                ip_pool[pool_name] = pool_ip

            if seq in global_nat_dst:
                if out_intf in global_nat_dst[seq]:
                    global_nat_dst[seq][out_intf].append(pool_name)
                else:
                    global_nat_dst[seq][out_intf] = [pool_name]

            else:
                global_nat_dst[seq] = {
                    out_intf: [pool_name]
                }

        if re_global_nat_src.match(line):
            in_intf = lines[1].strip('(').strip(')')
            seq = lines[2]
            if lines[3] == 'access-list':
                nat_src = lines[4]
            else:
                nat_src = check_addr(ip.format(lines[3], lines[4]))

            if seq in global_nat_src:
                if in_intf in global_nat_src[seq]:
                    global_nat_src[seq][in_intf].append(nat_src)
                else:
                    global_nat_src[seq][in_intf] = [nat_src]

            else:
                global_nat_src[seq] = {
                    in_intf: [nat_src]
                }

        if re_static_nat.match(line):
            in_intf = lines[1][1:-1].split(',')[0]
            out_intf = lines[1][1:-1].split(',')[1]
            if re_ip.match(lines[2]):
                out_ip = lines[2]
                if re_ip.match(lines[3]):
                    in_ip = lines[3]
                elif lines[3] == 'access-list':
                    in_ip = lines[4]
                nat = 'NAT_{}_{}'.format(in_ip, out_ip)
                portforward = False
                out_port = in_port = 0
                bi_vip_list[out_intf+'#'+out_ip] = in_intf+'#' + in_ip
            else:
                out_ip = lines[3]
                out_port = check_port(lines[4])
                in_ip = lines[5]
                if re_ip.match(lines[5]):
                    in_port = check_port(lines[6])
                else:
                    in_port = '404'
                nat = 'PAT_{}_{}_{}_{}'.format(
                    in_ip, in_port, out_ip, out_port)
                portforward = True
                bi_vip_list[out_intf+'#'+out_ip+'#' +
                            out_port] = in_intf+'#' + in_ip+'#' + in_port
            pool_name = 'static_pool_'+out_ip
            if pool_name not in ip_pool:
                ip_pool[pool_name] = out_ip

            vip_list[nat] = {
                'extintf': out_intf,
                'extip': out_ip,
                'mappedip': in_ip,
                'portforward': portforward,
                'extport': out_port,
                'mappedport': in_port,
                'mappedintf': in_intf
            }

            snat_list.append(
                {
                    'index': str(snat_index),
                    'orig-addr': in_ip,
                    'srcintf': in_intf,
                    'dst-addr': out_ip,
                    'dstintf': out_intf,
                    'nat-ippool': pool_name,
                    'portforward': portforward,
                    'orig-port': in_port,
                    'nat-port': out_port,
                    'disable': False
                }
            )
            snat_index += 1

        if re_route.match(line):
            pass
        if re_access_group.match(line):
            access_group[lines[1]] = {
                'intf': lines[-1],
                'direction': lines[-3]
            }


def build_glb_nat():
    global snat_index
    in_port = out_port = 0
    for seq in global_nat_src:
        for in_intf in global_nat_src[seq]:
            for src in global_nat_src[seq][in_intf]:
                if src.startswith('h-') or src.startswith('n-'):
                    if '0.0.0.0' in src:
                        src = 'any'
                    dstip = 'any'
                    acl_detail = [
                        asa_acl(in_intf, 'any', src, '0', 'any', '0', 'permit', 'SNAT', 'enable')]
                else:
                    acl_detail = analyze_acl(in_intf, acl_list[src])

                for asa in acl_detail:
                    # nat0
                    if seq == '0':
                        snat_list.append({
                            'index': str(snat_index),
                            'orig-addr': asa.srcip,
                            'srcintf': in_intf,
                            'dstintf': 'any',
                            'dst-addr': asa.dstip,
                            'nat-ippool': 'NULL',
                            'disable': True,
                            'portforward': False,
                            'orig-port': in_port,
                            'nat-port': out_port
                        })
                        snat_index += 1

                    elif seq in global_nat_dst:
                        for out_intf in global_nat_dst[seq]:
                            dst = global_nat_dst[seq][out_intf]
                            snat_list.append({
                                'index': str(snat_index),
                                'orig-addr': asa.srcip,
                                'srcintf': in_intf,
                                'dstintf': out_intf,
                                'dst-addr': asa.dstip,
                                'nat-ippool': ' '.join(dst),
                                'disable': False,
                                'portforward': False,
                                'orig-port': in_port,
                                'nat-port': out_port
                            })
                        snat_index += 1


def build_intf_policy():
    policy_index = 1
    for acl in access_group:
        intfs = access_group[acl]['intf']
        direction = access_group[acl]['direction']
        if direction == 'in':
            srcintf = intfs
            dstintf = 'any'
        else:
            dstintf = intfs
            srcintf = 'any'
        label = intfs+'_' + direction
        acl_details = analyze_acl(intfs, acl_list[acl])
        for acl in acl_details:
            policy_list.append({
                'index': policy_index,
                'srcaddr': acl.srcip,
                'srcintf': srcintf,
                'dstaddr': acl.dstip,
                'dstintf': acl.dstintf,
                'service': acl.dstport,
                'action': acl.action,
                'comments': acl.comments,
                'status': acl.status,
                'label': label,
            }
            )
            policy_index += 1


if __name__ == '__main__':
    loader = jinja2.FileSystemLoader(os.getcwd() + '/templates')
    jenv = jinja2.Environment(
        loader=loader, trim_blocks=True, lstrip_blocks=True)
    with open('config-0307.txt', 'r') as f:
        asa_config = [line.strip('\n') for line in f.readlines()]

    with open('asa-ports.txt', 'r') as f:
        ports = f.readlines()
        for port in ports:
            asa_port[port.split()[0]] = port.split()[1]
    prebuild(asa_config)
    build_intf_policy()
    build_glb_nat()
    c_addr = firewall_component('addr', addr_list, 'addr.j2')
    c_service = firewall_component('service', service_list, 'service.j2')
    c_addrgrp = firewall_component('addrgrp', obj_net_grp, 'addr_grp.j2')
    c_sergrp = firewall_component('sergrp', obj_ser_grp, 'service_grp.j2')
    c_ippool = firewall_component('ippool', ip_pool, 'ippool.j2')
    c_vip = firewall_component('vip', vip_list, 'vip.j2')
    c_snat = firewall_component('snat', snat_list, 'snat.j2')
    c_policy = firewall_component('policy', policy_list, 'policy.j2')

    compents = [c_addr, c_service, c_addrgrp,
                c_sergrp, c_ippool, c_vip, c_snat, c_policy]
    for compent in compents:
        file_name = 'forticonvert_{}.txt'.format(compent.name)
        with open(file_name, 'w') as f:
            f.write(jenv.get_template(compent.template).render(
                data=compent.data, vdom='Pegasus'))
