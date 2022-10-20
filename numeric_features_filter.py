from bs4 import BeautifulSoup

import requests

# ['arp', 'coap', 'data', 'data-text-lines', 'dhcp', 'dns', 'eth', 'ethertype', 'http', 'icmp', 'ip', 'llc', 'pkix1explicit', 'pkix1implicit', 'tcp', 'tls', 'udp', 'x509ce', 'x509sat']



protocol_urls = {
    "tcp":"https://www.wireshark.org/docs/dfref/t/tcp.html",
    "tls" : "https://www.wireshark.org/docs/dfref/t/tls.html", 
    "arp" : "https://www.wireshark.org/docs/dfref/a/arp.html", 
    "dhcp" : "https://www.wireshark.org/docs/dfref/d/dhcp.html",
    "coap" : "https://www.wireshark.org/docs/dfref/c/coap.html",
    "data" : "https://www.wireshark.org/docs/dfref/d/data.html",
    "dns" : "https://www.wireshark.org/docs/dfref/d/dns.html",
    "eth" : "https://www.wireshark.org/docs/dfref/e/eth.html",
    "http" : "https://www.wireshark.org/docs/dfref/h/http.html",
    "icmp" : "https://www.wireshark.org/docs/dfref/i/icmp.html",
    "ip" : "https://www.wireshark.org/docs/dfref/i/ip.html",
    "llc" : "https://www.wireshark.org/docs/dfref/l/llc.html",
    "pkix1explicit" : "https://www.wireshark.org/docs/dfref/p/pkix1explicit.html",
    "pkix1implicit" : "https://www.wireshark.org/docs/dfref/p/pkix1implicit.html",
    "udp" : "https://www.wireshark.org/docs/dfref/u/udp.html",
    "x509ce" : "https://www.wireshark.org/docs/dfref/x/x509ce.html",
    "x509sat" : "https://www.wireshark.org/docs/dfref/x/x509sat.html",
}

def get_numeric_features(protocol_name):
    features = []
    url = protocol_urls[protocol_name]
    r = requests.get(url)

    soup = BeautifulSoup(r.text, 'html.parser')

    rows = soup.find("table", {"class":'table table-condensed table-greenbar'}).find_all('tr')

    for row in rows:
        cells = row.find_all('td')
        try:
            if "integer" in cells[2].get_text():
                features.append(cells[0].get_text())
        except:
            pass
    
    return features


def get_tshark_valid_tcp_protocol_feature_list():
    features = get_numeric_features('tcp')
    
    unsed = ["tcp.options.timestamp.tsval.syncookie.sack",
            "tcp.options.timestamp.tsval.syncookie.ecn",
            "tcp.options.time_stamp",
            "tcp.options.tarr.rate",
            "tcp.options.tar.reserved",
            "tcp.options.scpsflags.reserved3",
            "tcp.options.scpsflags.reserved2",
            "tcp.options.scpsflags.reserved1",
            "tcp.options.rvbd.probe.len",
            "tcp.options.mptcp.sendtruncmac",
            "tcp.options.mptcp.sendmac",
            "tcp.options.mptcp.dataseqno",
            "tcp.options.mptcp.dataack",
            "tcp.options.mood_val",
            "tcp.options.mood",
            "tcp.options.experimental.exid",
            "tcp.options.echo_reply",
            "tcp.options.acc_ecn.ee1b",
            "tcp.options.acc_ecn.ee0b",
            "tcp.options.acc_ecn.eceb",
            "tcp.non_zero_bytes_after_eol",
            "tcp.flags.ece",
            "tcp.flags.ae",
            "tcp.flags.ace",
            "tcp.data",
            "tcp.connection.sack",
            "tcp.checksum_good",
            "tcp.checksum_bad",
            "mptcp.analysis.unsupported_algorithm",
            "mptcp.analysis.unexpected_idsn",
            "mptcp.analysis.missing_algorithm",
            "tcp.options.timestamp.tsval.syncookie.timestamp",
            "tcp.options.timestamp.tsval.syncookie.ecn",
            "tcp.options.tar.reserved",
            "tcp.options.timestamp.tsval.syncookie.wscale",
            "tcp.syncookie.time",
            "tcp.syncookie.mss",
            "tcp.syncookie.hash",
            "tcp.options.wscale_val",
            "tcp.options.type.number",
            "tcp.options.type.class",
            "tcp.options.type",
            "mptcp.analysis.echoed_key_mismatch",
            "tcp.analysis.echoed_key_mismatch"]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features

def get_tshark_valid_tls_protocol_feature_list():
    features = get_numeric_features('tls')
    
    unsed = [
        "tls.quic.supported_versions.len",
        "tls.quic.supported_versions",
        "tls.quic.parameter.vi.other_version",
        "tls.quic.parameter.vi.chosen_version",
        "tls.quic.parameter.preferred_address.ipversion",
        "tls.quic.parameter.preferred_address.ipaddress.length",
        "tls.quic.parameter.max_packet_size",
        "tls.quic.parameter.idle_timeout",
        "tls.quic.parameter.cibir_encoding.offset",
        "tls.quic.parameter.cibir_encoding.length",
        "tls.quic.negotiated_version",
        "tls.quic.initial_version",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_arp_protocol_feature_list():
    features = get_numeric_features('arp')
    
    # unsed = ["tcp.options.timestamp.tsval.syncookie.sack",
    #         "tcp.options.timestamp.tsval.syncookie.ecn",
    #         "tcp.options.time_stamp",
    #         "tcp.options.tarr.rate",
    #         "tcp.options.tar.reserved",
    #         "tcp.options.scpsflags.reserved3",
    #         "tcp.options.scpsflags.reserved2",
    #         "tcp.options.scpsflags.reserved1",
    #         "tcp.options.rvbd.probe.len",
    #         "tcp.options.mptcp.sendtruncmac",
    #         "tcp.options.mptcp.sendmac",
    #         "tcp.options.mptcp.dataseqno",
    #         "tcp.options.mptcp.dataack",
    #         "tcp.options.mood_val",
    #         "tcp.options.mood",
    #         "tcp.options.experimental.exid",
    #         "tcp.options.echo_reply",
    #         "tcp.options.acc_ecn.ee1b",
    #         "tcp.options.acc_ecn.ee0b",
    #         "tcp.options.acc_ecn.eceb",
    #         "tcp.non_zero_bytes_after_eol",
    #         "tcp.flags.ece",
    #         "tcp.flags.ae",
    #         "tcp.flags.ace",
    #         "tcp.data",
    #         "tcp.connection.sack",
    #         "tcp.checksum_good",
    #         "tcp.checksum_bad",
    #         "mptcp.analysis.unsupported_algorithm",
    #         "mptcp.analysis.unexpected_idsn",
    #         "mptcp.analysis.missing_algorithm",
    #         "tcp.options.timestamp.tsval.syncookie.timestamp",
    #         "tcp.options.timestamp.tsval.syncookie.ecn",
    #         "tcp.options.tar.reserved",
    #         "tcp.options.timestamp.tsval.syncookie.wscale",
    #         "tcp.syncookie.time",
    #         "tcp.syncookie.mss",
    #         "tcp.syncookie.hash",
    #         "tcp.options.wscale_val",
    #         "tcp.options.type.number",
    #         "tcp.options.type.class",
    #         "tcp.options.type",
    #         "mptcp.analysis.echoed_key_mismatch",
    #         "tcp.analysis.echoed_key_mismatch"]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features


def get_tshark_valid_dhcp_protocol_feature_list():
    features = get_numeric_features('dhcp')
    
    unsed = [
        "dhcp.option.agent_information_option.vi.cl.dpoe_system_version"
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_coap_protocol_feature_list():
    features = get_numeric_features('coap')
    
    unsed = [
        "coap.tid",
        "coap.optcount",
        "coap.opt.subscr_lifetime",
        "coap.opt.jump",
        "coap.ocount",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_data_protocol_feature_list():
    features = get_numeric_features('data')
    
    # unsed = [
    #     "dhcp.option.agent_information_option.vi.cl.dpoe_system_version"
    # ]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features

def get_tshark_valid_dns_protocol_feature_list():
    features = get_numeric_features('dns')
    
    unsed = [
        "hf.dns.apl.coded.prefix",
        "dns.t_key.flags.signatory",
        "dns.t_key.flags",
        "dns.soa.mininum_ttl",
        "dns.rr.opt.len",
        "dns.rr.opt.code",
        "dns.rr.opt.client.scope",
        "dns.rr.opt.client.netmask",
        "dns.rr.opt.client.family",
        "dns.resp.udp_payload_size",
        "dns.loc.vertial_precision",
        "dns.extraneous.length",
        "dns.apl.coded.prefix",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features



def get_tshark_valid_eth_protocol_feature_list():
    features = get_numeric_features('eth')
    
    unsed = [
        "eth.vlan.tpid",
        "eth.vlan.pri",
        "eth.vlan.id",
        "eth.vlan.cfi",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features



def get_tshark_valid_ethertype_protocol_feature_list():
    features = get_numeric_features('ethertype')
    
    # unsed = [
    #     "dhcp.option.agent_information_option.vi.cl.dpoe_system_version"
    # ]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features


def get_tshark_valid_http_protocol_feature_list():
    features = get_numeric_features('http')
    
    # unsed = [
    #     "dhcp.option.agent_information_option.vi.cl.dpoe_system_version"
    # ]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features

def get_tshark_valid_icmp_protocol_feature_list():
    features = get_numeric_features('icmp')
    
    unsed = [
        "icmp.mpls.version",
        "icmp.mpls.res",
        "icmp.mpls.length",
        "icmp.mpls.ctype",
        "icmp.mpls.class",
        "icmp.mpls.checksum",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features



def get_tshark_valid_ip_protocol_feature_list():
    features = get_numeric_features('ip')
    
    unsed = [
        "ip.dsfield.ect",
        "ip.dsfield.ce",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_llc_protocol_feature_list():
    features = get_numeric_features('llc')
    
    unsed = [
        "locamation-im.llc.pid",
        "llc.apple_pid",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_pkix1explicit_protocol_feature_list():
    features = get_numeric_features('pkix1explicit')
    
    unsed = [
        "pkix1explicit.RDNSequence_item",
        "pkix1explicit.asIdsOrRanges_item",
        "pkix1explicit.addressesOrRanges_item",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features

def get_tshark_valid_pkix1implicit_protocol_feature_list():
    features = get_numeric_features('pkix1implicit')
    
    # unsed = [
    #     "dhcp.option.agent_information_option.vi.cl.dpoe_system_version"
    # ]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features


def get_tshark_valid_udp_protocol_feature_list():
    features = get_numeric_features('udp')
    
    # unsed = [
    #     "dhcp.option.agent_information_option.vi.cl.dpoe_system_version"
    # ]
    
    # for u in unsed:
    #     if u in features:
    #         features.remove(u)
    

    return features


def get_tshark_valid_x509ce_protocol_feature_list():
    features = get_numeric_features('x509ce')
    
    unsed = [
        "x509ce.StatusReferrals_item",
        "x509ce.GeneralNames_item"
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features


def get_tshark_valid_x509sat_protocol_feature_list():
    features = get_numeric_features('x509sat')
    
    unsed = [
        "x509sat.PostalAddress_item",
        "x509sat.or_item",
        "x509sat.CaseIgnoreListMatch_item",
        "x509sat.and_item",
    ]
    
    for u in unsed:
        if u in features:
            features.remove(u)
    

    return features
