from bs4 import BeautifulSoup

import requests


protocol_urls = {
    "tcp":"https://www.wireshark.org/docs/dfref/t/tcp.html",
    "tls" : "https://www.wireshark.org/docs/dfref/t/tls.html", 
    "arp" : "https://www.wireshark.org/docs/dfref/a/arp.html", 
    "dhcp" : "https://www.wireshark.org/docs/dfref/d/dhcp.html",
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

# print(get_tshark_valid_tls_protocol_feature_list())