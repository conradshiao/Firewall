#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

# constants to define external IP and port types
ANY = 0
COUNTRY = 1
SINGLE = 2
RANGE = 3
CRLF = '\r\n'

def dotted_quad_to_num (IP_address):
    """
    Returns the number, an int, after @IP_address is converted from dotted quad
    to binary notation.
    @IP_address: str representing an IP address in dotted quad form.
    @return: int -- converted IP address.
    """
    return struct.unpack('!I', socket.inet_aton(IP_address))[0]

def str_assign (string, replace, start, end):
    """
    Assigns @replace at @string[@start:@start+@end] and returns result.
    @string: str to modify.
    @replace: str as replacement
    @start: int index to start at, inclusive
    @end: int index that replace ends at, exclusive.
    """
    return string[:start] + replace + string[end:]

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.rules = []
        with open(config['rule'], 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('%'):
                    continue
                l = [token.upper() for token in line.split()] # case-insensitive
                # if 'DNS' in l:
                if l[1] == 'DNS':
                    self.rules.append(DNS_Rule(l[0], l[2]))
                elif l[0] == 'LOG':
                    self.rules.append(HTTP_Log_Rule(l[2]))
                else:
                    self.rules.append(Firewall_Rule(l[0], l[1], l[2], l[3]))
        self.rules.reverse() # last match will now be the first match we see

        self.geo_info = []
        with open('geoipdb.txt', 'r') as f:
            for line in f: # specs say file has no bad formatted lines
                l = line.split()
                self.geo_info.append(GeoIP(l[0], l[1], l[2]))

        self.http_connections = {} # dictionary for (src_ip, dst_ip, src_port, dst_port) -> HTTP_Transaction

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):

        def get_num_from_pkt_field(pkt, byte_offset, num_bytes):
            """
            Returns the number extracted from @pkt when reading @num_bytes
            bytes starting at @byte_offset. The conversion format is dictated
            by python's struct library formatting.

            @pkt: str representing the packet data.
            @byte_offset: int indicating where to start reading from @pkt.
            @num_bytes: int for how many bytes we want to read in total. Must
            be of value 1, 2, or 4.
            @return: int that we extrapolated from packet.
            """
            temp = {1: 'B', 2: 'H', 4: 'I'}
            return struct.unpack('!' + temp[num_bytes],
                    pkt[byte_offset:byte_offset+num_bytes])[0]

        def send_packet(pkt, reverse = False):
            """
            Sends @pkt over the correct interface. This should be followed by
            an immediate return of the function.
            """
            if pkt_dir == PKT_DIR_INCOMING:
                receiver = self.iface_int if not reverse else self.iface_ext
            elif pkt_dir == PKT_DIR_OUTGOING:
                receiver = self.iface_ext if not reverse else self.iface_int
            receiver.send_ip_packet(pkt)

        def get_checksum(pkt):
            """ Return the checksum of @pkt I'm creating. @pkt is in packed string notation. """
            cs = 0
            for i in range(0, len(pkt), 2):
                cs += get_num_from_pkt_field(pkt, i, 2)
            if i == len(pkt) - 1: # odd-sized case
                cs += get_num_from_pkt_field(pkt, i, 1)
            while cs >> 16: # has more than 16 bits
                cs = (cs & 0xFFFF) + (cs >> 16)
            return ~cs & 0xFFFF # want to flip only the rightmost 16 bits

        def pack (num, num_bytes = 1):
            temp = {1: 'B', 2: 'H', 4: 'I'}
            return struct.pack('!' + temp[num_bytes], num)

        def create_RST_pkt():
            """ Creates and returns a TCP RST packet to the pkt in handle_packet(). """
            src1, dest1 = pkt[12:16], pkt[16:20] # IP addresses from IPv4 header
            src2, dest2 = pkt[ip_header_len:ip_header_len+2], pkt[ip_header_len+2:ip_header_len+4]
            received_seq_num = get_num_from_pkt_field(pkt, ip_header_len + 4, 4)
            ack_num = (received_seq_num + 1) % (1 << 32) # mod by 2^32
            rst = (pack(69) + pack(0) + pack(40, 2) + # 69 = (4 << 4) + 5, total length of RST packet is 40
                    pack(0, 4) + pack(64) + pack(6) + pack(0, 2) + # first zero out checksum; TTL = 64 in unix
                    dest1 + src1 + # switch src and destination IP addresses with the response
                    dest2 + src2 + # switch src and destination ports in TCP with response
                    pack(0, 4) + # seq number is zero-ed out, syn flag not set
                    pack(ack_num, 4) + # ack-ing back the SYN packet for resetting the connection
                    pack(80) + # 5 is TCP length, want to zero out padding and NS flag
                    pack(0x14) + # only ACK and RST fields should be set
                    pack(0, 2) + pack(0, 4)) # zero out remaining fields
            ipv4_checksum = get_checksum(rst[0:20]) # first 20 bytes are IPv4 header
            rst = str_assign(rst, pack(ipv4_checksum, 2), 10, 12)
            tcp_pseudoheader = (src1 + dest1 + pack(0) + pack(6) +
                                pack(20, 2) + rst[20:40]) # RST has empty payload, so TCP segment length = 20 (no options)
            tcp_checksum = get_checksum(tcp_pseudoheader)
            rst = str_assign(rst, pack(tcp_checksum, 2), 36, 38)
            return rst

        def create_DNS_response():
            """ Returns a DNS response packet for denying the pkt in handle_packet(). """
            src1, dest1 = pkt[12:16], pkt[16:20]
            src2, dest2 = pkt[ip_header_len:ip_header_len+2], pkt[ip_header_len+2:ip_header_len+4]
            resp = (pack(69) + pack(0) + pack(0, 2) + # will calculate true length later after messing with DNS
                    pack(0, 4) + pack(64) + pack(17) + pack(0, 2) + # UDP checksum = 0 means don't check
                    dest1 + src1 +
                    dest2 + src2 + # beginning of UDP header
                    pack(0, 4) + # don't know length or checksum yet, so initially zero-ed out.
                    pkt[dns_header:question_end_index] + # dns header and question section
                    pkt[question_begin_index:question_end_index] +
                    pack(1, 4) + pack(4, 2) + pack(dotted_quad_to_num("169.229.49.130"), 4))
            resp = str_assign(resp, pack(len(resp), 2), 2, 4)
            resp = str_assign(resp, pack(len(resp) - 20, 2), 24, 26) # ip header length is 20
            resp = str_assign(resp, pack(0x8000, 2), dns_header + 2, dns_header + 4)
            resp = str_assign(resp, pack(1, 2), dns_header + 6, dns_header + 8)
            resp = str_assign(resp, pack(0, 4), dns_header + 8, question_begin_index)
            ipv4_checksum = get_checksum(resp[0:20])
            resp = str_assign(resp, pack(ipv4_checksum, 2), 10, 12)
            return resp

        def save_http_info():
            """
            Reads the HTTP message of @pkt to store and potentially log
            information. Returns True iff we should drop this packet because
            it was an out of order forward TCP packet with HTTP connection.
            """
            src_ip, dst_ip = pkt[12:16], pkt[16:20]
            src_port, dst_port = pkt[ip_header_len:ip_header_len+2], pkt[ip_header_len+2:ip_header_len+4]

            if pkt_dir == PKT_DIR_OUTGOING:
                tup = (src_ip, dst_ip, src_port, dst_port)
            else:
                tup = (dst_ip, src_ip, dst_port, src_port)

            seq_num = get_num_from_pkt_field(pkt, ip_header_len + 4, 4)
            flags = get_num_from_pkt_field(pkt, ip_header_len + 13, 1)
            syn, ack, fin = flags & 0x2, flags & 0x10, flags & 0x1
            if tup in self.http_connections:
                connection = self.http_connections[tup]
                if connection.tcp_handshaking:
                    if connection.can_advance_handshake(syn, ack, pkt_dir, seq_num):
                        connection.advance_handshake()
                        return False
                    else:
                        return True
                else: # FIN-ACK packet disables http connection
                    if (fin != 0 and ack != 0 and pkt_dir == PKT_DIR_INCOMING
                                    and seq_num == connection.sender_ack_num):
                        del self.http_connections[tup]
                        return False
            else: # new connection
                if syn and not ack and pkt_dir == PKT_DIR_OUTGOING:
                    self.http_connections[tup] = HTTP_Transaction(None, seq_num + 1)
                    return False
                if ack and pkt_dir == PKT_DIR_OUTGOING: # for that last ack
                    return False
                return True # against TCP handshaking protocol

            window = get_num_from_pkt_field(pkt, ip_header_len + 14, 2)
            is_greater, exact_match = connection.is_out_of_order_packet(pkt_dir, seq_num, window)
            if is_greater:
                return True
            if exact_match:
                http_msg = pkt[ip_header_len+tcp_len:]
                connection.read(http_msg, pkt_dir)
                if connection.ready_to_log():
                    fields = connection.extract_fields(external_IP)
                    for rule in self.rules:
                        if isinstance(rule, HTTP_Log_Rule) and rule.matches_host(fields["host_name"]):
                            self.write_to_log(fields)
                            break
                elif (connection.req_header_seen and connection.resp_header_seen and
                            pkt_dir == PKT_DIR_OUTGOING): # persistent connection wantS to start another request
                    connection.read(http_msg, pkt_dir)
            return False

        #### Parsing the packet to identify the key features ###
        if pkt_dir == PKT_DIR_OUTGOING: # ext_IP is str in dotted quad notation
            external_IP = socket.inet_ntoa(pkt[16:20])
        else:
            external_IP = socket.inet_ntoa(pkt[12:16])

        ihl = get_num_from_pkt_field(pkt, 0, 1) & 0xF
        if ihl < 5: # IPv4 packet with header length < 5 should be dropped
            return

        ip_header_len = 4 * ihl
        is_DNS_packet = False
        protocol = None
        port = None
        qname = "" # relevant only when is_DNS_packet is True
        pkt_protocol = get_num_from_pkt_field(pkt, 9, 1)
        if pkt_protocol == 6:
            tcp_len = get_num_from_pkt_field(pkt, ip_header_len + 12, 1) >> 4
            tcp_len *= 4
            if tcp_len < 20: # TCP offset shouldn't be < 5
                return
            protocol = "TCP"
            if pkt_dir == PKT_DIR_OUTGOING:
                port_offset = ip_header_len + 2
            else:
                port_offset = ip_header_len
            port = get_num_from_pkt_field(pkt, port_offset, 2)
            if port == 80: # for http log rules
                should_drop = save_http_info()
                if should_drop:
                    return
        elif pkt_protocol == 17:
            protocol = "UDP"
            if pkt_dir == PKT_DIR_OUTGOING:
                port_offset = ip_header_len + 2
            else:
                port_offset = ip_header_len
            port = get_num_from_pkt_field(pkt, port_offset, 2)

            # checking to see if this is a DNS packet and if so, getting qname
            if port == 53 and pkt_dir == PKT_DIR_OUTGOING:
                dns_header = ip_header_len + 8 # UDP header is always 8 bytes
                qdcount = get_num_from_pkt_field(pkt, dns_header + 4, 2)
                if qdcount == 1:
                    curr = question_begin_index = dns_header + 12 # dns header is 12 B
                    length_byte = get_num_from_pkt_field(pkt, curr, 1)
                    curr += 1
                    while length_byte != 0:
                        for i in range(length_byte):
                            qname += chr(get_num_from_pkt_field(pkt, curr + i, 1))
                        qname += '.'
                        curr += length_byte
                        length_byte = get_num_from_pkt_field(pkt, curr, 1)
                        curr += 1
                    qname = qname[:-1] # get rid of that last "."
                    qtype = get_num_from_pkt_field(pkt, curr, 2)
                    qclass = get_num_from_pkt_field(pkt, curr + 2, 2)
                    question_end_index = curr + 4
                    if (qtype == 1 or qtype == 28) and qclass == 1:
                        is_DNS_packet = True
                        qname = qname.upper() # case-insensitive now
        elif pkt_protocol == 1:
            protocol = "ICMP"
            port = get_num_from_pkt_field(pkt, ip_header_len, 1)
        else:
            send_packet(pkt)
            return

        ### Checking the fields of the packet against our rules. ###
        for rule in self.rules: # remember, this is reversed. 1st match is good
            if isinstance(rule, DNS_Rule):
                if is_DNS_packet and rule.matches_domain(qname):
                    if rule.verdict == "PASS":
                        send_packet(pkt)
                    elif rule.verdict == 'DENY':
                        if qtype != 28: # AAAA = 28
                            send_packet(create_DNS_response(), reverse = True)
                    return

            elif isinstance(rule, Firewall_Rule):
                if rule.protocol == protocol and rule.matches_port(port):
                    if rule.need_country_for_IP_addr_check:
                        country_arg = self.find_country(external_IP)
                    else:
                        country_arg = None
                    if rule.matches_IP_address(external_IP, country_arg):
                        if rule.verdict == 'PASS':
                            send_packet(pkt)
                        elif rule.verdict == 'DENY' and rule.protocol == 'TCP':
                            send_packet(create_RST_pkt(), reverse = True)
                        return

        send_packet(pkt) # specs say send packet if no rules matched

    def find_country (self, ip_address):
        """
        Returns the country code that @ip_address belongs to, or None
        if this ip_address does not fall into any country IP address range
        provided by the provided geoipdb.txt file.

        @ip_address -- str for the IP address in dotted quad notation.
        """
        def binary_search (IP, low, high):
            """
            Helper function to perform binary search on @IP, as
            the format of geoipdb.txt is guaranteed to already be sorted.
            """
            if high <= low:
                return None
            mid_idx = (high + low) / 2
            entry = self.geo_info[mid_idx]
            if entry.min_IP <= IP <= entry.max_IP: # match!
                return entry.country_code
            if IP < entry.min_IP:
                return binary_search(IP, low, mid_idx)
            else:
                return binary_search(IP, mid_idx + 1, high)

        IP_as_num = dotted_quad_to_num(ip_address)
        return binary_search(IP_as_num, 0, len(self.geo_info))

    def write_to_log (self, field_map, file_name = 'http.log'):
        """
        Writes to file @file_name using the entries found in field_map as a
        basis.
        @field_map -- a dictionary mapping field names to their values.
        @file_name -- file to write to. By default, file name is 'http.log'
        """
        with open(file_name, 'a') as f: # closes file when exiting suite
            keys = ['host_name', 'method', 'path', 'version', 'status_code',
                    'object_size']
            f.write(" ".join([field_map[key] for key in keys]) + '\n')
            f.flush()

class GeoIP (object):

    def __init__(self, min_IP, max_IP, code):
        self.country_code = code.upper() # note case-insensitivity
        self.min_IP = dotted_quad_to_num(min_IP)
        self.max_IP = dotted_quad_to_num(max_IP)

class DNS_Rule:

    def __init__ (self, verdict, domain_name):
        self.verdict = verdict.upper()
        self.domain = domain_name
        self.exact_match = True
        if domain_name.startswith('*'):
            self.exact_match = False
            self.domain = domain_name[1:]

    def matches_domain (self, domain):
        """ Returns true iff @domain is a match to my domain. """
        if self.exact_match:
            return domain == self.domain
        else:
            return domain.endswith(self.domain)

class Firewall_Rule:

    def __init__ (self, verdict, protocol, external_IP, external_port):
        self.verdict = verdict.upper()
        self.protocol = protocol.upper()

        self.need_country_for_IP_addr_check = False
        self.external_IP = external_IP.upper()
        self.external_IP_type = None
        if self.external_IP == 'ANY':
            self.external_IP_type = ANY
        elif len(external_IP) == 2:
            self.external_IP_type = COUNTRY
            self.need_country_for_IP_addr_check = True
        elif '/' in external_IP: # external IP will be tuple of ints as min/max
            self.external_IP_type = RANGE
            addr, prefix = external_IP.split('/')
            mask = (1 << (32 - int(prefix))) - 1
            addr_num = dotted_quad_to_num(addr)
            self.external_IP = (addr_num & ~mask, addr_num | mask)
        else:
            self.external_IP_type = SINGLE
            self.external_IP = dotted_quad_to_num(external_IP)

        self.external_port = external_port.upper()
        self.external_port_type = None
        if self.external_port == 'ANY':
            self.external_port_type = ANY
        elif '-' in self.external_port:
            self.external_port_type = RANGE
            lst = self.external_port.split('-')
            self.external_port = (int(lst[0]), int(lst[1]))
        else:
            self.external_port_type = SINGLE
            self.external_port = int(external_port)

    def matches_port (self, port_no):
        """ Returns True iff @port_no, an int, matches this external port. """
        if self.external_port_type == ANY:
            return True
        elif self.external_port_type == RANGE:
            return self.external_port[0] <= port_no <= self.external_port[1]
        else:
            return port_no == self.external_port

    def matches_IP_address (self, IP, country):
        """
        Returns True iff @IP matches my external IP address.
        @ip: str -- in dotted quad notation.
        @country: str -- country code, the result of this IP when checked
            against a geoipdb file associated with a Firewall object. This
            is None object when country is not needed.
        @return: bool -- if @IP matched against the one found in this Rule.
        """
        if self.external_IP_type == ANY:
            return True
        elif self.external_IP_type == COUNTRY:
            return country == self.external_IP
        IP = dotted_quad_to_num (IP)
        if self.external_IP_type == SINGLE:
            return self.external_IP == IP
        else:
            return self.external_IP[0] <= IP <= self.external_IP[1]

class HTTP_Log_Rule:

    def __init__(self, host_name):
        self.host_name = host_name.upper()

    def matches_host (self, host):
        host = host.upper()
        if self.host_name.startswith('*'):
            return host.endswith(self.host_name[1:])
        return self.host_name == host

class HTTP_Transaction:
    """ Each HTTP_Transaction will have a unique (src_ip, dst_ip, src_port, dst_port). """
    def __init__(self, sender_ack_num, receiver_ack_num):
        self.request = ""
        self.sender_ack_num = sender_ack_num
        self.response = ""
        self.receiver_ack_num = receiver_ack_num
        self.req_header_seen = False
        self.resp_header_seen = False
        self.tcp_handshaking = True
        self.handshake_stage = 1

    def can_advance_handshake(self, syn, ack, pkt_dir, seq_num):
        assert self.tcp_handshaking
        if self.handshake_stage == 1:
            advance = syn != 0 and ack != 0 and pkt_dir == PKT_DIR_INCOMING
            if advance:
                self.sender_ack_num = seq_num + 1
            return advance
        elif self.handshake_stage == 2:
            return syn == 0 and ack != 0 and pkt_dir == PKT_DIR_OUTGOING

    def advance_handshake(self):
        self.handshake_stage += 1
        if self.handshake_stage == 3:
            self.tcp_handshaking = False

    def ready_to_log(self):
        """ True iff both transaction headers are fully seen and we have not
        yet logged this transaction. """
        if self.req_header_seen and self.resp_header_seen:
            return False
        self.req_header_seen = self.request[-4:] == CRLF * 2
        self.resp_header_seen = self.response[-4:] == CRLF * 2
        return self.req_header_seen and self.resp_header_seen

    def read(self, msg, pkt_dir):
        if pkt_dir == PKT_DIR_OUTGOING and self.req_header_seen and self.resp_header_seen:
            self.req_header_seen = False
            self.resp_header_seen = False
        if pkt_dir == PKT_DIR_OUTGOING:
            self.receiver_ack_num = (self.receiver_ack_num + len(msg)) % (1 << 32)
            if not self.req_header_seen:
                before, crlf, _ = msg.partition(CRLF * 2)
                if crlf != '':
                    msg = before + crlf
                self.request += msg
        else:
            self.sender_ack_num = (self.sender_ack_num + len(msg)) % (1 << 32)
            if not self.resp_header_seen:
                before, crlf, _ = msg.partition(CRLF * 2)
                if crlf != '':
                    msg = before + crlf
                self.response += msg

    def is_out_of_order_packet(self, pkt_dir, seq_num, window):
        """ Returns True iff this packet is an out of order FORWARD gap TCP packet. """
        # check = self.sender_ack_num if pkt_dir == PKT_DIR_INCOMING else self.receiver_ack_num
        # if seq_num > check: # forward out of order packet
        #     return True
        # elif (seq_num < check and seq_num < (check + window) % (1 << 32) # wrapped around, still forward gap packet
        #                     and (check + window) > (1 << 32)):
        #     return True
        # return False
        check = self.sender_ack_num if pkt_dir == PKT_DIR_INCOMING else self.receiver_ack_num
        strictly_greater = (seq_num < check and (check - seq_num) > (1 << 31) or
                seq_num > check and (seq_num - check) < (1 << 31))
        exact_match = seq_num == check
        return strictly_greater, exact_match

    def extract_fields(self, external_IP):
        """
        Returns a dictionary of necessary fields. Should be only called when
        self.ready_to_log() returns True.
        """
        fields = {}
        lines = self.request.split("\r\n")
        fields["method"] = lines[0].split()[0]
        fields["path"] = lines[0].split()[1]
        fields["version"] = lines[0].split()[2]
        fields["object_size"] = str(-1)
        fields['host_name'] = external_IP
        for line in lines:
            field, colon, value = line.partition(':')
            if colon != '' and field.strip().upper() == 'HOST':
                fields['host_name'] = value.strip()
                break
        lines = self.response.split("\r\n")
        fields["status_code"] = lines[0].split()[1]
        for line in lines:
            field, colon, value = line.partition(':')
            if colon != '' and field.strip().upper() == 'CONTENT-LENGTH':
                fields['object_size'] = value.strip()
                break
        self.response = ''
        self.request = ''
        return fields
