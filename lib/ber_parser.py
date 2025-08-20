import binascii
import builtins
from base64 import b64encode

TAG_CLASSES = {
    0: 'UNIVERSAL',
    1: 'APPLICATION',
    2: 'CONTEXT-SPECIFIC',
    3: 'PRIVATE'
}

UNIVERSAL_TAGS = {
    0x01: 'BOOLEAN',
    0x02: 'INTEGER',
    0x03: 'BIT STRING',
    0x04: 'OCTET STRING',
    0x05: 'NULL',
    0x06: 'OBJECT IDENTIFIER',
    0x0C: 'UTF8String',
    0x10: 'SEQUENCE',
    0x11: 'SET',
    0x13: 'PrintableString',
    0x17: 'UTCTime',
    0x30: 'SEQUENCE',
}


BASE64_ATTRS = ['ipatokenOTPkey', 'krbPrincipalKey', 'ipaNTHash', 'krbExtraData', 'userCertificate', 'ipaSshPubKey']

class LdapObject:
    def __init__(self, dn):
        self.dn = dn
        self.attributes = {}

    def add_attribute(self, key, value):
        if key not in self.attributes:
            self.attributes[key] = [value]
        else:
            self.attributes[key].append(value)

    def __str__(self):
        result = ""
        result += '- ' + self.dn + '\n'
        for i in self.attributes:
            if len(self.attributes[i]) == 1:
                result += '  |--- ' + i + ':'
                result += ' ' + str(self.attributes[i][0]) + '\n'
                continue
            result += '  |--- ' + i + '\n'
            for j in self.attributes[i]:
                result += '       |--- ' + j + '\n'
        return result


def parse_length(data, index):
    length = data[index]
    index += 1
    if length & 0x80:
        num_bytes = length & 0x7F
        length = int.from_bytes(data[index:index+num_bytes], 'big')
        index += num_bytes
    return length, index

def decode_value(tag, value):
    if tag == 0x02:  # INTEGER
        return int.from_bytes(value, 'big', signed=(value[0] & 0x80) != 0)
    elif tag == 0x04:  # OCTET STRING
        return value
    elif tag == 0x06:  # OBJECT IDENTIFIER
        return decode_oid(value)
    elif tag == 0x13 or tag == 0x0C:  # PrintableString or UTF8String
        return value.decode('utf-8', errors='replace')
    elif tag == 0x17:  # UTCTime
        return value.decode('ascii')
    elif tag == 0x01:  # BOOLEAN
        return value != b'\x00'
    elif tag == 0x05:  # NULL
        return None
    else:
        return value.hex()

def decode_oid(value):
    result = []
    if not value:
        return ""
    first_byte = value[0]
    result.append(str(first_byte // 40))
    result.append(str(first_byte % 40))

    num = 0
    for b in value[1:]:
        num = (num << 7) | (b & 0x7F)
        if not (b & 0x80):
            result.append(str(num))
            num = 0
    return '.'.join(result)

def parse_tlv(data, index=0, depth=0):
    parsed = []
    indent = '  ' * depth

    while index < len(data):
        tag = data[index]
        index += 1

        length, index = parse_length(data, index)
        value = data[index:index+length]
        index += length

        tag_class = (tag & 0b11000000) >> 6
        pc_bit = (tag & 0b00100000) >> 5
        tag_number = tag & 0b00011111

        tag_class_name = TAG_CLASSES.get(tag_class, 'UNKNOWN')
        tag_desc = UNIVERSAL_TAGS.get(tag, f"Tag-{tag_number}")


        if pc_bit:
            children = parse_tlv(value, 0, depth + 1)
            parsed.append({
                'tag': tag,
                'class': tag_class_name,
                'constructed': True,
                'type': tag_desc,
                'children': children
            })
        else:
            decoded = decode_value(tag, value)
            parsed.append({
                'tag': tag,
                'class': tag_class_name,
                'constructed': False,
                'type': tag_desc,
                'raw': value,
                'decoded': decoded
            })

    return parsed

def create_ldap_object(data):
    parsed = parse_tlv(data)
    ldap_object = LdapObject(parsed[0]['children'][1]['raw'].decode())
    for attr in parsed[0]['children'][2]['children']:
        attr_name = attr['children'][0]['raw'].decode()
        for attrs_seq in attr['children'][1:]:
            try:
                for attr_value in attrs_seq['children']:
                    if attr_name in BASE64_ATTRS:
                        ldap_object.add_attribute(attr_name, b64encode(attr_value['children'][0]['raw']).decode())
                    else:
                        try:
                            ldap_object.add_attribute(attr_name, attr_value['children'][0]['raw'].decode())
                        except builtins.UnicodeDecodeError:
                            ldap_object.add_attribute(attr_name, b64encode(attr_value['children'][0]['raw']).decode())
            except KeyError:
                pass
    return ldap_object


def create_key_object(data):
    parsed = parse_tlv(data)
    ldap_object = LdapObject(parsed[0]['children'][1]['raw'].decode())
    for attr in parsed[0]['children'][2]['children']:
        attr_name = attr['children'][0]['raw'].decode()
        for attrs_seq in attr['children'][1:]:
            try:
                for attr_value in attrs_seq['children']:
                    try:
                        ldap_object.add_attribute(attr_name, attr_value['children'][0]['raw'].decode())
                    except builtins.UnicodeDecodeError:
                        ldap_object.add_attribute(attr_name, attr_value['children'][0]['raw'])
            except KeyError:
                pass
    return ldap_object
