"""Pure bounded parsing of two sealed iproute2 -j local JSON command snapshots.

Source-reported kernel interface/address and route objects are retained
without inference of reachability, external IPs, topology, or connection health.
No socket/network access and no dynamically constructed shell commands.
"""
import json
import math

MAX_BYTES=1024*1024
MAX_ROWS=4096
MAX_NODES=20000
MAX_DEPTH=11
MAX_STRING=4096
MAX_FIELDS=128
COMMANDS={
 "ip -j addr show":"addr",
 "ip -j route show":"route",
}
class IpLocalParseError(ValueError):
    """Unsupported, malformed, unbounded, or ambiguous iproute2 JSON."""

def _object(pairs):
    obj={}
    for k,v in pairs:
        if k in obj:
            raise IpLocalParseError("IP_JSON_DUPLICATE_FIELD")
        obj[k]=v
    return obj

def _invalid_constant(value):
    raise IpLocalParseError("IP_JSON_NONFINITE_NUMBER")

def _validate_tree(value,depth,counter):
    counter[0]+=1
    if depth>MAX_DEPTH or counter[0]>MAX_NODES:
        raise IpLocalParseError("IP_JSON_NESTED_BOUNDS")
    if type(value) is dict:
        if len(value)>MAX_FIELDS:
            raise IpLocalParseError("IP_JSON_EXCESSIVE_FIELDS")
        for key,item in value.items():
            _validate_tree(key,depth+1,counter)
            _validate_tree(item,depth+1,counter)
    elif type(value) is list:
        if len(value)>MAX_ROWS:
            raise IpLocalParseError("IP_JSON_EXCESSIVE_ITEMS")
        for child in value:
            _validate_tree(child,depth+1,counter)
    elif type(value) is str:
        if (len(value)>MAX_STRING or any(ord(c)<32 or ord(c)==127 for c in value)):
            raise IpLocalParseError("IP_JSON_INVALID_STRING")
    elif type(value) is int:
        if abs(value)>2**64-1:
            raise IpLocalParseError("IP_JSON_INTEGER_OVERFLOW")
    elif type(value) is float:
        if not math.isfinite(value):
            raise IpLocalParseError("IP_JSON_NONFINITE_NUMBER")
    elif value is None or type(value) is bool:
        pass
    else:
        raise IpLocalParseError("IP_JSON_UNEXPECTED_VALUE")

def _valid_string(value):
    return type(value) is str and 0<len(value)<=MAX_STRING

def parse_ip_local(raw,*,source_command):
    if source_command not in COMMANDS or type(source_command) is not str:
        raise IpLocalParseError("IP_JSON_UNREGISTERED_COMMAND")
    if type(raw) is not bytes or not 0<len(raw)<=MAX_BYTES or not raw.endswith(b"\n"):
        raise IpLocalParseError("IP_JSON_BOUNDARY_OR_SIZE")
    try:
        text=raw.decode("utf-8","strict")
        parsed=json.loads(text,object_pairs_hook=_object,
                          parse_constant=_invalid_constant)
    except UnicodeDecodeError as exc:
        raise IpLocalParseError("IP_JSON_NON_UTF8") from exc
    except (json.JSONDecodeError,ValueError,RecursionError) as exc:
        if isinstance(exc,IpLocalParseError):
            raise
        raise IpLocalParseError("IP_JSON_MALFORMED") from exc
    if type(parsed) is not list or len(parsed)>MAX_ROWS:
        raise IpLocalParseError("IP_JSON_NOT_BOUNDED_ARRAY")
    _validate_tree(parsed,0,[0])
    kind=COMMANDS[source_command]
    if kind=="addr":
        for row in parsed:
            if type(row) is not dict:
                raise IpLocalParseError("IP_ADDR_NONOBJECT")
            index=row.get("ifindex")
            ifname=row.get("ifname")
            if (type(index) is not int or not 0<index<2**32
                    or not _valid_string(ifname)):
                raise IpLocalParseError("IP_ADDR_INVALID_INTERFACE_ID")
            infos=row.get("addr_info",[])
            if type(infos) is not list or any(type(item) is not dict for item in infos):
                raise IpLocalParseError("IP_ADDR_INVALID_ADDRESS_LIST")
    else:
        for row in parsed:
            if type(row) is not dict or not row:
                raise IpLocalParseError("IP_ROUTE_NONOBJECT")
            if not any(k in row for k in ("dst","dev","gateway","type","scope","protocol","table")):
                raise IpLocalParseError("IP_ROUTE_MISSING_REPORTED_ID")
            for key in ("dst","dev","gateway","type","scope","protocol","prefsrc","src"):
                if key in row and not _valid_string(row[key]):
                    raise IpLocalParseError("IP_ROUTE_INVALID_REPORTED_FIELD")
            for key in ("metric","mtu"):
                if key in row and (type(row[key]) is not int or row[key]<0):
                    raise IpLocalParseError("IP_ROUTE_INVALID_NUMERIC_FIELD")
    return kind,parsed
