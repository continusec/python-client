#
#   Copyright 2016 Continusec Pty Ltd
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# Portions of the Object Hash code are based on Ben Laurie's object hash
# implementation.
#

"""
The Python client for Continusec is nearly identical to the golang client which
is documented here:

xxxx

The documentation for the golang client is currently populated than the Python one,
so suggest check there first.

In general all of the clients are quite thin wrappers over the HTTPS requests.

Example usage:

client = Client("1234...678", "secretkey")

log = client.verifiable_log("logdemo")

# only create the log once
log.create()

# these add asynchronously
log.add("foo")
log.add("bar")

# since the adds are asynchronous, the following won't work right away
tree_size, root_hash = log.tree_hash()
idx, proof = log.inclusion_proof(tree_size, leaf_merkle_tree_hash("bar"))

print verify_log_inclusion_proof(idx, tree_size, leaf_merkle_tree_hash("bar"), root_hash, proof)

first_size, first_hash = log.tree_hash(1)
proof = log.consistency_proof(first_size, tree_size)
print verify_log_consistency_proof(first_size, tree_size, first_hash, root_hash, proof)

map = client.verifiable_map("mapdemo")

# only create the log once
map.create()

# these add asynchronously
map.set("foo", "bar")
map.set("biz", "boz")

# since the adds are asynchronous, the following won't work right away
map_size, map_root = map.tree_hash()
val, proof = map.get("foo", map_size)

print verify_map_inclusion_proof("foo", val, proof, map_root)

"""

import binascii
import httplib
import urlparse
import json
import base64
import hashlib
import unicodedata
import json
import time


HEAD = 0


class ContinusecError(Exception):
    """Base class for exceptions in this module"""
    pass


class InvalidRangeError(ContinusecError):
    pass


class UnauthorizedError(ContinusecError):
    pass


class NotFoundError(ContinusecError):
    pass


class InternalError(ContinusecError):
    pass


class ObjectHashError(ContinusecError):
    pass


class ObjectConflictError(ContinusecError):
    pass


class VerificationFailedError(ContinusecError):
    pass


class NotAllEntriesReturnedError(ContinusecError):
    pass


def object_hash_list(o, prefix):
    h = hashlib.sha256()
    h.update('l')
    for a in o:
        h.update(object_hash_with_redaction(a, prefix))
    return h.digest()


def object_hash_dict(o, prefix):
    x = []
    for k, v in o.items():
        x.append(object_hash_with_redaction(k, prefix) + object_hash_with_redaction(v, prefix))
    x.sort()
    h = hashlib.sha256()
    h.update('d')
    for a in x:
        h.update(a)
    return h.digest()


def object_hash_float(o):
    if o == 0.0:
        return '+0:'
    s = '+'
    if o < 0:
        s = '-'
        o = -o
    e = 0
    while o > 1:
        o /= 2.0
        e += 1
    while o <= 0.5:
        o *= 2.0
        e -= 1
    s += str(e) + ":"
    if o > 1:
        raise ObjectHashError()
    if o <= 0.5:
        raise ObjectHashError()
    while o != 0.0:
        if o >= 1:
            s += '1'
            o -= 1.0
        else:
            s += '0'
        if o >= 1.0:
            raise ObjectHashError()
        if len(s) >= 1000:
            raise ObjectHashError()
        o *= 2.0
    return hashlib.sha256('f' + s).digest()


def object_hash(o):
    return object_hash_with_redaction(o, prefix=None)


def object_hash_with_redaction(o, prefix="***REDACTED*** Hash: "):
    t = type(o)
    if t is list:
        return object_hash_list(o, prefix)
    elif t is dict:
        return object_hash_dict(o, prefix)
    elif t is unicode or t is str:
        if t is str:
            o = unicode(o)
        if prefix and o.startswith(prefix):
            return binascii.unhexlify(o[len(prefix):])
        else:
            return hashlib.sha256('u' + unicodedata.normalize("NFC", o).encode('utf-8')).digest()
    elif t is float or t is int: # json, sigh, only knows floats, not ints
        return object_hash_float(o * 1.0)
    elif t is bool:
        return hashlib.sha256('b' + ('1' if o else '0')).digest()
    elif o is None:
        return hashlib.sha256('n').digest()
    else:
        raise ObjectHashError()


def shed_redactable(o, prefix="***REDACTED*** Hash: "):
    if o is None:
        return None
    else:
        t = type(o)
        if t is list:
            return [shed_redactable(x, prefix) for x in o]
        elif t is dict:
            rv = {}
            for k, v in o.items():
                tv = type(v)
                if tv is list:
                    if len(v) == 2:
                        rv[k] = shed_redactable(v[1], prefix)
                    else:
                        raise ObjectHashError()
                elif tv is unicode or tv is str:
                    if tv is str:
                        v = unicode(v)
                    if v.startswith(prefix):
                        pass
                    else:
                        raise ObjectHashError()
                else:
                    raise ObjectHashError()
            return rv
        else:
            return o


class Client(object):
    def __init__(self, account, api_key, base_url="https://api.continusec.com"):
        self._account = account
        self._api_key = api_key
        self._base_parts = urlparse.urlparse(base_url)
        self._base_url = base_url

    def verifiable_map(self, name):
        return VerifiableMap(self._make_request, "/map/" + name)

    def verifiable_log(self, name):
        return VerifiableLog(self._make_request, "/log/" + name)

    def _make_request(self, method, path, data=None):
        url = self._base_url + "/v1/account/" + str(self._account) + path
        conn = {'https': httplib.HTTPSConnection, 'http': httplib.HTTPConnection} \
            [self._base_parts.scheme](self._base_parts.netloc)
        headers = {'Authorization': 'Key ' + self._api_key}
        conn.request(method, url, data, headers)
        resp = conn.getresponse()
        if resp.status == 200:
            return resp.read(), resp.getheaders()
        elif resp.status == 400:
            raise InvalidRangeError()
        elif resp.status == 403:
            raise UnauthorizedError()
        elif resp.status == 404:
            raise NotFoundError()
        elif resp.status == 409:
            raise ObjectConflictError()
        else:
            raise InternalError()


class VerifiableMap(object):
    def __init__(self, client, path):
        self._client = client
        self._path = path

    def mutation_log(self):
        return VerifiableLog(self._client, self._path + '/log/mutation')

    def tree_head_log(self):
        return VerifiableLog(self._client, self._path + '/log/treehead')

    def create(self):
        self._client("PUT", self._path)

    def get(self, key, map_head, factory):
        value, headers = self._client("GET", self._path + "/tree/" + str(map_head.tree_size()) + \
                                      "/key/h/" + binascii.hexlify(key) + factory.format())
        proof = [None] * 256
        vts = -1
        for k, v in headers:
            if k.lower() == 'x-verified-proof':
                for z in v.split(','):
                    x, y = z.split('/')
                    proof[int(x.strip())] = binascii.unhexlify(y.strip())
            elif k.lower() == 'x-verified-treesize':
                vts = int(v.strip())

        return MapEntryResponse(key, factory.create_from_bytes(value), vts, proof)

    def verified_get(self, key, map_state, factory):
        resp = self.get(key, map_state.map_head(), factory)
        resp.verify(map_state.map_head())
        return resp.value()

    def set(self, key, value):
        rv, _ = self._client("PUT", self._path + "/key/h/" + binascii.hexlify(key) + value.format(), value.data_for_upload())
        return AddEntryResponse(base64.b64decode(json.loads(rv)['leaf_hash']))

    def delete(self, key):
        rv, _ = self._client("DELETE", self._path + "/key/h/" + binascii.hexlify(key))
        return AddEntryResponse(base64.b64decode(json.loads(rv)['leaf_hash']))

    def tree_head(self, tree_size=HEAD):
        data, _ = self._client("GET", self._path + "/tree/" + str(tree_size))
        obj = json.loads(data)
        return MapTreeHead(LogTreeHead(int(obj['mutation_log']['tree_size']),
            None if obj['mutation_log']['tree_hash'] is None
            else base64.b64decode(obj['mutation_log']['tree_hash'])),
            base64.b64decode(obj['map_hash']))

    def block_until_size(self, size):
        last = -1
        secs = 0
        while 1:
            lth = self.tree_head(HEAD)
            if lth.mutation_log_tree_head().tree_size() > last:
                last = lth.mutation_log_tree_head().tree_size()
                if last >= size:
                    return lth
                else:
                    secs = 1
            else:
                secs *= 2

            time.sleep(secs)

    def verified_latest_map_state(self, prev):
        head = self.verified_map_state(prev, HEAD)
        if prev is not None:
            if head.tree_size() <= prev.tree_size():
                return prev
        return head

    def verified_map_state(self, prev, tree_size):
        if tree_size != 0 and prev is not None and prev.tree_size() == tree_size:
            return prev

        map_head = self.tree_head(tree_size)
        if prev is not None:
            self.mutation_log().verify_consistency(prev.map_head().mutation_log_tree_head(), map_head.mutation_log_tree_head())

        thlth = self.tree_head_log().verified_latest_tree_head(None if prev is None else prev.tree_head_log_tree_head())
        self.tree_head_log().verify_inclusion(thlth, map_head)

        return MapTreeState(map_head, thlth)


class MapEntryResponse(object):
    def __init__(self, key, value, tree_size, audit_path):
        self._key = key
        self._value = value
        self._tree_size = tree_size
        self._audit_path = audit_path

    def key(self):
        return self._key

    def value(self):
        return self._value

    def tree_size(self):
        return self._tree_size

    def audit_path(self):
        return self._audit_path

    def verify(self, head):
        if head.mutation_log_tree_head().tree_size() != self._tree_size:
            raise VerificationFailedError()
        kp = construct_map_key_path(self._key)
        t = self._value.leaf_hash()
        for i in range(len(kp) - 1, -1, -1):
            p = self._audit_path[i]
            if p is None:
                p = DEFAULT_LEAF_VALUES[i + 1]

            if kp[i]:
                t = node_merkle_tree_hash(p, t)
            else:
                t = node_merkle_tree_hash(t, p)
        if t != head.root_hash():
            raise VerificationFailedError()


class RawDataEntryFactory(object):
    def create_from_bytes(self, b):
        return RawDataEntry(b)
    def format(self):
        return ""

class JsonEntryFactory(object):
    def create_from_bytes(self, b):
        return JsonEntry(b)
    def format(self):
        return "/xjson"

class RedactedJsonEntryFactory(object):
    def create_from_bytes(self, b):
        return RedactedJsonEntry(b)
    def format(self):
        return "/xjson"

class RawDataEntry(object):
    def __init__(self, data):
        self._data = data
    def data(self):
        return self._data
    def data_for_upload(self):
        return self._data
    def format(self):
        return ""
    def leaf_hash(self):
        return leaf_merkle_tree_hash(self._data)

class JsonEntry(object):
    def __init__(self, data):
        self._data = data
    def data(self):
        return self._data
    def data_for_upload(self):
        return self._data
    def format(self):
        return "/xjson"
    def leaf_hash(self):
        return leaf_merkle_tree_hash(object_hash_with_redaction(json.loads(self._data)))

class RedactableJsonEntry(object):
    def __init__(self, data):
        self._data = data
    def data_for_upload(self):
        return self._data
    def format(self):
        return "/xjson/redactable"

class RedactedJsonEntry(object):
    def __init__(self, data):
        self._data = data
    def data(self):
        return json.dumps(shed_redactable(json.loads(self._data)))
    def leaf_hash(self):
        return leaf_merkle_tree_hash(object_hash_with_redaction(json.loads(self._data)))

class AddEntryResponse(object):
    def __init__(self, leaf_hash):
        self._leaf_hash = leaf_hash
    def leaf_hash(self):
        return self._leaf_hash

class LogTreeHead(object):
    def __init__(self, tree_size, root_hash):
        self._tree_size = tree_size
        self._root_hash = root_hash
    def tree_size(self):
        return self._tree_size
    def root_hash(self):
        return self._root_hash


class MapTreeHead(object):
    def __init__(self, mutation_log_tree_head, root_hash):
        self._mutation_log_tree_head = mutation_log_tree_head
        self._root_hash = root_hash
    def mutation_log_tree_head(self):
        return self._mutation_log_tree_head
    def root_hash(self):
        return self._root_hash
    def tree_size(self):
        return self.mutation_log_tree_head().tree_size()
    def leaf_hash(self):
        return leaf_merkle_tree_hash(object_hash({
            "mutation_log": {
                "tree_size": self.tree_size(),
                "tree_hash": base64.b64encode(self.mutation_log_tree_head().root_hash()),
            },
            "map_hash": base64.b64encode(self.root_hash()),
        }))


class MapTreeState(object):
    def __init__(self, map_head, tree_head_log_tree_head):
        self._map_head = map_head
        self._tree_head_log_tree_head = tree_head_log_tree_head
    def map_head(self):
        return self._map_head
    def tree_size(self):
        return self.map_head().tree_size()
    def tree_head_log_tree_head(self):
        return self._tree_head_log_tree_head

class LogConsistencyProof(object):
    def __init__(self, first_size, second_size, audit_path):
        self._first_size = first_size
        self._second_size = second_size
        self._audit_path = audit_path
    def first_size(self):
        return self._first_size
    def second_size(self):
        return self._second_size
    def audit_path(self):
        return self._audit_path
    def verify(self, first, second):
        if first.tree_size() != self._first_size:
            raise VerificationFailedError()
        if second.tree_size() != self._second_size:
            raise VerificationFailedError()

        if self._first_size < 1 or self._first_size >= self._second_size:
            raise VerificationFailedError()

        proof = self._audit_path
        if is_pow_2(self._first_size):
            proof = [first.root_hash()] + proof

        fn, sn = self._first_size - 1, self._second_size - 1
        while fn & 1 == 1:
            fn >>= 1
            sn >>= 1

        if len(proof) == 0:
            raise VerificationFailedError()

        fr = sr = proof[0]
        for c in proof[1:]:
            if sn == 0:
                raise VerificationFailedError()

            if fn & 1 == 1 or fn == sn:
                fr = node_merkle_tree_hash(c, fr)
                sr = node_merkle_tree_hash(c, sr)
                while not (fn == 0 or fn & 1 == 1):
                    fn >>= 1
                    sn >>= 1
            else:
                sr = node_merkle_tree_hash(sr, c)
            fn >>= 1
            sn >>= 1

        if sn != 0:
            raise VerificationFailedError()

        if fr != first.root_hash():
            raise VerificationFailedError()

        if sr != second.root_hash():
            raise VerificationFailedError()


class LogInclusionProof(object):
    def __init__(self, leaf_hash, tree_size, leaf_index, audit_path):
        self._leaf_hash = leaf_hash
        self._tree_size = tree_size
        self._leaf_index = leaf_index
        self._audit_path = audit_path
    def tree_size(self):
        return self._tree_size
    def audit_path(self):
        return self._audit_path
    def leaf_hash(self):
        return self._leaf_hash
    def leaf_index(self):
        return self._leaf_index
    def verify(self, head):
        if head.tree_size() != self._tree_size:
            raise VerificationFailedError()
        if self._leaf_index >= self._tree_size or self._leaf_index < 0:
            raise VerificationFailedError()

        fn, sn = self._leaf_index, self._tree_size - 1
        r = self._leaf_hash
        for p in self._audit_path:
            if fn == sn or fn & 1 == 1:
                r = node_merkle_tree_hash(p, r)
                while not (fn == 0 or fn & 1 == 1):
                    fn >>= 1
                    sn >>= 1
            else:
                r = node_merkle_tree_hash(r, p)
            fn >>= 1
            sn >>= 1

        if sn != 0:
            raise VerificationFailedError()

        if r != head.root_hash():
            raise VerificationFailedError()


class VerifiableLog(object):
    def __init__(self, client, path):
        self._client = client
        self._path = path

    def create(self):
        self._client("PUT", self._path)

    def add(self, data):
        rv, _ = self._client("POST", self._path + "/entry" + data.format(), data.data_for_upload())
        return AddEntryResponse(base64.b64decode(json.loads(rv)['leaf_hash']))

    def tree_head(self, tree_size=HEAD):
        data, _ = self._client("GET", self._path + "/tree/" + str(tree_size))
        obj = json.loads(data)
        return LogTreeHead(int(obj['tree_size']), None if obj['tree_hash'] is None else \
                                          base64.b64decode(obj['tree_hash']))

    def entry(self, idx, factory):
        rv, _ = self._client("GET", self._path + "/entry/" + str(idx) + factory.format())
        return factory.create_from_bytes(rv)

    def entries(self, start, end, factory):
        batch = 500
        rv = []
        done = False
        while start < end and not done:
            contents, _ = self._client("GET", self._path + "/entries/" + str(start) + \
                                       "-" + str(min(start + batch, end)) + factory.format())
            gotOne = False
            for x in json.loads(contents)["entries"]:
                rv.append(factory.create_from_bytes(base64.b64decode(x["leaf_data"])))
                start += 1
                gotOne = True

            if not gotOne:
                done = True
        return rv

    def inclusion_proof(self, tree_size, leaf):
        value, _ = self._client("GET", self._path + "/tree/" + str(tree_size) + \
                                "/inclusion/h/" + binascii.hexlify(leaf.leaf_hash()))
        obj = json.loads(value)
        return LogInclusionProof(leaf.leaf_hash(), int(obj['tree_size']), int(obj['leaf_index']), [base64.b64decode(x) for x in obj['proof']])

    def inclusion_proof_by_index(self, tree_size, leaf_index):
        value, _ = self._client("GET", self._path + "/tree/" + str(tree_size) + \
                                "/inclusion/" + str(leaf_index))
        obj = json.loads(value)
        return LogInclusionProof(None, int(obj['tree_size']), int(obj['leaf_index']), [base64.b64decode(x) for x in obj['proof']])

    def verify_inclusion(self, head, leaf):
        proof = self.inclusion_proof(head.tree_size(), leaf)
        proof.verify(head)

    def consistency_proof(self, first_size, second_size):
        value, _ = self._client("GET", self._path + "/tree/" + str(second_size) + \
                                "/consistency/" + str(first_size))
        return LogConsistencyProof(first_size, second_size, \
                                   [base64.b64decode(x) for x in json.loads(value)['proof']])

    def verify_consistency(self, a, b):
        if a is None or b is None or a.tree_size() <= 0 or b.tree_size() <= 0:
            raise VerificationFailedError()

        if a.tree_size() == b.tree_size():
            if a.root_hash() != b.root_hash():
                raise VerificationFailedError()
            return

        if a.tree_size() > b.tree_size():
            a, b = b, a

        proof = self.consistency_proof(a.tree_size(), b.tree_size())
        proof.verify(a, b)

    def verified_latest_tree_head(self, prev):
        head = self.verified_tree_head(prev, HEAD)
        if prev is not None:
            if head.tree_size() <= prev.tree_size():
                return prev
        return head

    def verified_tree_head(self, prev, tree_size):
        if tree_size != 0 and prev is not None and prev.tree_size() == tree_size:
            return prev

        head = self.tree_head(tree_size)
        if prev is not None:
            self.verify_consistency(prev, head)

        return head

    def block_until_present(self, leaf):
        last = -1
        secs = 0
        while 1:
            lth = self.tree_head(HEAD)
            if lth.tree_size() > last:
                last = lth.tree_size()
                try:
                    self.verify_inclusion(lth, leaf)
                    return lth
                except InvalidRangeError:
                    pass
                secs = 1
            else:
                secs *= 2

            time.sleep(secs)

    def verify_supplied_inclusion_proof(self, prev, proof):
        headForIncl = self.verified_tree_head(prev, proof.tree_size())
        proof.verify(headForIncl)
        return headForIncl

    def verify_entries(self, prev, head, factory, auditor):
        if prev is None or prev.tree_size() < head.tree_size():
            stack = []
            if prev is not None and prev.tree_size() > 0:
                p = self.inclusion_proof_by_index(prev.tree_size()+1, prev.tree_size())
                fh = None
                for b in p.audit_path():
                    if fh is None:
                        fh = b
                    else:
                        fh = node_merkle_tree_hash(b, fh)
                if fh != prev.root_hash():
                    raise VerificationFailedError()
                for b in p.audit_path()[::-1]:
                    stack.append(b)
            idx = 0
            if prev is not None:
                idx = prev.tree_size()
            for e in self.entries(idx, head.tree_size(), factory):
                auditor.audit_log_entry(idx, e)
                stack.append(e.leaf_hash())
                z = idx
                while (z & 1) == 1:
                    stack[-2:] = [node_merkle_tree_hash(stack[-2], stack[-1])]
                    z >>= 1
                idx += 1
            if idx != head.tree_size():
                raise NotAllEntriesReturnedError()

            while len(stack) > 1:
                stack[-2:] = [node_merkle_tree_hash(stack[-2], stack[-1])]

            if stack[0] != head.root_hash():
                raise VerificationFailedError()


def node_merkle_tree_hash(l, r):
    return hashlib.sha256(chr(1) + l + r).digest()


def leaf_merkle_tree_hash(b):
    return hashlib.sha256(chr(0) + b).digest()


def is_pow_2(n):
    return calc_k(n + 1) == n


def calc_k(n):
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def generate_map_default_leaf_values():
    rv = [None] * 257
    rv[256] = leaf_merkle_tree_hash('')
    for i in range(255, -1, -1):
        rv[i] = node_merkle_tree_hash(rv[i+1], rv[i+1])
    return rv

DEFAULT_LEAF_VALUES = generate_map_default_leaf_values()


def construct_map_key_path(key):
    h = hashlib.sha256(key).digest()
    rv = [False] * len(h) * 8
    for i, b in enumerate(h):
        for j in range(8):
            if (ord(b)>>j)&1 == 1:
                rv[(i<<3)+7-j] = True
    return rv
