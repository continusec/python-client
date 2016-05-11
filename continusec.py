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
    elif t is unicode:
        return hashlib.sha256('u' + unicodedata.normalize("NFC", o).encode('utf-8')).digest()
    elif t is str:
        return hashlib.sha256('u' + unicodedata.normalize("NFC", unicode(o)).encode('utf-8')).digest()
    elif t is float or t is int: # json, sigh, only knows floats, not ints
        return object_hash_float(o * 1.0)
    elif t is bool:
        return hashlib.sha256('b' + ('1' if o else '0')).digest()
    elif o is None:
        return hashlib.sha256('n').digest()
    else:
        raise ObjectHashError()


def test_object_hash(path):
    state = 0
    for line in file(path, 'rb'):
        line = line.strip()
        if len(line) > 0:
            if line[0] != '#':
                if state == 0:
                    j = line
                    state = 1
                elif state == 1:
                    a = line

                    if object_hash(json.loads(j)) == binascii.unhexlify(a):
                        print 'Match! - ', j
                    else:
                        print 'Fail! - ', j

                    state = 0


#test_object_hash("../../objecthash/common_json.test")


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
        #print url
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

    def get(self, key, tree_size):
        value, headers = self._client("GET", self._path + "/tree/" + str(tree_size) + \
                                      "/key/h/" + binascii.hexlify(key))
        proof = [None] * 256
        for k, v in headers:
            if k.lower() == 'x-verified-proof':
                for z in v.split(','):
                    x, y = z.split('/')
                    proof[int(x.strip())] = binascii.unhexlify(y.strip())
        return value, proof

    def set(self, key, value):
        self._client("PUT", self._path + "/key/h/" + binascii.hexlify(key), value)

    def delete(self, key):
        self._client("DELETE", self._path + "/key/h/" + binascii.hexlify(key))

    def tree_hash(self, tree_size=HEAD):
        data, _ = self._client("GET", self._path + "/tree/" + str(tree_size))
        obj = json.loads(data)
        return int(obj['mutation_log']['tree_size']), base64.b64decode(obj['map_hash'])


class VerifiableLog(object):
    def __init__(self, client, path):
        self._client = client
        self._path = path

    def create(self):
        self._client("PUT", self._path)

    def add(self, data):
        rv, _ = self._client("POST", self._path + "/entry", data)
        return base64.b64decode(json.loads(rv)['leaf_hash'])

    def tree_hash(self, tree_size=HEAD):
        data, _ = self._client("GET", self._path + "/tree/" + str(tree_size))
        obj = json.loads(data)
        return int(obj['tree_size']), None if obj['tree_hash'] is None else \
                                          base64.b64decode(obj['tree_hash'])

    def get_entry(self, idx):
        rv, _ = self._client("GET", self._path + "/entry/" + str(idx))
        return rv

    def get_entries(self, start, end):
        batch = 500
        rv = []
        while start < end:
            contents, _ = self._client("GET", self._path + "/entries/" + str(start) + \
                                       "-" + str(min(start + batch, end)))
            for x in json.loads(contents)["entries"]:
                rv.append(x["leaf_data"])
                start += 1
        return rv

    def inclusion_proof(self, tree_size, mtlHash):
        value, _ = self._client("GET", self._path + "/tree/" + str(tree_size) + \
                                "/inclusion/h/" + binascii.hexlify(mtlHash))
        obj = json.loads(value)
        return int(obj['leaf_index']), [base64.b64decode(x) for x in obj['proof']]

    def consistency_proof(self, first, second):
        value, _ = self._client("GET", self._path + "/tree/" + str(second) + \
                                "/consistency/" + str(first))
        return [base64.b64decode(x) for x in json.loads(value)['proof']]


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


def verify_log_consistency_proof(first, second, first_hash, second_hash, proof):
    if first < 1 or first >= second:
        return False

    if is_pow_2(first):
        proof = [first_hash] + proof

    fn, sn = first - 1, second - 1
    while fn & 1 == 1:
        fn >>= 1
        sn >>= 1

    if len(proof) == 0:
        return False

    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False

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

    return sn == 0 and first_hash == fr and second_hash == sr


def verify_log_inclusion_proof(idx, tree_size, leaf_hash, root_hash, proof):
    if idx >= tree_size or idx < 0:
        return False

    fn, sn = idx, tree_size - 1
    r = leaf_hash
    for p in proof:
        if fn == sn or fn & 1 == 1:
            r = node_merkle_tree_hash(p, r)
            while not (fn == 0 or fn & 1 == 1):
                fn >>= 1
                sn >>= 1
        else:
            r = node_merkle_tree_hash(r, p)
        fn >>= 1
        sn >>= 1

    return r == root_hash and sn == 0


def verify_map_inclusion_proof(key, value, proof, root_hash):
    kp = construct_map_key_path(key)
    t = leaf_merkle_tree_hash(value)
    for i in range(len(kp) - 1, -1, -1):
        p = proof[i]
        if p is None:
            p = DEFAULT_LEAF_VALUES[i + 1]

        if kp[i]:
            t = node_merkle_tree_hash(p, t)
        else:
            t = node_merkle_tree_hash(t, p)
    return t == root_hash


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
