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
Python Client for Continusec APIs.

Get started by instantiate a Client and then use this to get pointers to map and log
objects that subsequent API calls may be made on.
"""

import binascii
import httplib
import urlparse
import json
import base64
import hashlib
import unicodedata
import time


HEAD = 0


class ContinusecError(Exception):
    """Base class for exceptions in this module"""
    pass


class InvalidRangeError(ContinusecError):
    """
    Indicates invalid size or range in the request, e.g. tree size too large or small.
    """
    pass


class UnauthorizedError(ContinusecError):
    """
    Indicates that either the wrong API Key is being used, or the account is suspended
    for other reasons (check billing status in console).
    """
    pass


class NotFoundError(ContinusecError):
    """Indicates the object cannot be found."""
    pass


class InternalError(ContinusecError):
    """Indicates internal error that occurred on the server."""
    pass


class ObjectHashError(ContinusecError):
    """Indicates an error working with the objecthash for an object."""
    pass


class ObjectConflictError(ContinusecError):
    """Indicates that object being modified already exists."""
    pass


class VerificationFailedError(ContinusecError):
    """Indicates the verification of a proof has failed."""
    pass


class NotAllEntriesReturnedError(ContinusecError):
    """
    Indicates that not all entries were returned. Typically due to requesting Json, but
    not storing as such.
    """
    pass


def object_hash_list(o, prefix):
    """Private method. Use object_hash()."""
    h = hashlib.sha256()
    h.update('l')
    for a in o:
        h.update(object_hash_with_redaction(a, prefix))
    return h.digest()


def object_hash_dict(o, prefix):
    """Private method. Use object_hash()."""
    x = []
    for k, v in o.items():
        x.append(object_hash_with_redaction(k, prefix) +
                 object_hash_with_redaction(v, prefix))
    x.sort()
    h = hashlib.sha256()
    h.update('d')
    for a in x:
        h.update(a)
    return h.digest()


def object_hash_float(o):
    """Private method. Use object_hash()."""
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
    """
    Return the objecthash (https://github.com/benlaurie/objecthash) for an object.
    o is the object.
    """
    return object_hash_with_redaction(o, prefix=None)


def object_hash_with_redaction(o, prefix="***REDACTED*** Hash: "):
    """
    Return the objecthash (https://github.com/benlaurie/objecthash) for an object.
    o is the object.
    prefix is the prefix to use to indicate that the remainer of a string is a redacted
    objecthash.
    """
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
            return hashlib.sha256('u' +
                                  unicodedata.normalize("NFC", o).encode('utf-8')).digest()
    elif t is float or t is int: # json, sigh, only knows floats, not ints
        return object_hash_float(o * 1.0)
    elif t is bool:
        return hashlib.sha256('b' + ('1' if o else '0')).digest()
    elif o is None:
        return hashlib.sha256('n').digest()
    else:
        raise ObjectHashError()


def shed_redactable(o, prefix="***REDACTED*** Hash: "):
    """
    Given an object in redacted form (ie values of dicts are nonce-tupes, or redacted),
    this function will remove nonce parts and shed any redacted keys. This is useful
    for returning an object to work with.
    o the object.
    prefix the prefix used to indicate redaction.
    """
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
    """
    Main entry point for interacting with Continusec's Verifiable Data Structure APIs.
    """


    def __init__(self, account, api_key, base_url="https://api.continusec.com"):
        """
        Create a Client for a given account with specified API Key. The base_url parameter
        is optional and normally only used for unit tests.

        account the account number, found on the "Settings" tab in the console.
        api_key the API Key, found on the "API Keys" tab in the console.
        base_url the base URL to send API requests to.
        """
        self._account = account
        self._api_key = api_key
        self._base_parts = urlparse.urlparse(base_url)
        self._base_url = base_url

    def verifiable_map(self, name):
        """
        Return a pointer to a verifiable map that belongs to this account.
        name is the name of the map.
        Returned object is a VerifiableMap.
        """
        return VerifiableMap(self._make_request, "/map/" + name)

    def verifiable_log(self, name):
        """
        Return a pointer to a verifiable log that belongs to this account.
        name is the name of the log.
        Returned object is a VerifiableLog.
        """
        return VerifiableLog(self._make_request, "/log/" + name)

    def list_logs(self):
        """
        Return a list of LogInfo objects for each log held by the account.
        """
        data, _ = self._make_request("GET", "/logs")
        obj = json.loads(data)
        return [LogInfo(x["name"]) for x in obj["results"]]

    def list_maps(self):
        """
        Return a list of MapInfo objects for each map held by the account.
        """
        data, _ = self._make_request("GET", "/maps")
        obj = json.loads(data)
        return [MapInfo(x["name"]) for x in obj["results"]]

    def _make_request(self, method, path, data=None):
        """
        Private method.
        """
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
    """
    Class to manage interactions with a Verifiable Map.
    Instantiate by calling client.verifiable_map(name).
    """


    def __init__(self, client, path):
        """
        Private constructor. Use client.verifiable_map(name) to instantiate.
        """
        self._client = client
        self._path = path

    def mutation_log(self):
        """
        Get a pointer to the mutation log that underlies this verifiable map. Since the
        mutation log is managed by the map, it cannot be directly modified, however all
        read operations are supported.
        Note that mutations themselves are stored as Json format, so JsonEntryFactory
        should be used for entry retrieval.
        Returned object is of type VerifiableLog.
        """
        return VerifiableLog(self._client, self._path + '/log/mutation')

    def tree_head_log(self):
        """
        Get a pointer to the tree head log that contains all map root hashes produced by
        this map. Since the tree head log s managed by the map, it cannot be directly
        modified, however all read operations are supported.
        Note that tree heaads themselves are stored as JsonEntry format, so
        JsonEntryFactory should be used for entry retrieval.
        Returned object is of type VerifiableLog.
        """
        return VerifiableLog(self._client, self._path + '/log/treehead')

    def create(self):
        """
        Send API call to create this map. This should only be called once, and subsequent
        calls will cause an exception to be generated.
        """
        self._client("PUT", self._path)

    def destroy(self):
        """
        Destroy will send an API call to delete this map - this operation removes it permanently,
        and renders the name unusable again within the same account, so please use with caution.
        """
        self._client("DELETE", self._path)

    def get(self, key, tree_size, factory):
        """
        For a given key, return the value and inclusion proof for the given tree_size.
        key the key in the map.
        tree_size the tree size.
        f the factory that should be used to instantiate the VerifiableEntry. Typically
        one of RawDataEntryFactory, JsonEntryFactory, RedactedJsonEntryFactory.
        Returned object is of type MapEntryResponse.
        """
        value, headers = self._client("GET", self._path + "/tree/" + str(tree_size) + \
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
        """
        For a given key, fetch the value and inclusion proof, verify the proof for the
        given map_state, then return the value.
        key the key in the map.
        map_state the map state, as returned by verified_map_state() or
        verified_latest_map_state();
        f the factory that should be used to instantiate the VerifiableEntry. Typically
        one of RawDataEntryFactory, JsonEntryFactory, RedactedJsonEntryFactory.
        Returned object is of type VerifiableEntry.
        """
        resp = self.get(key, map_state.map_head().tree_size(), factory)
        resp.verify(map_state.map_head())
        return resp.value()

    def set(self, key, value):
        """
        Set the value for a given key in the map. Calling this has the effect of adding a
        mutation to the mutation log for the map, which then reflects in the root hash for
        the map. This occurs asynchronously.
        key the key to set.
        value the entry to set to key to. Typically one of RawDataEntry}, JsonEntry or
        RedactableJsonEntry.
        Returned object is of type AddEntryResponse, which includes the Merkle Tree Leaf
        hash of the mutation log entry added.
        """
        rv, _ = self._client("PUT", self._path + "/key/h/" + binascii.hexlify(key) +
                             value.format(), value.data_for_upload())
        return AddEntryResponse(base64.b64decode(json.loads(rv)['leaf_hash']))

    def delete(self, key):
        """
        Delete the value for a given key from the map. Calling this has the effect of
        adding a mutation to the mutation log for the map, which then reflects in the root
        hash for the map. This occurs asynchronously.
        key the key to delete.
        Returned object is of type AddEntryResponse, which includes the Merkle Tree Leaf
        hash of the mutation log entry added.
        """
        rv, _ = self._client("DELETE", self._path + "/key/h/" + binascii.hexlify(key))
        return AddEntryResponse(base64.b64decode(json.loads(rv)['leaf_hash']))

    def tree_head(self, tree_size=HEAD):
        """
        Get the tree hash for given tree size.
        tree_size the tree size to retrieve the hash for, use HEAD (0) to indicate the
        latest tree size.
        Returned object is of type MapTreeHead.
        """
        data, _ = self._client("GET", self._path + "/tree/" + str(tree_size))
        obj = json.loads(data)
        return MapTreeHead(LogTreeHead(int(obj['mutation_log']['tree_size']),
                                       None if obj['mutation_log']['tree_hash'] is None
                                       else base64.b64decode(obj['mutation_log']['tree_hash'])),
                           base64.b64decode(obj['map_hash']))

    def block_until_size(self, tree_size):
        """
        Block until the map has caught up to a certain size.
        This polls tree_head() until
        such time as a new tree hash is produced that is of at least this size.
        This is intended for test use.
        tree_size the tree size that we should wait for.
        Returned object the first tree hash that is at least this size (MapTreeHead).
        """
        last = -1
        secs = 0
        while 1:
            lth = self.tree_head(HEAD)
            if lth.mutation_log_tree_head().tree_size() > last:
                last = lth.mutation_log_tree_head().tree_size()
                if last >= tree_size:
                    return lth
                else:
                    secs = 1
            else:
                secs *= 2

            time.sleep(secs)

    def verified_latest_map_state(self, prev):
        """
        verified_latest_map_state fetches the latest MapTreeState, verifies it is
        consistent with, and newer than, any previously passed state.
        prev previously held MapTreeState, may be None to skip consistency checks.
        Return the latest map state (which may be the same as passed in if none newer
        available). Object is of type MapTreeState.
        """
        head = self.verified_map_state(prev, HEAD)
        if prev is not None:
            if head.tree_size() <= prev.tree_size():
                return prev
        return head

    def verified_map_state(self, prev, tree_size):
        """
        verified_map_state returns a wrapper for the MapTreeHead for a given tree size,
        along with a LogTreeHead for the TreeHeadLog that has been verified to contain
        this map tree head.
        The value returned by this will have been proven to be consistent with any passed
        prev value.  Note that the TreeHeadLogTreeHead returned may differ between calls,
        even for the same tree_size, as all future LogTreeHeads can also be proven to
        contain the MapTreeHead.

        Typical clients that only need to access current data will instead use
        verified_latest_map_state()
        prev previously held MapTreeState, may be null to skip consistency checks.
        tree_size the tree size to retrieve the hash for. Pass HEAD (0) to get the latest
        tree size.
        Return the map state for the given size. Object is of type MapTreeState.
        """
        if tree_size != 0 and prev is not None and prev.tree_size() == tree_size:
            return prev

        map_head = self.tree_head(tree_size)
        if prev is not None:
            self.mutation_log().verify_consistency(
                prev.map_head().mutation_log_tree_head(),
                map_head.mutation_log_tree_head())

        thlth = self.tree_head_log().verified_latest_tree_head(None if prev is None else
                                                               prev.tree_head_log_tree_head())
        self.tree_head_log().verify_inclusion(thlth, map_head)

        return MapTreeState(map_head, thlth)


class MapEntryResponse(object):
    """
    Class to represent the response for getting an entry from a map. It contains both the
    value itself, as well as an inclusion proof for how that value fits into the map root
    hash.
    """
    def __init__(self, key, value, tree_size, audit_path):
        """
        Constructor.
        key the key for which this value is valid.
        value the value for this key.
        tree_size the tree size that the inclusion proof is valid for.
        audit_path the inclusion proof for this value in the map for a given tree size.
        """
        self._key = key
        self._value = value
        self._tree_size = tree_size
        self._audit_path = audit_path

    def key(self):
        """Return the key."""
        return self._key

    def value(self):
        """Return the value."""
        return self._value

    def tree_size(self):
        """Return the tree_size."""
        return self._tree_size

    def audit_path(self):
        """Return the audit_path."""
        return self._audit_path

    def verify(self, head):
        """
        For a given tree head, check to see if our proof can produce it for the same tree
        size.
        head is of type MapTreeHead.
        Raises exception if an error occurs. Normal exit (with no return value) indicates
        success.
        """
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
    """
    Factory that produces RawDataEntry instances upon request.
    """
    def create_from_bytes(self, b):
        """
        Instantiate a new entry from bytes as returned by server.
        b is a byte array.
        Returned object is of type RawDataEntry.
        """
        return RawDataEntry(b)

    def format(self):
        """
        Returns the suffix added to calls to GET /entry/xxx.
        """
        return ""


class JsonEntryFactory(object):
    """
    Factory that produces JsonEntry instances upon request.
    """
    def create_from_bytes(self, b):
        """
        Instantiate a new entry from bytes as returned by server.
        b is a byte array.
        Returned object is of type JsonEntry.
        """
        return JsonEntry(b)

    def format(self):
        """
        Returns the suffix added to calls to GET /entry/xxx.
        """
        return "/xjson"


class RedactedJsonEntryFactory(object):
    """
    Factory that produces RedactedJsonEntry instances upon request.
    """
    def create_from_bytes(self, b):
        """
        Instantiate a new entry from bytes as returned by server.
        b is a byte array.
        Returned object is of type RedactedJsonEntry.
        """
        return RedactedJsonEntry(b)

    def format(self):
        """
        Returns the suffix added to calls to GET /entry/xxx.
        """
        return "/xjson"


class RawDataEntry(object):
    """
    Class to represent a log/map entry where no special processing is performed,
    that is, the bytes specified are stored as-is, and are used as-is for input
    to the Merkle Tree leaf function.
    """
    def __init__(self, data):
        """
        Construct a new RawDataEntry with the specified data.
        data is a string.
        """
        self._data = data
    def data(self):
        """Get the data for processing."""
        return self._data
    def data_for_upload(self):
        """Get the data that should be stored."""
        return self._data
    def format(self):
        """
        Get the suffix that should be added to the PUT/POST request for this data
        format.
        """
        return ""
    def leaf_hash(self):
        """Calculate the leaf hash for this entry."""
        return leaf_merkle_tree_hash(self._data)


class JsonEntry(object):
    """
    Class to be used when entry MerkleTreeLeafs should be based on ObjectHash
    rather than the JSON bytes directly. Since there is no canonical encoding for JSON,
    it is useful to hash these objects in a more defined manner.
    """
    def __init__(self, data):
        """data is a string that must be valid JSON."""
        self._data = data
    def data(self):
        """Get the data for processing."""
        return self._data
    def data_for_upload(self):
        """Get the data that should be stored."""
        return self._data
    def format(self):
        """
        Get the suffix that should be added to the PUT/POST request for this data format.
        """
        return "/xjson"
    def leaf_hash(self):
        """Calculate the leaf hash for this entry."""
        return leaf_merkle_tree_hash(object_hash_with_redaction(json.loads(self._data)))


class RedactableJsonEntry(object):
    """
    Class to represent JSON data should be made Redactable by the server upon upload.
    ie change all dictionary values to be nonce-value tuples and control access to fields
    based on the API key used to make the request.
    """
    def __init__(self, data):
        """data is a string that must be valid JSON."""
        self._data = data
    def data_for_upload(self):
        """Get the data that should be stored."""
        return self._data
    def format(self):
        """
        Get the suffix that should be added to the PUT/POST request for this data format.
        """
        return "/xjson/redactable"


class RedactedJsonEntry(object):
    """
    Class to represent redacted entries as returned by the server. Not to be confused
    with RedactableJsonEntry that should be used to represent objects that should
    be made Redactable by the server when uploaded.
    """
    def __init__(self, data):
        """
        data is the raw data respresenting the redacted JSON.
        """
        self._data = data
    def data(self):
        """
        Get the data for processing - this will shed any redacted nonce values and any
        redacted values before returning.
        Return type is a string.
        """
        return json.dumps(shed_redactable(json.loads(self._data)))
    def leaf_hash(self):
        """Calculate the leaf hash for this entry."""
        return leaf_merkle_tree_hash(object_hash_with_redaction(json.loads(self._data)))


class AddEntryResponse(object):
    """
    Contains leaf hash of entry added to log or of mutation for item set/deleted in map.
    Returned by verifiable_log().add() and verifiable_map.set()/delete()
    """
    def __init__(self, leaf_hash):
        """leaf_hash is the leaf hash of the item added."""
        self._leaf_hash = leaf_hash
    def leaf_hash(self):
        """Return the leaf hash."""
        return self._leaf_hash


class LogInfo(object):
    """Metadata about a log."""
    def __init__(self, name):
        """name is the name of the log."""
        self._name = name
    def name(self):
        """Return the name."""
        return self._name


class MapInfo(object):
    """Metadata about a map."""
    def __init__(self, name):
        """name is the name of the map."""
        self._name = name
    def name(self):
        """Return the name."""
        return self._name


class LogTreeHead(object):
    """
    Class to represent the root hash for a log for a given tree size.
    """
    def __init__(self, tree_size, root_hash):
        """
        tree_size is the tree size.
        root_hash is the root hash.
        """
        self._tree_size = tree_size
        self._root_hash = root_hash
    def tree_size(self):
        """Return the tree size."""
        return self._tree_size
    def root_hash(self):
        """Return the root hash."""
        return self._root_hash


class MapTreeHead(object):
    """
    Class for Tree Hash as returned for a map with a given size.
    """
    def __init__(self, mutation_log_tree_head, root_hash):
        """
        Constructor.
        mutation_log_tree_head is a LogTreeHead for the corresponding tree hash for the
        mutation log
        root_hash is the root hash for the map at this size.
        """
        self._mutation_log_tree_head = mutation_log_tree_head
        self._root_hash = root_hash
    def mutation_log_tree_head(self):
        """
        Get corresponding the mutation log tree hash. Returned value is of type
        LogTreeHead.
        """
        return self._mutation_log_tree_head
    def root_hash(self):
        """Return the map root hash for this map size."""
        return self._root_hash
    def tree_size(self):
        """Return the map size for this root hash."""
        return self.mutation_log_tree_head().tree_size()
    def leaf_hash(self):
        """
        Implementation of leaf_hash() so that MapTreeHead can be used easily with
        VerifiableLog.verify_inclusion()
        """
        return leaf_merkle_tree_hash(object_hash({
            "mutation_log": {
                "tree_size": self.tree_size(),
                "tree_hash": base64.b64encode(self.mutation_log_tree_head().root_hash()),
            },
            "map_hash": base64.b64encode(self.root_hash()),
        }))


class MapTreeState(object):
    """
    Class for MapTreeState as returned by VerifiableMap.verified_map_state().
    """
    def __init__(self, map_head, tree_head_log_tree_head):
        """
        Constructor.
        map_head the map tree head for the map (type MapTreeHead).
        tree_head_log_tree_head the tree head for the underlying tree head log that the
        map_head has been verified as being included (type LogTreeHead).
        """
        self._map_head = map_head
        self._tree_head_log_tree_head = tree_head_log_tree_head
    def map_head(self):
        """Return the MapTreeHead."""
        return self._map_head
    def tree_size(self):
        """Return the tree size this state is valid for."""
        return self.map_head().tree_size()
    def tree_head_log_tree_head(self):
        """
        Return the LogTreeHead for the tree head log that the map head has been
        verified to be within.
        """
        return self._tree_head_log_tree_head

class LogConsistencyProof(object):
    """
    Class to represent the result of a call to VerifiableLog.consistency_proof().
    """
    def __init__(self, first_size, second_size, audit_path):
        """
        Creates a new LogConsistencyProof for given tree sizes and auditPath.
        second_size the size of the first tree.
        second_size the size of the second tree.
        audit_path the audit proof returned by the server (array of byte arrays).
        """
        self._first_size = first_size
        self._second_size = second_size
        self._audit_path = audit_path
    def first_size(self):
        """Return the size of the first tree."""
        return self._first_size
    def second_size(self):
        """Return the size of the second tree."""
        return self._second_size
    def audit_path(self):
        """Return the audit path."""
        return self._audit_path
    def verify(self, first, second):
        """
        Verify that the consistency proof stored in this object can produce both the log
        tree heads passed to this method.
        i.e, verify the append-only nature of the log between first.tree_size() and
        second.tree_size().
        first the tree head (type LogTreeHead) for the first tree size
        second the tree head (type LogTreeHead) for the second tree size
        Success is when no exception is thrown.
         """
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
    """
    Class to represent proof of inclusion of an entry in a log.
    """
    def __init__(self, leaf_hash, tree_size, leaf_index, audit_path):
        """
        Create new LogInclusionProof.

        leaf_hash the Merkle Tree Leaf hash of the entry this proof is valid for.
        tree_size the tree size for which this proof is valid.
        leaf_index the index of this entry in the log.
        audit_path the set of Merkle Tree nodes that apply to this entry in order to
        generate the root hash and prove inclusion.
         """
        self._leaf_hash = leaf_hash
        self._tree_size = tree_size
        self._leaf_index = leaf_index
        self._audit_path = audit_path
    def tree_size(self):
        """Return the tree size."""
        return self._tree_size
    def audit_path(self):
        """Return the audit path."""
        return self._audit_path
    def leaf_hash(self):
        """Return the leaf hash."""
        return self._leaf_hash
    def leaf_index(self):
        """Return the leaf index."""
        return self._leaf_index
    def verify(self, head):
        """
        For a given tree head, check to see if our proof can produce it for the same tree
        size.
        head the LogTreeHead to compare
        Success is no error being thrown.
        """
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
    """
    Class to interact with verifiable logs. Call client.verifiable_log(name) to
    instantiate.
    """
    def __init__(self, client, path):
        """
        Private constructor. Use client.verifiable_log(name) to instantiate.
        """
        self._client = client
        self._path = path

    def create(self):
        """
        Send API call to create this log. This should only be called once, and subsequent
        calls will cause an exception to be generated.
        """
        self._client("PUT", self._path)

    def destroy(self):
        """
        Destroy will send an API call to delete this log - this operation removes it permanently,
        and renders the name unusable again within the same account, so please use with caution.
        """
        self._client("DELETE", self._path)

    def add(self, data):
        """
        Send API call to add an entry to the log. Note the entry is added asynchronously,
        so while the library will return as soon as the server acknowledges receipt of
        entry, it may not be reflected in the tree hash (or inclusion proofs) until the
        server has sequenced the entry.

        e the entry to add, often a RawDataEntry, JsonEntry} or RedactableJsonEntry.
        Returns an object of type AddEntryResponse, which includes the Merkle Tree Leaf
        hash of the entry added.
        """
        rv, _ = self._client("POST", self._path + "/entry" + data.format(),
                             data.data_for_upload())
        return AddEntryResponse(base64.b64decode(json.loads(rv)['leaf_hash']))

    def tree_head(self, tree_size=HEAD):
        """
        Get the tree hash for given tree size.

        tree_size the tree size to retrieve the hash for. Pass HEAD (0) to get the latest
        tree size.
        Return the tree hash (LogTreeHead) for the given size (includes the tree size
        actually used, if unknown before running the query).
        """
        data, _ = self._client("GET", self._path + "/tree/" + str(tree_size))
        obj = json.loads(data)
        return LogTreeHead(int(obj['tree_size']), None if obj['tree_hash'] is None else \
                                          base64.b64decode(obj['tree_hash']))

    def entry(self, idx, factory):
        """
        Get the entry at the specified index.
        idx the index to retrieve (starts at zero).
        f the type of entry to return, usually one of RawDataEntryFactory,
        JsonEntryFactory, RedactedJsonEntryFactory.
        Return the entry requested (in the type returned by the factory used).
        """
        rv, _ = self._client("GET", self._path + "/entry/" + str(idx) + factory.format())
        return factory.create_from_bytes(rv)

    def entries(self, start, end, factory):
        """
        Returns an iterator to efficiently fetch a contiguous set of entries. If for any
        reason not all entries are returned, the iterator will terminate early.

        start the first entry to return (int)
        end the last entry to return (int)
        f the type of entry to return, usually one of RawDataEntryFactory,
        JsonEntryFactory, RedactedJsonEntryFactory.
        Return a generator for the entries requested.
         """
        batch = 500
        rv = []
        done = False
        while start < end and not done:
            contents, _ = self._client("GET", self._path + "/entries/" + str(start) + \
                                       "-" + str(min(start + batch, end)) + \
                                       factory.format())
            gotOne = False
            for x in json.loads(contents)["entries"]:
                yield factory.create_from_bytes(base64.b64decode(x["leaf_data"]))
                start += 1
                gotOne = True

            if not gotOne:
                done = True


    def inclusion_proof(self, tree_size, leaf):
        """
        Get an inclusion proof for a given item for a specific tree size. Most clients
        will commonly use verify_inclusion() instead.
        tree_size the tree size for which the inclusion proof should be returned. This is
        usually as returned by tree_head().tree_size().
        leaf the entry for which the inclusion proof should be returned - object must
        implement leaf_hash(). Note that AddEntryResponse and RawDataEntry, JsonEntry,
        RedactedJsonEntry each implement this.
        Return a LogInclusionProof object that can be verified against a given tree hash.
        """
        value, _ = self._client("GET", self._path + "/tree/" + str(tree_size) + \
                                "/inclusion/h/" + binascii.hexlify(leaf.leaf_hash()))
        obj = json.loads(value)
        return LogInclusionProof(leaf.leaf_hash(), int(obj['tree_size']),
                                 int(obj['leaf_index']),
                                 [base64.b64decode(x) for x in obj['proof']])

    def inclusion_proof_by_index(self, tree_size, leaf_index):
        """
        Get an inclusion proof for a specified tree size and leaf index. This is not used
        by typical clients, however it can be useful for audit operations and debugging
        tools. Typical clients will use verify_inclusion().
        tree_size the tree size on which to base the proof.
        leaf_index the leaf index for which to retrieve the inclusion proof.
        Return a partially filled in LogInclusionProof (note it will not include the
        MerkleTreeLeaf hash for the item).
        """
        value, _ = self._client("GET", self._path + "/tree/" + str(tree_size) + \
                                "/inclusion/" + str(leaf_index))
        obj = json.loads(value)
        return LogInclusionProof(None, int(obj['tree_size']), int(obj['leaf_index']),
                                 [base64.b64decode(x) for x in obj['proof']])

    def verify_inclusion(self, head, leaf):
        """
        Get an inclusion proof for a given item and verify it.
        head the tree head (LogTreeHead) for which the inclusion proof should be returned.
        This is usually as returned by tree_head().
        leaf the entry for which the inclusion proof should be returned - object must
        implement leaf_hash(). Note that AddEntryResponse and RawDataEntry, JsonEntry,
        RedactedJsonEntry each implement this.
        Success is indicated by no exception being thrown.
        """
        proof = self.inclusion_proof(head.tree_size(), leaf)
        proof.verify(head)

    def consistency_proof(self, first_size, second_size):
        """
        consistency_proof returns an audit path which contains the set of Merkle Subtree
        hashes that demonstrate how the root hash is calculated for both the first and
        second tree sizes.
        first_size the size of the first tree.
        second_size the size of the second tree.
        Return a LogConsistencyProof object that must be verified.
        """
        value, _ = self._client("GET", self._path + "/tree/" + str(second_size) + \
                                "/consistency/" + str(first_size))
        return LogConsistencyProof(first_size, second_size, \
                                [base64.b64decode(x) for x in json.loads(value)['proof']])

    def verify_consistency(self, a, b):
        """
        verifyConsistency takes two tree heads, retrieves a consistency proof and then
        verifies it.
        The two tree heads may be in either order (even equal), but both must be greater
        than zero and non-nil.
        a one LogTreeHead
        b another LogTreeHead
        Success is indicated by no exception being thrown.
        """
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
        """
        verified_latest_tree_head calls verified_tree_head() with HEAD to fetch the latest
        tree head, and additionally verifies that it is newer than the previously passed
        tree head.
        For first use, pass None to skip consistency checking.
        prev a previously persisted LogTreeHead.
        Return a new LogTreeHead which has been verified to be consistent with the past
        tree head, or if no newer one present, the same value as passed in.
        """
        head = self.verified_tree_head(prev, HEAD)
        if prev is not None:
            if head.tree_size() <= prev.tree_size():
                return prev
        return head

    def verified_tree_head(self, prev, tree_size):
        """
        VerifiedTreeHead is a utility method to fetch a LogTreeHead and verifies that it
        is consistent with a tree head earlier fetched and persisted. For first use, pass
        None for prev, which will bypass consistency proof checking. Tree size may be
        older or newer than the previous head value.
        prev a previously persisted LogTreeHead.
        tree_size the tree size to fetch
        Return a new LogTreeHead, which has been verified to be consistent with the past
        tree head, or if no newer one present, the same value as passed in.
        """
        if tree_size != 0 and prev is not None and prev.tree_size() == tree_size:
            return prev

        head = self.tree_head(tree_size)
        if prev is not None:
            self.verify_consistency(prev, head)

        return head

    def block_until_present(self, leaf):
        """
        Block until the log is able to produce a LogTreeHead that includes the specified
        MerkleTreeLeaf.
        This polls tree_head() and verify_inclusion() until such time as a new LogTreeHead
        is produced that includes the given MerkleTreeLeaf. Exponential back-off is used
        when no tree hash is available. This is intended for test use - the returned tree
        head is not verified for consistency.
        leaf the leaf we should block until included (must implement leaf_hash()).
        Typically this is an AddEntryResponse as returned by add().
        Return the first tree hash that includes this leaf (proof is not verified).
        """
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
        """
        verify_supplied_inclusion_proof is a utility method that fetches any required tree
        heads that are needed to verify a supplied LogInclusionProof. Additionally it will
        ensure that any fetched tree heads are consistent with any prior supplied
        LogTreeHead. For first use, pass None for prev, which will bypass consistency proof
        checking.
        prev a previously persisted LogTreeHead, or none
        proof a LogInclusionProof that may be for a different tree size than
        prev.tree_size()
        Return the verified (for consistency) LogTreeHead that was used for successful
        verification (of inclusion) of the supplied proof. This may be older than the
        LogTreeHead passed in.
        """
        headForIncl = self.verified_tree_head(prev, proof.tree_size())
        proof.verify(headForIncl)
        return headForIncl

    def verify_entries(self, prev, head, factory, auditor):
        """
        Utility method for auditors that wish to audit the full content of a log, as well
        as the log operation.
        This method will retrieve all entries in batch from the log, and ensure that the
        root hash in head can be confirmed to accurately represent the contents
        of all of the log entries. If prev is not None, then additionally it is proven
        that the root hash in head is consistent with the root hash in prev.
        prev a previous LogTreeHead representing the set of entries that have been
        previously audited. To indicate this is has not previously been audited, pass
        None.
        head the LogTreeHead up to which we wish to audit the log. Upon successful
        completion the caller should persist this for a future iteration.
        auditor must implement method audit_log_entry(idx, entry) which is called
        sequentially for each log entry as it is encountered.
        f the type of entry to return, usually one of RawDataEntryFactory,
        JsonEntryFactory, RedactedJsonEntryFactory.
        """
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
    """
    Calculate the Merkle Tree Node Hash for an existing left and right hash
    (HASH(chr(1) || l || r)).
    l the left node hash.
    r the right node hash.
    Return the node hash for the combination.
    """
    return hashlib.sha256(chr(1) + l + r).digest()


def leaf_merkle_tree_hash(b):
    """
    Calculate the Merkle Tree Leaf Hash for an object (HASH(chr(0) || b)).
    b the input to the leaf hash
    Return the leaf hash.
    """
    return hashlib.sha256(chr(0) + b).digest()


def is_pow_2(n):
    """Private method."""
    return calc_k(n + 1) == n


def calc_k(n):
    """Private method."""
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def generate_map_default_leaf_values():
    """
    Generate the set of 257 default values for every level in a sparse Merkle Tree.
    Returns an array of 257 values.
    """
    rv = [None] * 257
    rv[256] = leaf_merkle_tree_hash('')
    for i in range(255, -1, -1):
        rv[i] = node_merkle_tree_hash(rv[i+1], rv[i+1])
    return rv

DEFAULT_LEAF_VALUES = generate_map_default_leaf_values()


def construct_map_key_path(key):
    """
    Create the path in a sparse merkle tree for a given key. ie a boolean array
    representing the big-endian index of the the hash of the key.
    key the key
    Returns a length 256 array of booleans representing left (false) and right (true) path
    in the Sparse Merkle Tree.
    """
    h = hashlib.sha256(key).digest()
    rv = [False] * len(h) * 8
    for i, b in enumerate(h):
        for j in range(8):
            if (ord(b)>>j)&1 == 1:
                rv[(i<<3)+7-j] = True
    return rv
