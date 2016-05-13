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

import continusec

import json
import binascii

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

                    if continusec.object_hash(json.loads(j)) == binascii.unhexlify(a):
                        print 'Match! - ', j
                    else:
                        print 'Fail! - ', j

                    state = 0

test_object_hash("../objecthash/common_json.test")



client = continusec.Client("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6", base_url="http://localhost:8080")
log = client.verifiable_log("newtestlog");
try:
    log.tree_head(continusec.HEAD);
    raise "blah"
except continusec.NotFoundError:
    pass

client = continusec.Client("7981306761429961588", "wrongcred", base_url="http://localhost:8080")
log = client.verifiable_log("newtestlog");
try:
    log.tree_head(continusec.HEAD);
    raise "blah"
except continusec.UnauthorizedError:
    pass

client = continusec.Client("wrongaccount", "wrongcred", base_url="http://localhost:8080")
log = client.verifiable_log("newtestlog");
try:
    log.tree_head(continusec.HEAD);
    raise "blah"
except continusec.NotFoundError:
    pass

client = continusec.Client("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6", base_url="http://localhost:8080")
log = client.verifiable_log("newtestlog");
log.create()
try:
    log.create();
    raise "blah"
except continusec.ObjectConflictError:
    pass

log.add(continusec.RawDataEntry("foo"))
log.add(continusec.JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}"))
log.add(continusec.RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}"))

log.block_until_present(log.add(continusec.RawDataEntry("foo")))

head = log.tree_head(continusec.HEAD)
if head.tree_size() != 3:
    raise "fds"

for i in range(100):
    log.add(continusec.RawDataEntry("foo-%i" % i))

head103 = log.fetch_verified_tree_head(head)
if head103.tree_size() != 103:
    raise "fds"

try:
    log.inclusion_proof(head103, continusec.RawDataEntry("foo27"))
    raise "fds"
except continusec.NotFoundError:
    pass

inclProof = log.inclusion_proof(head103, continusec.RawDataEntry("foo-27"))
inclProof.verify(head103)

try:
    inclProof.verify(head)
    raise "fds"
except continusec.VerificationFailedError:
    pass


head50 = log.tree_head(50)
if head50.tree_size() != 50:
    raise "fsd"

cons = log.consistency_proof(head50, head103)
cons.verify(head50, head103)

try:
    cons.verify(head, head103)
    raise "fds"
except continusec.VerificationFailedError:
    pass

inclProof = log.inclusion_proof(continusec.LogTreeHead(10, None), continusec.RawDataEntry("foo"))

h10 = log.verify_supplied_proof(head103, inclProof)
if h10.tree_size() != 10:
    raise "fds"

class Counter(object):
    def __init__(self):
        self._count = 0
    def audit_log_entry(self, idx, entry):
        entry.data()
        self._count += 1
    def count(self):
        return self._count

c = Counter()
log.audit_log_entries(continusec.LogTreeHead(0, None), head103, continusec.RawDataEntryFactory(), c)
if c.count() != 103:
    raise "bloop"

head1 = log.tree_head(1)
c = Counter()
try:
    log.audit_log_entries(head1, head103, continusec.JsonEntryFactory(), c)
    raise "blah"
except continusec.NotAllEntriesReturnedError:
    pass
if c.count() != 0:
    raise "bloop"

head3 = log.tree_head(3)
c = Counter()
log.audit_log_entries(head1, head3, continusec.JsonEntryFactory(), c)
if c.count() != 2:
    raise "bloop"

c = Counter()
log.audit_log_entries(head50, head103, continusec.RawDataEntryFactory(), c)
if c.count() != 53:
    raise "bloop"

inclProof = log.inclusion_proof(head103, continusec.JsonEntry("{    \"ssn\":  123.4500 ,   \"name\" :  \"adam\"}"))
inclProof.verify(head103)

redEnt = log.entry(2, continusec.RedactedJsonEntryFactory())
dd = redEnt.data()

if 'ssn' in dd:
    raise 'fsdf'
if 'adam' not in dd:
    raise 'fsd'

inclProof = log.inclusion_proof(head103, redEnt)
inclProof.verify(head103)

client = continusec.Client("7981306761429961588", "allseeing", base_url="http://localhost:8080");
log = client.verifiable_log("newtestlog");

redEnt = log.entry(2, continusec.RedactedJsonEntryFactory())
dd = redEnt.data()

if '123.45' not in dd:
    raise 'fsdf'
if 'adam' not in dd:
    raise 'fsd'

inclProof = log.inclusion_proof(head103, redEnt)
inclProof.verify(head103)

'''

'''