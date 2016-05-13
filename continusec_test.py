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


'''


count[0] = 0;
log.auditLogEntries(head50, head103, RawDataEntryFactory.getInstance(), new LogAuditor() {
	public void auditLogEntry(int idx, VerifiableEntry e) throws ContinusecException {
		e.getData();
		count[0]++;
	}
});
if (count[0] != 53) {
	throw new RuntimeException();
}

JsonEntry je = new JsonEntry("{    \"ssn\":  123.4500 ,   \"name\" :  \"adam\"}".getBytes());
inclProof = log.getInclusionProof(head103, je);
inclProof.verify(head103);

VerifiableEntry redEnt = log.get(2, RedactedJsonEntryFactory.getInstance());
String dd = new String(redEnt.getData());
if (dd.indexOf("snn") >= 0) {
	throw new RuntimeException();
}
if (dd.indexOf("adam") < 0) {
	throw new RuntimeException();
}
inclProof = log.getInclusionProof(head103, redEnt);
inclProof.verify(head103);

client = new ContinusecClient("7981306761429961588", "allseeing", "http://localhost:8080");
log = client.verifiableLog("newtestlog");

redEnt = log.get(2, RedactedJsonEntryFactory.getInstance());
dd = new String(redEnt.getData());
if (dd.indexOf("snn") >= 0) {
	throw new RuntimeException();
}
if (dd.indexOf("adam") < 0) {
	throw new RuntimeException();
}
inclProof = log.getInclusionProof(head103, redEnt);
inclProof.verify(head103);
'''