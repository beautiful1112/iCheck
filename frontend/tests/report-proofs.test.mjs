import test from "node:test";
import assert from "node:assert/strict";
import { reportProofReferences } from "../lib/report-proofs.ts";
const id="12345678-1234-1234-1234-123456789abc";
test("proof selectors normalize exact IDs and drop untrusted extra fields",()=>{
  assert.deepEqual(reportProofReferences([{reference_kind:"source_retirement",reference_id:id.toUpperCase(),authority:true}]),
    [{reference_kind:"source_retirement",reference_id:id}]);
});
test("proof selector bounds and unsupported or duplicate references fail closed",()=>{
  for(const value of [null,[],Array(21).fill({reference_kind:"source_retirement",reference_id:id}),
    [[]],[{reference_kind:["source_retirement"],reference_id:id}],
    [{reference_kind:"arbitrary_tool",reference_id:id}],[{reference_kind:"source_retirement",reference_id:"not-a-uuid"}],
    [{reference_kind:"source_retirement",reference_id:id},{reference_kind:"source_retirement",reference_id:id.toUpperCase()}]]){
    assert.throws(()=>reportProofReferences(value));
  }
});
