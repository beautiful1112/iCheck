import test from "node:test";
import assert from "node:assert/strict";
import { rememberReplacement, replacementCanApply, replacementCanReview, replacementIntentMatches } from "../lib/source-replacement.ts";

const value = {hostEnabled:true,canApply:true,executorIndependent:true,reviewId:"review",revoked:false,retirementId:null,priorRetirementId:null,expiresAt:"2030-01-01T00:00:00Z"};
test("reviewed metadata enables only a fresh candidate, never retired history", () => {
  assert.equal(replacementCanApply(value,0),true);
  for (const update of [{hostEnabled:false},{canApply:false},{executorIndependent:false},{reviewId:null},{revoked:true},{retirementId:"retired"},{priorRetirementId:"original"},{expiresAt:"invalid"},{expiresAt:"1970-01-01T00:00:00Z"}]) {
    assert.equal(replacementCanApply({...value,...update},0),false);
  }
});
test("independent review requires a current finite expiry and persisted different principal", () => {
  const review = {canReview:true,principalId:"peer",authorPrincipalId:"author",expiresAt:value.expiresAt};
  assert.equal(replacementCanReview(review,0),true);
  for (const update of [{canReview:false},{principalId:null},{principalId:"author"},{expiresAt:"invalid"},{expiresAt:"1970-01-01T00:00:00Z"}]) {
    assert.equal(replacementCanReview({...review,...update},0),false);
  }
  assert.equal(replacementCanReview(review,Date.parse(value.expiresAt)),false);
  assert.equal(replacementCanApply(value,Date.parse(value.expiresAt)),false);
});

test("exact retained mapping updates bounded selector metadata without storing sealed material", () => {
  const request = {id:"mapping",new_source_id:"target",prior_retirement_id:null,author_subject:"author",expires_at:value.expiresAt,snapshot:{private_material:"must-not-enter-selector"}};
  const detail = {request,review:{id:"peer-review",reviewer_subject:"peer"},revocation:null,retirement_id:null};
  const first = rememberReplacement([],detail);
  assert.equal(first.requests.length,1);
  assert.equal(first.requests[0].request_id,"mapping");
  assert.equal(first.requests[0].review_id,"peer-review");
  assert.equal(first.requests[0].revoked,false);
  assert.equal("snapshot" in first.requests[0],false);
  const updated = rememberReplacement(first.requests,{...detail,revocation:{reason:"withdrawn"},retirement_id:"receipt"});
  assert.equal(updated.requests.length,1);
  assert.equal(updated.requests[0].revoked,true);
  assert.equal(updated.requests[0].retirement_id,"receipt");
  const bounded = rememberReplacement(Array.from({length:100},(_,i)=>({...first.requests[0],request_id:"other-"+i})),detail);
  assert.equal(bounded.requests.length,100);
  assert.equal(bounded.requests[0].request_id,"mapping");
  assert.equal(bounded.truncated,true);
});
test("uncertain execution retains exact request and normalized reason", () => {
  const intent={requestId:"original",executionKey:"runtime-key",reason:"exact reason"};
  assert.equal(replacementIntentMatches(intent,"original"," exact reason "),true);
  assert.equal(replacementIntentMatches(intent,"different","exact reason"),false);
  assert.equal(replacementIntentMatches(intent,"original","changed reason"),false);
});
