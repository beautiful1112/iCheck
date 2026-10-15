import assert from "node:assert/strict";
import test from "node:test";
import {checkedRuntimeInput,runtimeDefaults,runtimeFields,setRuntimeField} from "../lib/runtime-input.ts";

const schema={type:"object",additionalProperties:false,required:["device_id","limit"],properties:{
  device_id:{type:"string",minLength:1,maxLength:36},limit:{type:"integer",minimum:1,maximum:10},
  severity:{enum:["warning","critical"]},verify:{type:"boolean"},note:{type:["string","null"]},
  credential_ref:{type:"string"},nested:{type:"object"},mixed:{type:["string","number"]}}};
test("scalar inputs use ordinary fields while complex inputs remain in Advanced",()=>{
  const fields=runtimeFields(schema);assert.deepEqual(fields.map(row=>row.name),["device_id","limit","severity","verify","note","credential_ref"]);
  assert.equal(fields[0].label,"Device");assert.equal(fields[0].required,true);assert.equal(fields[2].type,"string");
});
test("defaults never manufacture a target, counter, boolean or enum selection",()=>{
  assert.deepEqual(runtimeDefaults(schema),{});
  assert.deepEqual(runtimeDefaults({...schema,properties:{...schema.properties,limit:{type:"integer",default:3},token:{type:"string",default:"must-not-appear"}}}),{limit:3});
});
test("field edits preserve nested JSON and optional omission, and retain real scalar types",()=>{
  const fields=Object.fromEntries(runtimeFields(schema).map(row=>[row.name,row]));
  let value=JSON.stringify({device_id:"device-1",nested:{retained:true}});
  value=setRuntimeField(value,fields.limit,"-1");assert.equal(JSON.parse(value).limit,-1);
  value=setRuntimeField(value,fields.limit,"3");value=setRuntimeField(value,fields.severity,"1");value=setRuntimeField(value,fields.verify,"false");
  assert.deepEqual(checkedRuntimeInput(value,schema),{device_id:"device-1",nested:{retained:true},limit:3,severity:"critical",verify:false});
  value=setRuntimeField(value,fields.severity,"");assert.equal("severity" in JSON.parse(value),false);
});
test("client rejects malformed, missing, nonfinite and out-of-range inputs before launch",()=>{
  for(const value of ["[]","broken","{}",JSON.stringify({device_id:"",limit:3}),JSON.stringify({device_id:"device-1",limit:1.5}),JSON.stringify({device_id:"device-1",limit:11}),JSON.stringify({device_id:"device-1",limit:"NaN"})])assert.throws(()=>checkedRuntimeInput(value,schema));
  assert.deepEqual(checkedRuntimeInput(JSON.stringify({device_id:"device-1",limit:2,note:null}),schema),{device_id:"device-1",limit:2,note:null});
});
test("inline credentials cannot become ordinary fields or be submitted as inputs",()=>{
  assert.equal(runtimeFields({properties:{password:{type:"string"},api_key:{type:"string"},token_ref:{type:"string"}}}).length,1);
  assert.throws(()=>checkedRuntimeInput(JSON.stringify({password:"never-send"}),{}),/protected credential references/);
});
test("Advanced input retains large enums and string lengths use Unicode code points",()=>{
  const large={properties:{choice:{type:"string",enum:Array.from({length:110},(_,index)=>`choice-${index}`)}}};
  assert.deepEqual(runtimeFields(large),[]);
  assert.deepEqual(checkedRuntimeInput('{"choice":"choice-109"}',large),{choice:"choice-109"});
  const unicode={properties:{note:{type:"string",minLength:1,maxLength:1}}};
  assert.deepEqual(checkedRuntimeInput('{"note":"😀"}',unicode),{note:"😀"});
});
