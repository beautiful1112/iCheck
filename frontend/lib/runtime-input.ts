/** Small input controls for the existing typed Workflow/Skill contracts. */
export type InputSchema = Record<string, unknown>;
export type RuntimeField = {name:string;label:string;description:string;type:"string"|"number"|"integer"|"boolean";required:boolean;schema:InputSchema;choices:unknown[]};
function record(value:unknown):value is InputSchema{return !!value&&typeof value==="object"&&!Array.isArray(value);}
export function secretInputName(name:string){return /password|secret|token|authorization|api[_-]?key/i.test(name)&&!/(?:_ref|_reference)$/.test(name);}
export function runtimeFields(schema:InputSchema):RuntimeField[]{
  if(!record(schema.properties))return [];
  const required=Array.isArray(schema.required)?schema.required:[];
  const labels:Record<string,string>={device_id:"Device",controller_id:"Wi-Fi controller",backend_id:"Prometheus backend",metric:"Measurement",severity:"Severity"};
  return Object.entries(schema.properties).slice(0,40).flatMap(([name,value])=>{
    if(!record(value)||secretInputName(name)||["$ref","anyOf","oneOf","allOf"].some(key=>key in value))return [];
    if(Array.isArray(value.enum)&&value.enum.length>100)return []; // Keep large selections in full-schema Advanced input.
    const enumeration=Array.isArray(value.enum)?value.enum.filter(item=>item!==null):[];
    const inferred=value.type===undefined&&enumeration.length&&enumeration.every(item=>typeof item===typeof enumeration[0])?typeof enumeration[0]:value.type;
    const types=Array.isArray(value.type)?value.type.filter(item=>item!=="null"):[inferred];
    if(types.length!==1)return [];
    const type=types[0];
    if(!["string","number","integer","boolean"].includes(String(type)))return [];
    const choices=Array.isArray(value.enum)?value.enum.filter(choice=>["string","number","boolean"].includes(typeof choice)).slice(0,100):[];
    return [{name,label:typeof value.title==="string"?value.title.slice(0,200):labels[name]||name.replaceAll("_"," "),
      description:typeof value.description==="string"?value.description.slice(0,1000):"",type:type as RuntimeField["type"],required:required.includes(name),schema:value,choices}];
  });
}
export function runtimeDefaults(schema:InputSchema):Record<string,unknown>{
  return Object.fromEntries(runtimeFields(schema).filter(field=>"default" in field.schema).map(field=>[field.name,field.schema.default]));
}
export function runtimeDocument(value:string):Record<string,unknown>{
  const document=JSON.parse(value) as unknown;
  if(!record(document))throw new Error("Check inputs must be an object");
  return document;
}
export function setRuntimeField(value:string,field:RuntimeField,text:string):string{
  const document=runtimeDocument(value);
  if(text==="")delete document[field.name];
  else if(field.choices.length)document[field.name]=field.choices[Number(text)];
  else if(field.type==="boolean")document[field.name]=text==="true";
  else if(field.type==="number"||field.type==="integer")document[field.name]=Number.isFinite(Number(text))?Number(text):text;
  else document[field.name]=text;
  return JSON.stringify(document,null,2);
}
export function checkedRuntimeInput(value:string,schema:InputSchema):Record<string,unknown>{
  const document=runtimeDocument(value),fields=runtimeFields(schema);
  if(Object.keys(document).some(secretInputName))throw new Error("Select protected credential references; do not enter passwords or tokens as check inputs");
  for(const name of Array.isArray(schema.required)?schema.required:[]){
    if(typeof name==="string"&&!(name in document))throw new Error(`${fields.find(field=>field.name===name)?.label||name} is required`);
  }
  for(const field of fields){
    const current=document[field.name];if(current===undefined)continue;
    if(current===null&&(Array.isArray(field.schema.type)&&field.schema.type.includes("null")||Array.isArray(field.schema.enum)&&field.schema.enum.includes(null)))continue;
    if(field.type==="string"&&typeof current!=="string"||field.type==="boolean"&&typeof current!=="boolean"||
        ["number","integer"].includes(field.type)&&(typeof current!=="number"||!Number.isFinite(current)||field.type==="integer"&&!Number.isInteger(current)))throw new Error(`${field.label} has an invalid value`);
    if(field.choices.length&&!field.choices.includes(current))throw new Error(`Choose a declared ${field.label} value`);
    if(typeof current==="number"&&((typeof field.schema.minimum==="number"&&current<field.schema.minimum)||(typeof field.schema.maximum==="number"&&current>field.schema.maximum)))throw new Error(`${field.label} is outside its declared range`);
    if(typeof current==="string"&&((typeof field.schema.minLength==="number"&&[...current].length<field.schema.minLength)||(typeof field.schema.maxLength==="number"&&[...current].length>field.schema.maxLength)))throw new Error(`${field.label} has an invalid length`);
  }
  // The server still validates the full schema, dependencies, scope and budgets.
  return document;
}
