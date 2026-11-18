import YAML from 'yaml';
import * as yarn from '@yarnpkg/lockfile';

export type ResolvedPackage={ecosystem:'npm'|'Packagist',name:string,version:string,direct:boolean,sourceFile:string,sourceType:'lockfile'|'sbom'};
const validVersion=(s:unknown):s is string => typeof s==='string'&&s.length>0&&s.length<150&&!s.includes('://')&&!s.startsWith('file:')&&!s.startsWith('link:');
function unique(pkgs:ResolvedPackage[]) {
 const byKey=new Map<string,ResolvedPackage>();
 for(const p of pkgs){if(!p.name||!validVersion(p.version))continue;const key=`${p.ecosystem}:${p.name}:${p.version}:${p.sourceFile}`;const prev=byKey.get(key); if(!prev||p.direct)byKey.set(key,p);}
 return [...byKey.values()];
}
function parsePurl(purl:string):{name:string,version:string,ecosystem:'npm'|'Packagist'}|null {
 // Support only npm and Composer purls in v1; queries require version proof.
 const match=/^pkg:(npm|composer)\/([^?#]+)@([^?#]+)(?:[?#].*)?$/.exec(purl);
 if(!match)return null;
 try {
  const name=decodeURIComponent(match[2]);const version=decodeURIComponent(match[3]);
  if(!name||!validVersion(version))return null;
  return {name,version,ecosystem:match[1]==='composer'?'Packagist':'npm'};
 } catch{return null;}
}
export function parseSpdx(input:unknown,filename='sbom.spdx.json'):ResolvedPackage[] {
 if(!input||typeof input!=='object')throw new Error('Invalid SPDX document');
 const doc=input as Record<string,unknown>;
 if(typeof doc.spdxVersion!=='string'||!doc.spdxVersion.startsWith('SPDX-')||!Array.isArray(doc.packages))throw new Error('Expected SPDX JSON packages');
 const dependencies=new Map<string,string[]>();
 for(const item of (Array.isArray(doc.relationships)?doc.relationships:[])) {
  if(!item||typeof item!=='object')continue;
  const r=item as Record<string,unknown>;
  if(r.relationshipType==='DEPENDS_ON'&&typeof r.spdxElementId==='string'&&typeof r.relatedSpdxElement==='string') {
    dependencies.set(r.spdxElementId,[...(dependencies.get(r.spdxElementId)||[]),r.relatedSpdxElement]);
  }
 }
 const roots=new Set<string>();
 for(const item of (Array.isArray(doc.relationships)?doc.relationships:[])) {
  if(item&&typeof item==='object'&&(item as Record<string,unknown>).relationshipType==='DESCRIBES'&&typeof (item as Record<string,unknown>).relatedSpdxElement==='string')roots.add((item as Record<string,string>).relatedSpdxElement);
 }
 const directIds=new Set([...roots].flatMap(id=>dependencies.get(id)||[]));
 const out:ResolvedPackage[]=[];
 for(const item of doc.packages){
  if(!item||typeof item!=='object')continue;
  const p=item as Record<string,unknown>;
  const refs=Array.isArray(p.externalRefs)?p.externalRefs:[];
  for(const ref of refs){
   if(!ref||typeof ref!=='object')continue;
   const r=ref as Record<string,unknown>;
   if(typeof r.referenceLocator!=='string'||!r.referenceLocator.startsWith('pkg:'))continue;
   const parsed=parsePurl(r.referenceLocator);if(!parsed)continue;
   out.push({...parsed,direct:directIds.has(String(p.SPDXID)),sourceFile:filename,sourceType:'sbom'});
   break;
  }
 }
 return unique(out);
}
export function parseCycloneDX(input:unknown,filename='bom.cdx.json'):ResolvedPackage[] {
 if(!input||typeof input!=='object')throw new Error('Invalid CycloneDX document');
 const doc=input as Record<string,unknown>;
 if(doc.bomFormat!=='CycloneDX'||!Array.isArray(doc.components))throw new Error('Expected CycloneDX JSON components');
 const root=(doc.metadata&&typeof doc.metadata==='object'?(doc.metadata as Record<string,unknown>).component:null);
 const rootRef=root&&typeof root==='object'?(root as Record<string,unknown>)['bom-ref']:null;
 const directRefs=new Set<string>();
 if(rootRef&&Array.isArray(doc.dependencies))for(const d of doc.dependencies){if(d&&typeof d==='object'&&(d as Record<string,unknown>).ref===rootRef){for(const dep of (Array.isArray((d as Record<string,unknown>).dependsOn)?(d as Record<string,unknown>).dependsOn:[]) as unknown[])if(typeof dep==='string')directRefs.add(dep);}}
 const out:ResolvedPackage[]=[];
 for(const item of doc.components){
  if(!item||typeof item!=='object')continue;
  const c=item as Record<string,unknown>;
  if(typeof c.purl!=='string')continue; const p=parsePurl(c.purl);if(!p)continue;
  out.push({...p,direct:directRefs.has(String(c['bom-ref'])),sourceFile:filename,sourceType:'sbom'});
 }
 return unique(out);
}
export function parseLockfile(filename:string,content:string,packageManifest?:string):ResolvedPackage[] {
 if(content.length>3_000_000)throw new Error('Input file exceeds 3MB size limit');
 const lower=filename.toLowerCase();
 const root=packageManifest?JSON.parse(packageManifest) as Record<string,unknown>:null;
 const direct=new Set<string>([...Object.keys((root?.dependencies??{}) as object),...Object.keys((root?.devDependencies??{}) as object)]);
 const out:ResolvedPackage[]=[];
 if(lower.endsWith('package-lock.json')){
  const doc=JSON.parse(content) as Record<string,unknown>;
  if(typeof doc.lockfileVersion!=='number')throw new Error('Invalid package-lock: missing lockfileVersion');
  const entries=doc.packages;
  if(entries&&typeof entries==='object'){
   const rootPkg=(entries as Record<string,any>)[''];
   const rootDirect=new Set([...direct,...Object.keys(rootPkg?.dependencies??{}),...Object.keys(rootPkg?.devDependencies??{})]);
   for(const [key,value] of Object.entries(entries as Record<string,any>)){
    if(!key.includes('node_modules/')||!value||!validVersion(value.version))continue;
    const name=key.split('node_modules/').at(-1)!;
    out.push({ecosystem:'npm',name,version:value.version,direct:rootDirect.has(name)&&key===`node_modules/${name}`,sourceFile:filename,sourceType:'lockfile'});
   }
  }else if(doc.dependencies&&typeof doc.dependencies==='object'){
   function walk(node:Record<string,any>,level:number){if(level>50)return;for(const [name,v] of Object.entries(node)){
    if(validVersion(v?.version))out.push({ecosystem:'npm',name,version:v.version,direct:level===0&&direct.has(name),sourceFile:filename,sourceType:'lockfile'});
    if(v?.dependencies&&typeof v.dependencies==='object')walk(v.dependencies,level+1);
   }}walk(doc.dependencies as Record<string,any>,0);
  }
  return unique(out);
 }
 if(lower.endsWith('composer.lock')){
  const doc=JSON.parse(content) as Record<string,unknown>;
  if(!Array.isArray(doc.packages))throw new Error('Invalid composer.lock');
  const composerRoot=root;
  const composerDirect=new Set([...Object.keys((composerRoot?.require??{}) as object),...Object.keys((composerRoot?.['require-dev']??{}) as object)]);
  for(const section of ['packages','packages-dev']){
   const entries=doc[section];if(!Array.isArray(entries))continue;
   for(const item of entries){if(!item||typeof item!=='object')continue;
    const p=item as Record<string,unknown>;
    if(typeof p.name!=='string'||!validVersion(p.version))continue;
    out.push({ecosystem:'Packagist',name:p.name,version:p.version,direct:composerDirect.has(p.name),sourceFile:filename,sourceType:'lockfile'});
   }
  }
  return unique(out);
 }
 if(lower.endsWith('yarn.lock')){
  const result=yarn.parse(content);if(result.type!=='success')throw new Error('Unsupported yarn.lock format (Berry requires SBOM)');
  for(const [selector,value] of Object.entries(result.object)){
   if(!validVersion(value.version))continue;
   const name=selector.startsWith('@')?selector.substring(0,selector.indexOf('/',1)>0?selector.indexOf('@',selector.indexOf('/',1)):selector.lastIndexOf('@')):selector.slice(0,selector.indexOf('@'));
   if(!name)continue;
   out.push({ecosystem:'npm',name,version:value.version,direct:direct.has(name),sourceFile:filename,sourceType:'lockfile'});
  }
  return unique(out);
 }
 if(lower.endsWith('pnpm-lock.yaml')){
  const doc=YAML.parse(content) as Record<string,unknown>;
  if(!doc||!doc.packages||typeof doc.packages!=='object')throw new Error('Invalid pnpm lockfile');
  const importers=doc.importers as Record<string,any>|undefined;
  const selected=importers?.['.'];
  const rootDirect=new Set([...direct,...Object.keys(selected?.dependencies??{}),...Object.keys(selected?.devDependencies??{})]);
  for(const [key,value] of Object.entries(doc.packages as Record<string,any>)){
   let parsed=key.replace(/^\//,'');
   // Strip peer dependency suffix e.g. react@19.0.0(peer@1.0.0)
   parsed=parsed.split('(')[0];const at=parsed.lastIndexOf('@');if(at<1)continue;
   const name=parsed.slice(0,at),version=parsed.slice(at+1);
   if(!validVersion(version)||!value||typeof value!=='object')continue;
   out.push({ecosystem:'npm',name,version,direct:rootDirect.has(name),sourceFile:filename,sourceType:'lockfile'});
  }
  return unique(out);
 }
 throw new Error('Unsupported file type: upload an npm/Composer lockfile or SPDX/CycloneDX JSON');
}
export function parseImport(filename:string,content:string,manifest?:string):ResolvedPackage[] {
 const lower=filename.toLowerCase();
 if(lower.endsWith('.json')&&lower.includes('spdx'))return parseSpdx(JSON.parse(content),filename);
 if(lower.endsWith('.json')&&(lower.includes('cyclonedx')||lower.includes('cdx')))return parseCycloneDX(JSON.parse(content),filename);
 if(lower.endsWith('.json')&&!lower.includes('lock')){
  const doc=JSON.parse(content);
  if(doc?.spdxVersion)return parseSpdx(doc,filename);
  if(doc?.bomFormat==='CycloneDX')return parseCycloneDX(doc,filename);
 }
 return parseLockfile(filename,content,manifest);
}
