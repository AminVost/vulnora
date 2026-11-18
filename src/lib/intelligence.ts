import {db} from './db';
import {parseImport,parseSpdx,ResolvedPackage} from './dependencies';
import {normalizedSeverity,riskProfile} from './risk';

type OSV={id:string,aliases?:string[],summary?:string,details?:string,modified?:string,
 severity?:{type:string,score:string}[],database_specific?:{severity?:string},
 affected?:{package?:{ecosystem?:string,name?:string},ranges?:unknown[]}[]};
function safeError(e:unknown){return e instanceof Error?e.message.slice(0,350):'Unknown external service error';}
async function remoteJson(url:string,options:RequestInit={},timeout=9000):Promise<any>{
 const response=await fetch(url,{...options,signal:AbortSignal.timeout(timeout),cache:'no-store'});
 if(!response.ok)throw new Error(`Remote service returned HTTP ${response.status} (${new URL(url).hostname})`);
 const size=Number(response.headers.get('content-length')||0);
 if(size>5_000_000)throw new Error('External payload exceeds safety limit');
 return response.json();
}
function githubRepo(url:string):{owner:string,repo:string}|null {
 try {const u=new URL(url);if(u.protocol!=='https:'||u.hostname!=='github.com'||u.port)return null;
  const path=u.pathname.replace(/\/$/,'').replace(/\.git$/,'').split('/').filter(Boolean);
  if(path.length!==2||!path.every(s=>/^[\w.-]{1,100}$/.test(s)))return null;
  return {owner:path[0],repo:path[1]};
 }catch{return null;}
}
async function githubJson(path:string):Promise<any>{
 const headers:Record<string,string>={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'Vulnora/0.1'};
 if(process.env.GITHUB_READ_TOKEN) headers.Authorization=`Bearer ${process.env.GITHUB_READ_TOKEN}`;
 return remoteJson(`https://api.github.com${path}`,{headers},12000);
}
async function discoverFromGitHub(repositoryUrl:string):Promise<{packages:ResolvedPackage[],origin:string}> {
 const parsed=githubRepo(repositoryUrl);
 if(!parsed)throw new Error('Only HTTPS github.com/owner/repo URLs are supported in public-repository scans');
 const path=`/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}`;
 try{
  const payload=await githubJson(`${path}/dependency-graph/sbom`);
  const pkgs=parseSpdx(payload.sbom,`${parsed.owner}/${parsed.repo}:GitHub-SBOM`);
  if(pkgs.length>0)return {packages:pkgs,origin:'github-sbom'};
 }catch(e){
  // Fall back to public lockfiles. Never pretend repository metadata proves production versions.
  console.warn('GitHub SBOM unavailable:',safeError(e));
 }
 async function getFile(file:string):Promise<string|null>{
  try {const response=await githubJson(`${path}/contents/${encodeURIComponent(file)}`);
   if(response?.type!=='file'||response.size>3_000_000||response.encoding!=='base64')return null;
   return Buffer.from(response.content.replace(/\s/g,''),'base64').toString('utf8');
  }catch{return null;}
 }
 const candidates=['package-lock.json','composer.lock','pnpm-lock.yaml','yarn.lock'];
 const packages:ResolvedPackage[]=[];
 for(const filename of candidates){
  const file=await getFile(filename);if(!file)continue;
  const manifest=await getFile(filename==='composer.lock'?'composer.json':'package.json');
  try{packages.push(...parseImport(filename,file,manifest??undefined));}catch(e){console.warn('Lockfile parse issue:',filename,safeError(e));}
 }
 if(!packages.length)throw new Error('No supported resolved dependencies found. Upload a lockfile or SBOM. Manifest-only versions are not sufficient.');
 return {packages,origin:'github-lockfiles'};
}
async function storeSnapshot(projectId:string,packages:ResolvedPackage[],origin:string){
 const sql=db();
 const [snap]=await sql`INSERT INTO dependency_snapshots(project_id,origin,source_type,package_count)
 VALUES (${projectId}::uuid,${origin},${origin.startsWith('github')?'repository':'uploaded'},${packages.length}) RETURNING id`;
 await sql`UPDATE dependencies SET current=false WHERE project_id=${projectId}::uuid`;
 for(const p of packages){
  const [pkg]=await sql`INSERT INTO packages(ecosystem,name) VALUES (${p.ecosystem},${p.name})
   ON CONFLICT(ecosystem,name) DO UPDATE SET name=EXCLUDED.name RETURNING id`;
  const [ver]=await sql`INSERT INTO package_versions(package_id,version) VALUES (${pkg.id},${p.version})
   ON CONFLICT(package_id,version) DO UPDATE SET version=EXCLUDED.version RETURNING id`;
  await sql`INSERT INTO dependencies(project_id,snapshot_id,package_id,package_version_id,ecosystem,name,version,direct,source_file,source_type,current)
   VALUES(${projectId}::uuid,${snap.id}::uuid,${pkg.id}::uuid,${ver.id}::uuid,${p.ecosystem},${p.name},${p.version},${p.direct},${p.sourceFile},${p.sourceType},true)
   ON CONFLICT(project_id,ecosystem,name,version,source_file) DO UPDATE SET
    snapshot_id=EXCLUDED.snapshot_id,direct=EXCLUDED.direct,source_type=EXCLUDED.source_type,current=true`;
 }
 return snap.id as string;
}
export async function importDependencies(projectId:string,filename:string,content:string,manifest?:string) {
 const pkgs=parseImport(filename,content,manifest);
 if(!pkgs.length)throw new Error('No resolved packages could be extracted from this file');
 await storeSnapshot(projectId,pkgs,`upload:${filename}`);
 return pkgs.length;
}
async function fetchKev():Promise<Set<string>|null>{
 try{
  const feed=await remoteJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',{},11000);
  if(!Array.isArray(feed.vulnerabilities))return null;
  return new Set<string>(feed.vulnerabilities.map((v:any)=>v.cveID).filter((s:any)=>typeof s==='string'));
 }catch{return null;}
}
async function fetchEpss(cves:string[]):Promise<Map<string,number>>{
 if(!cves.length)return new Map();
 try{
  const feed=await remoteJson(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cves.join(','))}`,{},7500);
  const out=new Map<string,number>();
  for(const x of Array.isArray(feed.data)?feed.data:[]){const score=Number(x.epss);if(typeof x.cve==='string'&&Number.isFinite(score)&&score>=0&&score<=1)out.set(x.cve,score);}
  return out;
 }catch{return new Map();}
}
function canonicalId(v:OSV){
 const candidates=[v.id,...(v.aliases||[])];
 return candidates.find(x=>/^CVE-\d{4}-\d{4,}$/i.test(x))??candidates.find(x=>/^GHSA-/.test(x))??v.id;
}
async function osvBatch(list:{name:string,ecosystem:string,version:string}[]):Promise<OSV[][]>{
 const response=await remoteJson('https://api.osv.dev/v1/querybatch',{
  method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({queries:list.map(x=>({package:{name:x.name,ecosystem:x.ecosystem},version:x.version}))})
 },25000);
 if(!Array.isArray(response.results)||response.results.length!==list.length)throw new Error('Invalid OSV response');
 const all:OSV[][]=[];
 for(const r of response.results){
  if(r.next_page_token)throw new Error('OSV result pagination required: incomplete results; scan not marked successful');
  all.push(Array.isArray(r.vulns)?r.vulns:[]);
 }
 return all;
}
async function advisory(id:string):Promise<OSV>{
 const record=await remoteJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,{},10000);
 if(!record||typeof record.id!=='string')throw new Error('Invalid OSV advisory');
 return record as OSV;
}
export async function processScanJob(jobId:string):Promise<void>{
 const sql=db();
 const [claimed]=await sql`UPDATE scan_jobs SET status='running',started_at=now(),error=null
  WHERE id=${jobId}::uuid AND (status='queued' OR (status='running' AND started_at < now()-interval '10 minutes'))
  RETURNING id,workspace_id,project_id`;
 if(!claimed)return;
 const pid=String(claimed.project_id),wid=String(claimed.workspace_id);
 try{
  const [project]=await sql`SELECT * FROM projects WHERE id=${pid}::uuid AND workspace_id=${wid}::uuid`;
  if(!project)throw new Error('Project was removed');
  if(project.repository_url&&project.source_type==='github'){
   const fresh=await discoverFromGitHub(project.repository_url);
   await storeSnapshot(pid,fresh.packages,fresh.origin);
  }
  const deps=await sql`SELECT id,name,version,ecosystem,direct,source_file FROM dependencies WHERE project_id=${pid}::uuid AND current=true ORDER BY name`;
  if(!deps.length)throw new Error('No resolved dependencies. Import a lockfile/SBOM or connect a public repository first.');
  if(deps.length>200)throw new Error(`Scan exceeds the initial 200-package execution limit (${deps.length} packages); no findings were auto-resolved. Divide the SBOM or use a dedicated worker.`);
  const kev=await fetchKev();
  let total=0,newFindings=0;
  for(let i=0;i<deps.length;i+=40){
   const slice=deps.slice(i,i+40);
   const matches=await osvBatch(slice.map(p=>({name:String(p.name),version:String(p.version),ecosystem:String(p.ecosystem)})));
   const identifiers=[...new Set(matches.flat().map(x=>x.id))];
   const details=new Map<string,OSV>();
   // Bounded parallelism to respect APIs and function duration.
   for(let k=0;k<identifiers.length;k+=6){
    const records=await Promise.all(identifiers.slice(k,k+6).map(advisory));
    for(const record of records)details.set(record.id,record);
   }
   const allCves=[...new Set([...details.values()].flatMap(v=>[v.id,...(v.aliases||[])]).filter(v=>/^CVE-\d{4}-/.test(v)))];
   const epss=await fetchEpss(allCves);
   for(let j=0;j<slice.length;j++){
    const dep=slice[j];
    const uniqueInDependency=new Set<string>();
    for(const stub of matches[j]){
     const v=details.get(stub.id);if(!v)throw new Error('Missing OSV advisory data');
     const key=canonicalId(v);if(uniqueInDependency.has(key))continue;
     uniqueInDependency.add(key);
     const aliases=[...new Set([v.id,...(v.aliases||[])])];
     const cve=aliases.find(a=>a.startsWith('CVE-'));
     const isKev=cve&&kev?kev.has(cve):null;
     const eps=cve&&epss.has(cve)?epss.get(cve)!:null;
     const severity=normalizedSeverity(v.database_specific?.severity);
     const risk=riskProfile({severity,kev:isKev??null,epss:eps,
       criticality:String(project.criticality),environment:String(project.environment),exposed:Boolean(project.internet_exposed),direct:Boolean(dep.direct)});
     // Store provider vector, but do not invent a numeric CVSS score without a reliable parser.
     const vector=v.severity?.find(s=>s.type.startsWith('CVSS'))?.score||null;
     await sql`INSERT INTO vulnerability_advisories(id,summary,details,severity,cvss_vector,aliases,kev,epss,modified_at,raw)
      VALUES(${key},${(v.summary||v.id).slice(0,500)},${(v.details||'').slice(0,20000)},${severity},${vector},${aliases},${isKev??null},${eps},${v.modified??null},${sql.json(v as any)})
      ON CONFLICT(id) DO UPDATE SET summary=EXCLUDED.summary,details=EXCLUDED.details,
       severity=EXCLUDED.severity,cvss_vector=EXCLUDED.cvss_vector,aliases=EXCLUDED.aliases,
       kev=EXCLUDED.kev,epss=EXCLUDED.epss,modified_at=EXCLUDED.modified_at,raw=EXCLUDED.raw,fetched_at=now()`;
     for(const a of aliases){await sql`INSERT INTO advisory_aliases(alias,advisory_id) VALUES(${a},${key}) ON CONFLICT DO NOTHING`;}
     const [existing]=await sql`SELECT id,status FROM findings WHERE project_id=${pid}::uuid AND dependency_id=${dep.id}::uuid AND advisory_id=${key}`;
     const [finding]=await sql`INSERT INTO findings(workspace_id,project_id,dependency_id,advisory_id,priority,risk_score,risk_reason)
      VALUES(${wid}::uuid,${pid}::uuid,${dep.id}::uuid,${key},${risk.priority},${risk.score},${risk.reason})
      ON CONFLICT(project_id,dependency_id,advisory_id) DO UPDATE SET last_seen_at=now(),
       status=CASE WHEN findings.status='resolved' THEN 'reopened' ELSE findings.status END,
       resolved_at=CASE WHEN findings.status='resolved' THEN null ELSE findings.resolved_at END,
       priority=EXCLUDED.priority,risk_score=EXCLUDED.risk_score,risk_reason=EXCLUDED.risk_reason
      RETURNING id`;
     if(!existing){newFindings++;
      await sql`INSERT INTO notifications(workspace_id,title,body,fingerprint)
       VALUES(${wid}::uuid,${severity.toUpperCase()+' advisory detected'},${key+' in '+project.name},${'finding:'+finding.id}) ON CONFLICT DO NOTHING`;
      await sql`INSERT INTO audit_events(workspace_id,action,subject_type,subject_id,after)
       VALUES(${wid}::uuid,'finding.discovered','finding',${String(finding.id)},${sql.json({advisory:key,source:'OSV'})})`;
     }
    }
   }
   total+=slice.length;
   await sql`UPDATE scan_jobs SET packages_checked=${total},findings_new=${newFindings} WHERE id=${jobId}::uuid`;
  }
  // Auto-resolution is performed only after all queries and advisory fetches succeed.
  await sql`UPDATE findings SET status='resolved',resolved_at=now(),closure_reason='Not detected in complete scan'
    WHERE project_id=${pid}::uuid AND status IN ('open','triaged','in_progress','ready_for_verification','reopened')
    AND last_seen_at < (SELECT started_at FROM scan_jobs WHERE id=${jobId}::uuid)`;
  await sql`UPDATE projects SET last_scanned_at=now() WHERE id=${pid}::uuid`;
  await sql`UPDATE scan_jobs SET status='completed',finished_at=now(),packages_checked=${total},findings_new=${newFindings} WHERE id=${jobId}::uuid`;
 }catch(e){
  await sql`UPDATE scan_jobs SET status='failed',finished_at=now(),error=${safeError(e)} WHERE id=${jobId}::uuid`;
  console.error('Scan failed:',jobId,safeError(e));
 }
}
export async function processNextQueuedJob(){
 const sql=db();
 const rows=await sql`SELECT id FROM scan_jobs WHERE status='queued' OR
  (status='running' AND started_at < now()-interval '10 minutes') ORDER BY created_at LIMIT 1`;
 if(!rows[0])return null;
 await processScanJob(String(rows[0].id));
 return String(rows[0].id);
}
