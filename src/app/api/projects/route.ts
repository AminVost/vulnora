import {NextRequest} from 'next/server';
import {z} from 'zod';
import {db} from '@/lib/db';
import {requireUser,workspaceAccess} from '@/lib/auth';
import {json,fail,HttpError,requireOrigin,parseJSON} from '@/lib/http';
export const runtime='nodejs';
export async function GET(req:NextRequest){
 try{const user=await requireUser();const id=req.nextUrl.searchParams.get('workspaceId');
  if(!id)throw new HttpError(400,'Workspace is required');await workspaceAccess(user.id,id);
  const records=await db()`SELECT p.*, (SELECT count(*)::int FROM dependencies d WHERE d.project_id=p.id AND d.current) AS dependency_count,
   (SELECT count(*)::int FROM findings f WHERE f.project_id=p.id AND f.status NOT IN('resolved','false_positive','risk_accepted')) AS open_findings,
   (SELECT count(*)::int FROM findings f JOIN vulnerability_advisories a ON a.id=f.advisory_id WHERE f.project_id=p.id AND f.status NOT IN('resolved','false_positive','risk_accepted') AND a.severity='critical') AS critical_findings
   FROM projects p WHERE workspace_id=${id}::uuid ORDER BY created_at DESC`;
  return json(records);
 }catch(e){return fail(e);}
}
const schema=z.object({workspaceId:z.string().uuid(),name:z.string().trim().min(2).max(120),description:z.string().max(600).optional(),repositoryUrl:z.string().url().max(350).optional().or(z.literal('')),
 criticality:z.enum(['low','medium','high','critical']).default('medium'),environment:z.enum(['unknown','development','staging','production']).default('unknown'),exposed:z.boolean().default(false)});
export async function POST(req:NextRequest){
 try{requireOrigin(req);const user=await requireUser();const form=schema.safeParse(await parseJSON(req));if(!form.success)throw new HttpError(400,'Invalid project data');
  const f=form.data;await workspaceAccess(user.id,f.workspaceId,'editor');
  const url=f.repositoryUrl||null;
  if(url){const parsed=new URL(url);if(parsed.protocol!=='https:'||parsed.hostname!=='github.com'||parsed.pathname.split('/').filter(Boolean).length!==2)throw new HttpError(400,'Only public GitHub repository URLs are supported in this release');}
  const [project]=await db()`INSERT INTO projects(workspace_id,name,description,repository_url,source_type,criticality,environment,internet_exposed)
   VALUES(${f.workspaceId}::uuid,${f.name},${f.description??''},${url},${url?'github':'manual'},${f.criticality},${f.environment},${f.exposed}) RETURNING id,name`;
  await db()`INSERT INTO audit_events(workspace_id,actor_id,action,subject_type,subject_id,after)
   VALUES(${f.workspaceId}::uuid,${user.id}::uuid,'project.created','project',${String(project.id)},${db().json({name:f.name})})`;
  return json(project,201);
 }catch(e){return fail(e);}
}
