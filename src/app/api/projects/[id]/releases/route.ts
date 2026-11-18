import {NextRequest} from 'next/server';import {z} from 'zod';
import {db} from '@/lib/db';import {requireUser,projectAccess} from '@/lib/auth';
import {json,fail,HttpError,requireOrigin,parseJSON} from '@/lib/http';
export const runtime='nodejs';
export async function POST(req:NextRequest,ctx:{params:Promise<{id:string}>}){
 try{requireOrigin(req);const user=await requireUser(),{id}=await ctx.params;const p=await projectAccess(user.id,id,'editor');
  const input=z.object({environment:z.string().min(2).max(70),version:z.string().min(1).max(100),gitSha:z.string().max(80).optional(),deployedAt:z.string().datetime().optional()}).safeParse(await parseJSON(req));
  if(!input.success)throw new HttpError(400,'Invalid release');const f=input.data,sql=db();
  const [env]=await sql`INSERT INTO project_environments(project_id,name) VALUES(${id}::uuid,${f.environment}) ON CONFLICT(project_id,name) DO UPDATE SET name=EXCLUDED.name RETURNING id`;
  const [release]=await sql`INSERT INTO project_releases(project_id,environment_id,version,git_sha,deployed_at,provenance,verified)
   VALUES(${id}::uuid,${env.id}::uuid,${f.version},${f.gitSha??null},${f.deployedAt??null},'manual',false) RETURNING id`;
  await sql`INSERT INTO audit_events(workspace_id,actor_id,action,subject_type,subject_id,after) VALUES(${p.workspace_id}::uuid,${user.id}::uuid,'release.recorded','release',${String(release.id)},${sql.json(f)})`;
  return json({id:release.id,verified:false},201);
 }catch(e){return fail(e);}
}
