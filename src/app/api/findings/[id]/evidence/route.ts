import {NextRequest} from 'next/server';import {z} from 'zod';
import {db} from '@/lib/db';import {requireUser,workspaceAccess} from '@/lib/auth';
import {json,fail,HttpError,requireOrigin,parseJSON} from '@/lib/http';
export const runtime='nodejs';
export async function GET(_req:NextRequest,ctx:{params:Promise<{id:string}>}){
 try{const user=await requireUser(),{id}=await ctx.params,sql=db();const [f]=await sql`SELECT workspace_id FROM findings WHERE id=${id}::uuid`;
  if(!f)throw new HttpError(404,'Finding not found');await workspaceAccess(user.id,String(f.workspace_id));
  const [evidence,comments,activity]=await Promise.all([
   sql`SELECT e.id,e.evidence_url,e.notes,e.created_at,u.name AS author FROM test_evidence e JOIN users u ON u.id=e.author_id WHERE e.finding_id=${id}::uuid ORDER BY e.created_at DESC`,
   sql`SELECT c.id,c.body,c.created_at,u.name AS author FROM comments c JOIN users u ON u.id=c.author_id WHERE c.finding_id=${id}::uuid ORDER BY c.created_at DESC`,
   sql`SELECT a.action,a.before,a.after,a.reason,a.created_at,u.name AS author FROM audit_events a LEFT JOIN users u ON u.id=a.actor_id WHERE a.subject_type='finding' AND a.subject_id=${id} AND a.workspace_id=${f.workspace_id}::uuid ORDER BY a.created_at DESC LIMIT 100`
  ]);return json({evidence,comments,activity});
 }catch(e){return fail(e);}
}
export async function POST(req:NextRequest,ctx:{params:Promise<{id:string}>}){
 try{requireOrigin(req);const user=await requireUser(),{id}=await ctx.params;
  const input=z.object({type:z.enum(['comment','evidence']),notes:z.string().trim().min(2).max(3000),url:z.string().url().max(1000).optional()}).safeParse(await parseJSON(req));
  if(!input.success)throw new HttpError(400,'Invalid evidence');
  const sql=db();const [f]=await sql`SELECT workspace_id FROM findings WHERE id=${id}::uuid`;
  if(!f)throw new HttpError(404,'Finding not found');await workspaceAccess(user.id,String(f.workspace_id),'editor');
  if(input.data.type==='comment')await sql`INSERT INTO comments(finding_id,author_id,body) VALUES(${id}::uuid,${user.id}::uuid,${input.data.notes})`;
  else await sql`INSERT INTO test_evidence(finding_id,author_id,evidence_url,notes) VALUES(${id}::uuid,${user.id}::uuid,${input.data.url??null},${input.data.notes})`;
  await sql`INSERT INTO audit_events(workspace_id,actor_id,action,subject_type,subject_id,reason) VALUES(${f.workspace_id}::uuid,${user.id}::uuid,${input.data.type+'.created'},'finding',${id},${input.data.notes})`;
  return json({ok:true},201);
 }catch(e){return fail(e);}
}
