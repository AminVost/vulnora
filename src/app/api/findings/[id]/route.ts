import {NextRequest} from 'next/server';import {z} from 'zod';
import {db} from '@/lib/db';import {requireUser,workspaceAccess} from '@/lib/auth';
import {json,fail,HttpError,requireOrigin,parseJSON} from '@/lib/http';
export const runtime='nodejs';
const statuses=['open','triaged','in_progress','ready_for_verification','resolved','risk_accepted','false_positive','reopened'] as const;
const schema=z.object({status:z.enum(statuses),reason:z.string().trim().max(1000).default(''),dueAt:z.string().datetime().nullable().optional(),assigneeId:z.string().uuid().nullable().optional()});
export async function PATCH(req:NextRequest,ctx:{params:Promise<{id:string}>}){
 try{requireOrigin(req);const user=await requireUser();const {id}=await ctx.params;
  const form=schema.safeParse(await parseJSON(req));if(!form.success)throw new HttpError(400,'Invalid finding update');
  const f=form.data,sql=db();
  const [old]=await sql`SELECT id,workspace_id,status,due_at,assignee_id FROM findings WHERE id=${id}::uuid`;
  if(!old)throw new HttpError(404,'Finding not found');await workspaceAccess(user.id,String(old.workspace_id),'editor');
  if(['resolved','risk_accepted','false_positive'].includes(f.status)&&f.reason.length<10)throw new HttpError(400,'Closing or accepting risk requires a reason of at least 10 characters');
  if(f.assigneeId){const mem=await sql`SELECT 1 FROM memberships WHERE workspace_id=${old.workspace_id}::uuid AND user_id=${f.assigneeId}::uuid`;if(!mem.length)throw new HttpError(400,'Assignee must belong to this workspace');}
  const [updated]=await sql`UPDATE findings SET status=${f.status},closure_reason=${f.reason||null},
   due_at=${f.dueAt===undefined?old.due_at:f.dueAt},assignee_id=${f.assigneeId===undefined?old.assignee_id:f.assigneeId},
   resolved_at=CASE WHEN ${f.status}='resolved' THEN now() ELSE null END
   WHERE id=${id}::uuid RETURNING id,status`;
  await sql`INSERT INTO audit_events(workspace_id,actor_id,action,subject_type,subject_id,before,after,reason)
   VALUES(${old.workspace_id}::uuid,${user.id}::uuid,'finding.updated','finding',${id},${sql.json({status:old.status,assignee:old.assignee_id})},${sql.json(f)},${f.reason||null})`;
  if(f.status==='risk_accepted')await sql`INSERT INTO risk_acceptances(finding_id,accepted_by,reason) VALUES(${id}::uuid,${user.id}::uuid,${f.reason})`;
  return json(updated);
 }catch(e){return fail(e);}
}
