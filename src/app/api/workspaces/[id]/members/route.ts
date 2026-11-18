import {NextRequest} from 'next/server';import {z} from 'zod';
import {db} from '@/lib/db';import {requireUser,workspaceAccess} from '@/lib/auth';
import {json,fail,HttpError,requireOrigin,parseJSON} from '@/lib/http';
export const runtime='nodejs';
export async function GET(_req:NextRequest,ctx:{params:Promise<{id:string}>}){
 try{const user=await requireUser(),{id}=await ctx.params;await workspaceAccess(user.id,id);
  return json(await db()`SELECT m.user_id,m.role,u.name,u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.workspace_id=${id}::uuid ORDER BY m.created_at`);
 }catch(e){return fail(e);}
}
export async function POST(req:NextRequest,ctx:{params:Promise<{id:string}>}){
 try{requireOrigin(req);const user=await requireUser(),{id}=await ctx.params;await workspaceAccess(user.id,id,'manager');
  const input=z.object({email:z.string().email(),role:z.enum(['admin','security_manager','developer','viewer'])}).safeParse(await parseJSON(req));if(!input.success)throw new HttpError(400,'Invalid member');
  const sql=db();const [member]=await sql`SELECT id FROM users WHERE email=${input.data.email.toLowerCase().trim()}`;
  if(!member)throw new HttpError(404,'User must register before being added to a workspace');
  await sql`INSERT INTO memberships(workspace_id,user_id,role) VALUES(${id}::uuid,${member.id}::uuid,${input.data.role}) ON CONFLICT(workspace_id,user_id) DO UPDATE SET role=EXCLUDED.role`;
  await sql`INSERT INTO audit_events(workspace_id,actor_id,action,subject_type,subject_id,after) VALUES(${id}::uuid,${user.id}::uuid,'membership.updated','user',${String(member.id)},${sql.json(input.data)})`;
  return json({ok:true});
 }catch(e){return fail(e);}
}
