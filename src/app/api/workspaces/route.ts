import {NextRequest} from 'next/server';
import {z} from 'zod';
import {db} from '@/lib/db';
import {requireUser,workspaceAccess} from '@/lib/auth';
import {json,fail,HttpError,requireOrigin,parseJSON} from '@/lib/http';
export const runtime='nodejs';
export async function GET(){try{const user=await requireUser();return json(await db()`SELECT w.id,w.name,m.role FROM memberships m JOIN workspaces w ON w.id=m.workspace_id WHERE m.user_id=${user.id}::uuid ORDER BY w.created_at`);}catch(e){return fail(e);}}
export async function POST(req:NextRequest){
 try{requireOrigin(req);const user=await requireUser();const input=z.object({name:z.string().trim().min(2).max(100)}).safeParse(await parseJSON(req));
  if(!input.success)throw new HttpError(400,'Workspace name is required');
  const sql=db();
  const result=await sql.begin(async tx=>{
   const [workspace]=await tx`INSERT INTO workspaces(name,created_by) VALUES(${input.data.name},${user.id}::uuid) RETURNING id,name`;
   await tx`INSERT INTO memberships(workspace_id,user_id,role) VALUES(${workspace.id}::uuid,${user.id}::uuid,'owner')`;
   for(const [severity,days] of [['critical',2],['high',7],['medium',30],['low',90]] as const){
    await tx`INSERT INTO sla_policies(workspace_id,severity,deadline_days) VALUES(${workspace.id}::uuid,${severity},${days})`;
   }
   return workspace;
  });return json(result,201);
 }catch(e){return fail(e);}
}
