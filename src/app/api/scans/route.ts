import {NextRequest} from 'next/server';import {db} from '@/lib/db';
import {requireUser,workspaceAccess} from '@/lib/auth';import {json,fail,HttpError} from '@/lib/http';
export const runtime='nodejs';
export async function GET(req:NextRequest){
 try{const user=await requireUser(),id=req.nextUrl.searchParams.get('workspaceId');if(!id)throw new HttpError(400,'Workspace required');await workspaceAccess(user.id,id);
  return json(await db()`SELECT s.id,s.status,s.packages_checked,s.findings_new,s.error,s.created_at,s.started_at,s.finished_at,p.name AS project_name,p.id AS project_id
   FROM scan_jobs s JOIN projects p ON p.id=s.project_id WHERE s.workspace_id=${id}::uuid ORDER BY s.created_at DESC LIMIT 300`);
 }catch(e){return fail(e);}
}
