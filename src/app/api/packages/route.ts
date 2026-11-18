import {NextRequest} from 'next/server';import {db} from '@/lib/db';
import {requireUser,workspaceAccess} from '@/lib/auth';import {json,fail,HttpError} from '@/lib/http';
export const runtime='nodejs';
export async function GET(req:NextRequest){
 try{const user=await requireUser(),id=req.nextUrl.searchParams.get('workspaceId');if(!id)throw new HttpError(400,'Workspace required');await workspaceAccess(user.id,id);
  return json(await db()`SELECT d.ecosystem,d.name,count(DISTINCT d.project_id)::int AS projects,
   count(DISTINCT d.version)::int AS versions,string_agg(DISTINCT d.version,', ') AS version_list,
   count(DISTINCT f.id)::int AS findings FROM dependencies d JOIN projects p ON p.id=d.project_id
   LEFT JOIN findings f ON f.dependency_id=d.id AND f.status NOT IN('resolved','false_positive','risk_accepted')
   WHERE p.workspace_id=${id}::uuid AND d.current GROUP BY d.ecosystem,d.name ORDER BY projects DESC,d.name LIMIT 1000`);
 }catch(e){return fail(e);}
}
