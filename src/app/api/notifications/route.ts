import {NextRequest} from 'next/server';import {db} from '@/lib/db';
import {requireUser,workspaceAccess} from '@/lib/auth';import {json,fail,HttpError} from '@/lib/http';
export const runtime='nodejs';
export async function GET(req:NextRequest){
 try{const user=await requireUser(),id=req.nextUrl.searchParams.get('workspaceId');if(!id)throw new HttpError(400,'Workspace required');await workspaceAccess(user.id,id);
  return json(await db()`SELECT id,title,body,read_at,created_at FROM notifications WHERE workspace_id=${id}::uuid AND (user_id IS NULL OR user_id=${user.id}::uuid) ORDER BY created_at DESC LIMIT 200`);
 }catch(e){return fail(e);}
}
