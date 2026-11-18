import {NextRequest,after} from 'next/server';
import {requireUser,projectAccess} from '@/lib/auth';
import {json,fail,requireOrigin} from '@/lib/http';
import {db} from '@/lib/db';
import {processScanJob} from '@/lib/intelligence';
export const runtime='nodejs';export const maxDuration=60;
export async function POST(req:NextRequest,ctx:{params:Promise<{id:string}>}){
 try {requireOrigin(req);const user=await requireUser();const {id}=await ctx.params;
  const p=await projectAccess(user.id,id,'editor');
  const sql=db();const existing=await sql`SELECT id FROM scan_jobs WHERE project_id=${id}::uuid AND status IN('running','queued') AND created_at>now()-interval '10 minutes' LIMIT 1`;
  if(existing.length)return json({id:existing[0].id,status:'queued_or_running'});
  const [job]=await sql`INSERT INTO scan_jobs(project_id,workspace_id,requested_by) VALUES(${id}::uuid,${p.workspace_id}::uuid,${user.id}::uuid) RETURNING id`;
  after(async()=>{await processScanJob(String(job.id));});
  return json({id:job.id,status:'queued',note:'Job is processed server-side; check Scan Center for completion'},202);
 }catch(e){return fail(e);}
}
