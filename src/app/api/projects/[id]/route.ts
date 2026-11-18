import {NextRequest} from 'next/server';
import {db} from '@/lib/db';import {requireUser,projectAccess} from '@/lib/auth';import {json,fail} from '@/lib/http';
export const runtime='nodejs';
export async function GET(_req:NextRequest,ctx:{params:Promise<{id:string}>}){
 try{const user=await requireUser(),{id}=await ctx.params;await projectAccess(user.id,id);
  const sql=db();const [[project],dependencies,scans,releases]=await Promise.all([
   sql`SELECT * FROM projects WHERE id=${id}::uuid`,
   sql`SELECT name,version,ecosystem,direct,source_file,source_type FROM dependencies WHERE project_id=${id}::uuid AND current=true ORDER BY name LIMIT 1000`,
   sql`SELECT id,status,error,created_at,finished_at,packages_checked,findings_new FROM scan_jobs WHERE project_id=${id}::uuid ORDER BY created_at DESC LIMIT 30`,
   sql`SELECT r.version,r.git_sha,r.deployed_at,r.provenance,r.verified,e.name AS environment FROM project_releases r LEFT JOIN project_environments e ON e.id=r.environment_id WHERE r.project_id=${id}::uuid ORDER BY r.created_at DESC`
  ]);return json({project,dependencies,scans,releases});
 }catch(e){return fail(e);}
}
