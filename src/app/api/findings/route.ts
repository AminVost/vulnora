import {NextRequest} from 'next/server';
import {db} from '@/lib/db';import {requireUser,workspaceAccess} from '@/lib/auth';import {json,fail,HttpError} from '@/lib/http';
export const runtime='nodejs';
export async function GET(req:NextRequest){
 try{const user=await requireUser(),workspaceId=req.nextUrl.searchParams.get('workspaceId');if(!workspaceId)throw new HttpError(400,'Workspace required');await workspaceAccess(user.id,workspaceId);
  const sql=db();const rows=await sql`SELECT f.id,f.project_id,f.status,f.priority,f.risk_score,f.risk_reason,f.first_seen_at,f.last_seen_at,f.due_at,f.assignee_id,f.closure_reason,
   a.id AS advisory_id,a.summary,a.details,a.aliases,a.severity,a.cvss_score,a.cvss_vector,a.kev,a.epss,a.source,a.fetched_at,
   d.ecosystem,d.name AS package_name,d.version,d.direct,d.source_file,d.source_type,p.name AS project_name,p.environment,p.criticality
   FROM findings f JOIN vulnerability_advisories a ON a.id=f.advisory_id JOIN dependencies d ON d.id=f.dependency_id
   JOIN projects p ON p.id=f.project_id WHERE f.workspace_id=${workspaceId}::uuid ORDER BY f.first_seen_at DESC LIMIT 1000`;
  return json(rows);
 }catch(e){return fail(e);}
}
