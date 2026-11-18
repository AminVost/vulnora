import {NextRequest} from 'next/server';
import {db} from '@/lib/db';import {requireUser,workspaceAccess} from '@/lib/auth';import {json,fail,HttpError} from '@/lib/http';
export const runtime='nodejs';
export async function GET(req:NextRequest){
 try{const user=await requireUser();const id=req.nextUrl.searchParams.get('workspaceId');if(!id)throw new HttpError(400,'Workspace required');await workspaceAccess(user.id,id);
  const sql=db();const [[metrics],bySeverity,urgent,scans,recent]=await Promise.all([
   sql`SELECT
    (SELECT count(*)::int FROM projects WHERE workspace_id=${id}::uuid) AS projects,
    (SELECT count(*)::int FROM dependencies d JOIN projects p ON p.id=d.project_id WHERE p.workspace_id=${id}::uuid AND d.current) AS dependencies,
    (SELECT count(*)::int FROM findings WHERE workspace_id=${id}::uuid AND status NOT IN ('resolved','false_positive','risk_accepted')) AS open_findings,
    (SELECT count(*)::int FROM findings WHERE workspace_id=${id}::uuid AND status NOT IN ('resolved','false_positive','risk_accepted') AND due_at<now()) AS overdue,
    (SELECT count(*)::int FROM projects WHERE workspace_id=${id}::uuid AND (last_scanned_at IS NULL OR last_scanned_at<now()-interval '7 days')) AS stale_projects`,
   sql`SELECT a.severity,count(*)::int AS count FROM findings f JOIN vulnerability_advisories a ON a.id=f.advisory_id WHERE f.workspace_id=${id}::uuid AND f.status NOT IN('resolved','false_positive','risk_accepted') GROUP BY a.severity`,
   sql`SELECT f.id,f.status,f.priority,f.risk_score,f.risk_reason,f.due_at,p.name AS project_name,p.id AS project_id,
    a.id AS advisory_id,a.summary,a.severity,a.kev,d.name AS package_name,d.version FROM findings f
    JOIN projects p ON p.id=f.project_id JOIN dependencies d ON d.id=f.dependency_id
    JOIN vulnerability_advisories a ON a.id=f.advisory_id
    WHERE f.workspace_id=${id}::uuid AND f.status NOT IN('resolved','false_positive','risk_accepted')
    ORDER BY f.risk_score DESC NULLS LAST,f.first_seen_at DESC LIMIT 8`,
   sql`SELECT j.id,j.status,j.error,j.created_at,j.finished_at,j.packages_checked,j.findings_new,p.name AS project_name FROM scan_jobs j JOIN projects p ON p.id=j.project_id WHERE j.workspace_id=${id}::uuid ORDER BY j.created_at DESC LIMIT 5`,
   sql`SELECT id,title,body,created_at FROM notifications WHERE workspace_id=${id}::uuid ORDER BY created_at DESC LIMIT 6`
  ]);
  return json({metrics,bySeverity,urgent,scans,recent});
 }catch(e){return fail(e);}
}
