import {NextRequest,NextResponse} from 'next/server';import {db} from '@/lib/db';
import {requireUser,workspaceAccess} from '@/lib/auth';import {fail,HttpError} from '@/lib/http';
export const runtime='nodejs';
const cell=(x:unknown)=>{const s=String(x??'');return `"${(/^[=+@\-\t\r]/.test(s)?"'":'')+s.replace(/"/g,'""')}"`;};
export async function GET(req:NextRequest){
 try{const user=await requireUser(),id=req.nextUrl.searchParams.get('workspaceId');if(!id)throw new HttpError(400,'Workspace required');await workspaceAccess(user.id,id);
  const rows=await db()`SELECT p.name AS project,a.id AS advisory,a.severity,d.ecosystem,d.name AS package,d.version AS installed_version,f.status,f.priority,f.risk_score,f.first_seen_at
   FROM findings f JOIN projects p ON p.id=f.project_id JOIN vulnerability_advisories a ON a.id=f.advisory_id JOIN dependencies d ON d.id=f.dependency_id
   WHERE f.workspace_id=${id}::uuid ORDER BY f.first_seen_at DESC LIMIT 10000`;
  const keys=['project','advisory','severity','ecosystem','package','installed_version','status','priority','risk_score','first_seen_at'];
  const output=[keys.join(','),...rows.map(r=>keys.map(k=>cell(r[k])).join(','))].join('\r\n');
  return new NextResponse('\uFEFF'+output,{headers:{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="vulnora-findings.csv"','Cache-Control':'no-store'}});
 }catch(e){return fail(e);}
}
