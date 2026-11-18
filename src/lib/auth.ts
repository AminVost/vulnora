import {cookies} from 'next/headers';
import {createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
import {db} from './db';
import {HttpError} from './http';
const scrypt=promisify(scryptCallback);
const lifetime=60*60*24*7;
export async function hashPassword(value:string) {
 const salt=randomBytes(16).toString('hex'); const hash=await scrypt(value,salt,64) as Buffer;
 return `scrypt$${salt}$${hash.toString('hex')}`;
}
export async function comparePassword(value:string,stored:string) {
 const [algorithm,salt,hash]=stored.split('$');
 if(algorithm!=='scrypt'||!salt||!hash) return false;
 const a=await scrypt(value,salt,64) as Buffer; const b=Buffer.from(hash,'hex');
 return a.length===b.length&&timingSafeEqual(a,b);
}
function hmac(data:string) {
 const secret=process.env.SESSION_SECRET;
 if(!secret || secret.length<32) throw new Error('SESSION_SECRET_INVALID');
 return createHmac('sha256',secret).update(data).digest('base64url');
}
export async function issueSession(userId:string){
 const token=Buffer.from(JSON.stringify({sub:userId,exp:Math.floor(Date.now()/1000)+lifetime})).toString('base64url');
 (await cookies()).set('vulnora_session',`${token}.${hmac(token)}`,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',path:'/',maxAge:lifetime});
}
export async function endSession(){(await cookies()).delete('vulnora_session');}
export async function currentUser(){
 try {
  const value=(await cookies()).get('vulnora_session')?.value; if(!value)return null;
  const [token,signature]=value.split('.'); if(!token||!signature)return null;
  const a=Buffer.from(signature);const b=Buffer.from(hmac(token)); if(a.length!==b.length||!timingSafeEqual(a,b))return null;
  const payload=JSON.parse(Buffer.from(token,'base64url').toString()) as {sub:string,exp:number};
  if(payload.exp<Math.floor(Date.now()/1000)||!payload.sub)return null;
  const rows=await db()`SELECT id,email,name FROM users WHERE id=${payload.sub}::uuid LIMIT 1`;
  return rows[0] as {id:string,email:string,name:string}|undefined ?? null;
 } catch{return null;}
}
export async function requireUser(){const user=await currentUser();if(!user)throw new HttpError(401,'Please sign in');return user;}
export const canManage=(role:string)=>['owner','admin','security_manager'].includes(role);
export async function workspaceAccess(userId:string,workspaceId:string,minRole?:'manager'|'editor') {
 const rows=await db()`SELECT w.id,w.name,m.role FROM memberships m JOIN workspaces w ON w.id=m.workspace_id WHERE m.user_id=${userId}::uuid AND w.id=${workspaceId}::uuid LIMIT 1`;
 const access=rows[0] as {id:string,name:string,role:string}|undefined;
 if(!access)throw new HttpError(403,'Workspace access denied');
 if(minRole==='manager'&&!canManage(access.role))throw new HttpError(403,'Manager permissions required');
 if(minRole==='editor'&&access.role==='viewer')throw new HttpError(403,'Read-only role');
 return access;
}
export async function projectAccess(userId:string,projectId:string,minRole?:'manager'|'editor') {
 const rows=await db()`SELECT id,workspace_id,name,repository_url,criticality,environment FROM projects WHERE id=${projectId}::uuid LIMIT 1`;
 const project=rows[0] as {id:string,workspace_id:string,name:string,repository_url:string|null,criticality:string,environment:string}|undefined;
 if(!project)throw new HttpError(404,'Project not found');
 const membership=await workspaceAccess(userId,project.workspace_id,minRole);
 return {...project,role:membership.role};
}
