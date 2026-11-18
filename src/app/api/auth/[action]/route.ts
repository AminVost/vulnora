import {NextRequest} from 'next/server';
import {z} from 'zod';
import {db} from '@/lib/db';
import {comparePassword,currentUser,endSession,hashPassword,issueSession} from '@/lib/auth';
import {fail,HttpError,json,parseJSON,requireOrigin} from '@/lib/http';
export const runtime='nodejs';
const credentials=z.object({email:z.string().email().max(220).transform(v=>v.toLowerCase().trim()),password:z.string().min(12).max(200)});
export async function GET(_req:NextRequest,ctx:{params:Promise<{action:string}>}){
 const {action}=await ctx.params;
 if(action!=='me')return json({error:'Not found'},404);
 const user=await currentUser(); if(!user)return json({user:null,workspaces:[]});
 const memberships=await db()`SELECT w.id,w.name,m.role FROM memberships m JOIN workspaces w ON w.id=m.workspace_id WHERE m.user_id=${user.id}::uuid ORDER BY w.created_at`;
 return json({user,workspaces:memberships});
}
export async function POST(req:NextRequest,ctx:{params:Promise<{action:string}>}){
 try {
  requireOrigin(req);
  const {action}=await ctx.params;
  if(action==='logout'){await endSession();return json({ok:true});}
  if(!['login','register'].includes(action))throw new HttpError(404,'Not found');
  const raw=await parseJSON(req,4096);
  const parsed=credentials.safeParse(raw);if(!parsed.success)throw new HttpError(400,'Use a valid email and password of at least 12 characters');
  const {email,password}=parsed.data;
  const sql=db();
  if(action==='register'){
   if(process.env.ALLOW_SIGNUP==='false')throw new HttpError(403,'Registration is disabled');
   const name=(raw&&typeof raw==='object'&&'name' in raw?String(raw.name):'').trim().slice(0,100);
   if(name.length<2)throw new HttpError(400,'Name must be at least 2 characters');
   const hash=await hashPassword(password);
   const found=await sql`SELECT id FROM users WHERE email=${email} LIMIT 1`;
   if(found.length)throw new HttpError(409,'This email already has an account');
   const [user]=await sql`INSERT INTO users(email,name,password_hash) VALUES(${email},${name},${hash}) RETURNING id`;
   await issueSession(String(user.id));
   return json({ok:true},201);
  }
  const [attempt]=await sql`SELECT attempts,locked_until FROM auth_throttles WHERE email=${email}`;
  if(attempt?.locked_until&&new Date(String(attempt.locked_until)).getTime()>Date.now())throw new HttpError(429,'Too many attempts. Try again in 15 minutes');
  const [user]=await sql`SELECT id,password_hash FROM users WHERE email=${email} LIMIT 1`;
  const valid=user?await comparePassword(password,String(user.password_hash)):false;
  if(!valid){
   await sql`INSERT INTO auth_throttles(email,attempts,locked_until) VALUES(${email},1,null)
    ON CONFLICT(email) DO UPDATE SET attempts=CASE WHEN auth_throttles.updated_at<now()-interval '15 minutes' THEN 1 ELSE auth_throttles.attempts+1 END,
    updated_at=now(),locked_until=CASE WHEN auth_throttles.attempts>=4 AND auth_throttles.updated_at>=now()-interval '15 minutes' THEN now()+interval '15 minutes' ELSE null END`;
   throw new HttpError(401,'Invalid email or password');
  }
  await sql`DELETE FROM auth_throttles WHERE email=${email}`;
  await issueSession(String(user.id));return json({ok:true});
 }catch(e){return fail(e);}
}
