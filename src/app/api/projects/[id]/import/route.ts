import {NextRequest} from 'next/server';
import {requireUser,projectAccess} from '@/lib/auth';
import {json,fail,HttpError,requireOrigin,parseJSON} from '@/lib/http';
import {importDependencies} from '@/lib/intelligence';
export const runtime='nodejs';export const maxDuration=60;
export async function POST(req:NextRequest,ctx:{params:Promise<{id:string}>}){
 try {requireOrigin(req);const user=await requireUser();const {id}=await ctx.params;await projectAccess(user.id,id,'editor');
  const data=await parseJSON(req,3_300_000) as {filename?:string,content?:string,manifest?:string};
  if(typeof data.filename!=='string'||!/^[\w.-]{1,120}$/.test(data.filename)||typeof data.content!=='string')throw new HttpError(400,'Invalid file import');
  if(data.content.length>3_000_000)throw new HttpError(413,'File too large');
  const count=await importDependencies(id,data.filename,data.content,typeof data.manifest==='string'?data.manifest:undefined);
  return json({count,source:'uploaded',note:'Recorded versions are from the uploaded evidence, not verified production deployments'},201);
 }catch(e){return fail(e);}
}
