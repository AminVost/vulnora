import {NextRequest} from 'next/server';
import {timingSafeEqual} from 'node:crypto';
import {processNextQueuedJob} from '@/lib/intelligence';
import {json,fail,HttpError} from '@/lib/http';
export const runtime='nodejs';export const maxDuration=60;
export async function GET(req:NextRequest){
 try{
  const key=process.env.CRON_SECRET;
  if(!key||key.length<32)throw new HttpError(503,'Cron is not configured');
  const sent=req.headers.get('authorization')?.replace(/^Bearer\s+/i,'')??'';
  const a=Buffer.from(sent),b=Buffer.from(key);
  if(a.length!==b.length||!timingSafeEqual(a,b))throw new HttpError(401,'Unauthorized');
  const id=await processNextQueuedJob();return json({ok:true,processed:id});
 }catch(e){return fail(e);}
}
