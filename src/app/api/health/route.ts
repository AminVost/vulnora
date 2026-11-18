import {db} from '@/lib/db';import {json} from '@/lib/http';
export const runtime='nodejs';
export async function GET(){
 try{await db()`SELECT 1`;return json({status:'ok',database:'connected',service:'vulnora',time:new Date().toISOString()});}
 catch{return json({status:'degraded',database:'unavailable'},503);}
}
