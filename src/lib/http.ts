import {NextRequest, NextResponse} from 'next/server';
export const json = (data: unknown, status=200) => NextResponse.json(data,{status,headers:{'Cache-Control':'no-store'}});
export function fail(e: unknown) {
  if (e instanceof HttpError) return json({error:e.message},e.status);
  console.error('Vulnora operation failed',e instanceof Error ? e.message : 'unknown');
  return json({error:'Internal server error'},500);
}
export class HttpError extends Error { constructor(public status: number,message: string){super(message);} }
export function requireOrigin(req: NextRequest){
 const origin=req.headers.get('origin');
 if (!origin) throw new HttpError(403,'Origin header required');
 if (new URL(origin).host !== req.nextUrl.host) throw new HttpError(403,'Cross-origin request rejected');
}
export async function parseJSON(req:NextRequest,max=1024*1024){
 const body=await req.text(); if (Buffer.byteLength(body)>max) throw new HttpError(413,'Request too large');
 try{return JSON.parse(body) as unknown;}catch{throw new HttpError(400,'Invalid JSON');}
}
