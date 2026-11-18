'use client';
import {FormEvent,useState} from 'react';
import {ArrowRight,Building2,Check,ShieldCheck} from 'lucide-react';
import {T,api,payload} from '@/lib/client';import {Button,ErrorMessage,Spinner,Notice} from './ui';
export default function Onboarding({t,onCreated}:{t:T,onCreated:()=>void}){
 const [name,setName]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState<string|null>(null);
 async function submit(e:FormEvent){e.preventDefault();setBusy(true);setError(null);try{await api('/api/workspaces',payload({name}));onCreated();}catch(e){setError((e as Error).message);}finally{setBusy(false)}}
 return <div style={{minHeight:'100vh',display:'grid',placeItems:'center',padding:20}} className="fade-in"><section className="modal" style={{maxWidth:550,boxShadow:'var(--shadow)'}}><div className="logo-line" style={{padding:0,marginBottom:27}}><div className="logo"><ShieldCheck size={20}/></div><span className="brand">vulnora.</span></div><div className="step-list"><i className="done"/><i/><i/><i/><i/></div>
 <div className="eyebrow" style={{marginBottom:12}}>01 / 05 · {t('guide')}</div><h1 style={{fontSize:25,marginBottom:9}}>{t('firstWorkspace')}</h1><p style={{color:'var(--muted)',fontSize:13,marginBottom:27}}>{t('firstWorkspaceSub')}</p>
 <form className="form-stack" onSubmit={submit}><label className="field"><span className="field-label">{t('workspaceName')}</span><div style={{position:'relative'}}><Building2 size={17} style={{position:'absolute',top:13,left:12,color:'var(--muted)'}}/><input className="field-input" style={{paddingLeft:39}} required minLength={2} maxLength={100} value={name} onChange={e=>setName(e.target.value)} placeholder="Acme Engineering"/></div></label><ErrorMessage message={error}/><Button type="submit" disabled={busy}>{busy?<Spinner/>:<><Check size={16}/>{t('continue')}<ArrowRight size={16}/></>}</Button></form>
 <div style={{marginTop:24}}><Notice>{t('workspaceSecurity')}</Notice></div></section></div>;
}
