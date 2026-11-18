'use client';
import {useState,FormEvent} from 'react';
import {ArrowRight,Eye,EyeOff,ShieldCheck,Sparkles,LockKeyhole,Globe2} from 'lucide-react';
import {Lang,T,api,payload} from '@/lib/client';
import {Button,ErrorMessage,Spinner} from './ui';
export default function AuthScreen({t,lang,onAuthenticated,switchLanguage}:{t:T,lang:Lang,onAuthenticated:()=>void,switchLanguage:()=>void}){
 const [register,setRegister]=useState(false),[loading,setLoading]=useState(false),[error,setError]=useState<string|null>(null),[reveal,setReveal]=useState(false);
 const [name,setName]=useState(''),[email,setEmail]=useState(''),[password,setPassword]=useState('');
 async function submit(e:FormEvent){e.preventDefault();setError(null);setLoading(true);
  try{await api(`/api/auth/${register?'register':'login'}`,payload({name,email,password}));onAuthenticated();}
  catch(err){setError((err as Error).message);}finally{setLoading(false);}
 }
 return <div className="auth-wrap fade-in" dir={lang==='fa'?'rtl':'ltr'}>
  <div className="auth-content"><div className="auth-form"><div className="logo-line" style={{padding:0}}><div className="logo"><ShieldCheck size={21}/></div><span className="brand">vulnora<span style={{color:'var(--accent)'}}>.</span></span></div>
   <h2>{register?t('createAccount'):t('welcome')}</h2><p>{register?t('createAccountSub'):t('welcomeSub')}</p>
   <form onSubmit={submit} className="form-stack">
    {register&&<label className="field"><span className="field-label">{t('name')}</span><input className="field-input" required minLength={2} maxLength={100} value={name} onChange={e=>setName(e.target.value)} autoComplete="name"/></label>}
    <label className="field"><span className="field-label">{t('email')}</span><input className="field-input ltr" type="email" required value={email} onChange={e=>setEmail(e.target.value)} autoComplete="email" placeholder="you@company.com"/></label>
    <label className="field"><span className="field-label">{t('password')}</span><div style={{position:'relative'}}><input className="field-input ltr" type={reveal?'text':'password'} required minLength={12} maxLength={200} value={password} onChange={e=>setPassword(e.target.value)} autoComplete={register?'new-password':'current-password'} style={{paddingRight:43}}/><button className="icon-button" type="button" onClick={()=>setReveal(!reveal)} style={{position:'absolute',right:3,top:2,border:0}} aria-label="Toggle password">{reveal?<EyeOff size={16}/>:<Eye size={16}/>}</button></div></label>
    <ErrorMessage message={error}/><Button type="submit" disabled={loading}>{loading?<Spinner/>:register?t('register'):t('signIn')}<ArrowRight size={15}/></Button>
   </form>
   <div className="auth-foot">{register?t('haveAccount'):t('newAccount')} <button onClick={()=>{setRegister(!register);setError(null)}}>{register?t('signIn'):t('register')}</button></div>
   <button className="btn btn-ghost" onClick={switchLanguage} style={{marginTop:24,paddingInline:0}}><Globe2 size={14}/>{t('switchLang')}</button>
  </div></div>
  <div className="auth-side"><span className="hero-tag" style={{alignSelf:'flex-start',fontSize:12}}><Sparkles size={14}/> Security operations, reimagined</span><h1>See every risk.<br/>Own every fix.</h1><p>One calm, intelligent workspace for your software supply chain. Trace vulnerabilities to actual versions, prioritize with evidence, and move remediation forward.</p><div style={{display:'flex',gap:10,alignItems:'center',marginTop:12,color:'#b8bde2'}}><LockKeyhole size={15}/><small>Evidence first. Privacy by design. No fabricated findings.</small></div></div>
 </div>;
}
