'use client';
import {useEffect,useState} from 'react';
import {Activity,ArrowRight,Boxes,CalendarClock,CheckCircle2,Clock3,FolderKanban,Radar,ShieldAlert,ShieldCheck,TrendingUp,Zap} from 'lucide-react';
import {Dashboard,Lang,T,View,api,dateLabel} from '@/lib/client';
import {Button,Empty,ErrorMessage,PageTitle,Severity,Spinner,Status} from './ui';
const palette:{[k:string]:string}={critical:'#e45a68',high:'#f3a453',medium:'#e2c56d',low:'#4bbb9c',unknown:'#9fa7bb'};
export default function Overview({workspaceId,t,lang,navigate,refreshKey}:{workspaceId:string,t:T,lang:Lang,navigate:(v:View)=>void,refreshKey:number}){
 const [data,setData]=useState<Dashboard|null>(null),[error,setError]=useState<string|null>(null);
 useEffect(()=>{let live=true;api<Dashboard>(`/api/dashboard?workspaceId=${workspaceId}`).then(r=>{if(live){setData(r);setError(null)}}).catch(e=>{if(live)setError(e.message)});return()=>{live=false}},[workspaceId,refreshKey]);
 const metrics=data?.metrics;
 const cards=[{title:t('totalProjects'),value:metrics?.projects??0,icon:<FolderKanban size={17}/>,hint:t('yourProjects'),view:'projects' as View},
  {title:t('openFindings'),value:metrics?.open_findings??0,icon:<ShieldAlert size={17}/>,hint:t('needAttention'),view:'findings' as View},
  {title:t('trackedDeps'),value:metrics?.dependencies??0,icon:<Boxes size={17}/>,hint:t('sharedPackages'),view:'dependencies' as View},
  {title:t('overdue'),value:metrics?.overdue??0,icon:<CalendarClock size={17}/>,hint:t('deadline'),view:'remediation' as View}];
 const total=(data?.bySeverity??[]).reduce((s,x)=>s+x.count,0);
 return <div className="fade-in"><PageTitle title={t('overviewTitle')} description={t('todaySub')} eyebrow="SECURITY POSTURE"/>
 <section className="hero"><div><span className="hero-tag"><Zap size={13}/> VULNERABILITY INTELLIGENCE</span><h2>{t('today')}</h2><p>{t('todaySub')}</p><Button onClick={()=>navigate('projects')}>{t('addProject')}<ArrowRight size={16}/></Button></div><div className="hero-icon"><ShieldCheck size={60} color="#e8e9ff" strokeWidth={1.3}/></div></section>
 <div className="metrics-grid">{cards.map(x=><div className="metric clickable" key={x.title} onClick={()=>navigate(x.view)} role="button" tabIndex={0} onKeyDown={e=>{if(e.key==='Enter')navigate(x.view)}}><div className="metric-top"><span>{x.title}</span><span className="metric-icon">{x.icon}</span></div><strong className="num">{!data?<Spinner/>:x.value.toLocaleString('en-US')}</strong><small>{x.hint}</small></div>)}</div>
 {error&&<div style={{marginTop:20}}><ErrorMessage message={error}/></div>}
 <div className="section-grid"><section className="panel panel-pad"><div className="panel-head"><div><h3>{t('needAttention')}</h3><span>{t('needAttentionSub')}</span></div><button className="clicktext" onClick={()=>navigate('findings')}>{t('viewAll')} <ArrowRight size={12}/></button></div>
 {!data?<div className="skeleton skeleton-card"/>:data.urgent.length===0?<Empty icon={<ShieldCheck size={25}/>} title={t('noData')} description={t('emptyFindingsSub')} action={<Button small onClick={()=>navigate('projects')} variant="secondary">{t('addProject')}</Button>}/>:data.urgent.map(x=><div key={x.id} className="risk-row"><div style={{minWidth:0}}><span className="risk-title mono" dir="ltr">{x.advisory_id}</span><span className="risk-description">{x.project_name} · <span className="ltr">{x.package_name}</span></span></div><div className="inline-stack"><Severity value={x.severity}/><strong className="risk-score">{x.risk_score??'—'}</strong></div></div>)}
 </section><section className="panel panel-pad"><div className="panel-head"><div><h3>{t('severityDistribution')}</h3><span>{t('severityDescription')}</span></div><Activity size={16} color="var(--muted)"/></div>
 <div className="severity-bar">{total?data?.bySeverity.map(x=><span key={x.severity} style={{width:`${100*x.count/total}%`,background:palette[x.severity]}}/>):<span style={{width:'100%',background:'var(--surface-3)'}}/>}</div>
 {(['critical','high','medium','low','unknown'] as const).map(k=><div className="legend-row" key={k}><span><i className="dot" style={{background:palette[k]}}/>{k[0].toUpperCase()+k.slice(1)}</span><strong className="num">{data?.bySeverity.find(x=>x.severity===k)?.count??0}</strong></div>)}
 </section></div>
 <div className="section-grid"><section className="panel panel-pad"><div className="panel-head"><h3>{t('recentScans')}</h3><button className="clicktext" onClick={()=>navigate('scans')}>{t('viewAll')}</button></div>{!data?<Spinner/>:data.scans.length===0?<div className="empty-inline">{t('emptyScansSub')}</div>:data.scans.map(x=><div className="risk-row" key={x.id}><div><strong className="risk-title">{x.project_name}</strong><span className="risk-description">{dateLabel(x.created_at,lang)}</span></div><Status value={x.status}/></div>)}</section>
 <section className="panel panel-pad"><div className="panel-head"><h3>{t('guide')}</h3><span>01 → 05</span></div>{(['stepOne','stepTwo','stepThree','stepFour','stepFive'] as const).map((key,i)=><div key={key} style={{display:'flex',alignItems:'center',gap:12,padding:'11px 0',borderBottom:i===4?'none':'1px solid var(--border)',fontSize:12}}><span className="badge-mini">{String(i+1).padStart(2,'0')}</span><span>{t(key)}</span></div>)}</section></div>
 </div>;
}
