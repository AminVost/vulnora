'use client';
import {useCallback,useEffect,useMemo,useState} from 'react';
import {Activity,ArrowDownToLine,ArrowRight,Bell,Boxes,ChevronDown,Command,FileBarChart2,FolderKanban,Globe2,LogOut,Moon,Plus,Radar,ScanSearch,Search,Settings,ShieldAlert,ShieldCheck,Sun,Users,Wrench,X} from 'lucide-react';
import {en,fa,Key,Lang,T,User,View,Workspace,api,payload} from '@/lib/client';
import {Button,Modal,SearchBox,Spinner} from './ui';
import AuthScreen from './auth-screen';
import Onboarding from './onboarding';
import Overview from './overview';
import Projects from './projects';
import Findings from './findings';
import {Dependencies,Notifications,Reports,ScanCenter,Settings as SettingsPanel} from './sections';
const navPrimary:[View,typeof Radar][]=[['overview',Radar],['projects',FolderKanban],['findings',ShieldAlert],['dependencies',Boxes],['remediation',Wrench],['scans',ScanSearch]];
const navSecondary:[View,typeof Radar][]=[['reports',FileBarChart2],['notifications',Bell],['settings',Settings]];
export default function AppShell(){
 const [lang,setLang]=useState<Lang>('fa'),[theme,setTheme]=useState<'light'|'dark'>('light');
 const [user,setUser]=useState<User|null>(null),[workspaces,setWorkspaces]=useState<Workspace[]>([]),[workspaceId,setWorkspaceId]=useState<string|null>(null);
 const [booting,setBooting]=useState(true),[view,setView]=useState<View>('overview'),[refresh,setRefresh]=useState(0),[paletteOpen,setPaletteOpen]=useState(false),[paletteQuery,setPaletteQuery]=useState(''),[commandResults,setCommandResults]=useState<{id:string,name:string,type:string}[]>([]);
 const t=useCallback<T>((key:Key)=>(lang==='fa'?fa:en)[key],[lang]);
 useEffect(()=>{setLang(localStorage.getItem('vulnora-lang')==='en'?'en':'fa');setTheme(localStorage.getItem('vulnora-theme')==='dark'?'dark':'light');loadSession();},[]);
 useEffect(()=>{document.documentElement.setAttribute('lang',lang);document.documentElement.setAttribute('dir',lang==='fa'?'rtl':'ltr');localStorage.setItem('vulnora-lang',lang);},[lang]);
 useEffect(()=>{document.documentElement.setAttribute('data-theme',theme);localStorage.setItem('vulnora-theme',theme);},[theme]);
 useEffect(()=>{const keydown=(e:KeyboardEvent)=>{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){e.preventDefault();setPaletteOpen(x=>!x);}if(e.key==='Escape')setPaletteOpen(false);};window.addEventListener('keydown',keydown);return()=>window.removeEventListener('keydown',keydown);},[]);
 async function loadSession(){try{const r=await api<{user:User|null,workspaces:Workspace[]}>('/api/auth/me');setUser(r.user);setWorkspaces(r.workspaces);
  const saved=localStorage.getItem('vulnora-workspace');setWorkspaceId(r.workspaces.find(w=>w.id===saved)?.id??r.workspaces[0]?.id??null);
 }catch{setUser(null);setWorkspaces([]);setWorkspaceId(null);}finally{setBooting(false);}}
 function chooseWorkspace(id:string){localStorage.setItem('vulnora-workspace',id);setWorkspaceId(id);setView('overview');setRefresh(v=>v+1);}
 function navigate(v:View){setView(v);setPaletteOpen(false);window.scrollTo({top:0,behavior:'smooth'});}
 async function logout(){try{await api('/api/auth/logout',payload({}));}finally{setUser(null);setWorkspaces([]);setWorkspaceId(null);}}
 function switchLanguage(){setLang(s=>s==='fa'?'en':'fa');}
 const workspace=workspaces.find(w=>w.id===workspaceId);
 useEffect(()=>{if(!paletteOpen||!workspaceId)return;let live=true;
  Promise.all([api<{id:string,name:string}[]>(`/api/projects?workspaceId=${workspaceId}`),api<{id:string,advisory_id:string}[]>(`/api/findings?workspaceId=${workspaceId}`)]).then(([projects,findings])=>{if(live)setCommandResults([...projects.map(x=>({id:x.id,name:x.name,type:'project'})),...findings.slice(0,100).map(x=>({id:x.id,name:x.advisory_id,type:'finding'}))]);}).catch(()=>{});
  return()=>{live=false};},[paletteOpen,workspaceId]);
 const nav=(arr:typeof navPrimary)=>arr.map(([id,Icon])=><button className={`nav-link ${view===id?'active':''}`} onClick={()=>navigate(id)} key={id}><Icon size={17} strokeWidth={1.85}/><span>{t(id)}</span>{id==='notifications'&&<span style={{marginInlineStart:'auto',height:6,width:6,background:'var(--accent)',borderRadius:10}}/>}</button>);
 if(booting)return <div style={{height:'100vh',display:'grid',placeItems:'center'}}><div style={{display:'grid',gap:15,justifyItems:'center'}}><div className="logo"><ShieldCheck size={23}/></div><Spinner/><small>Vulnora Security Intelligence</small></div></div>;
 if(!user)return <AuthScreen t={t} lang={lang} onAuthenticated={loadSession} switchLanguage={switchLanguage}/>;
 if(!workspace)return <Onboarding t={t} onCreated={loadSession}/>;
 return <div className="app-shell" dir={lang==='fa'?'rtl':'ltr'}>
 <aside className="sidebar"><div className="logo-line"><div className="logo"><ShieldCheck size={20}/></div><div><div className="brand">vulnora<span style={{color:'var(--accent)'}}>.</span></div><div className="brand-hint">SECURITY INTELLIGENCE</div></div></div>
 <div className="workspace-chooser"><div className="workspace-glyph">{workspace.name.trim()[0]?.toUpperCase()}</div><div style={{flex:1,minWidth:0}}><div className="micro muted">{t('workspace')}</div><select aria-label={t('workspace')} value={workspace.id} onChange={e=>chooseWorkspace(e.target.value)}>{workspaces.map(w=><option key={w.id} value={w.id}>{w.name}</option>)}</select></div><ChevronDown size={12} color="var(--muted)"/></div>
 <nav className="nav-stack" aria-label="Primary navigation"><div className="nav-caption">{t('monitor')}</div>{nav(navPrimary)}</nav>
 <nav className="nav-stack" aria-label="More navigation"><div className="nav-caption">{t('manage')}</div>{nav(navSecondary)}</nav>
 <div className="sidebar-bottom"><div className="user-line"><div className="avatar">{user.name.trim()[0]?.toUpperCase()}</div><div className="minitext"><strong>{user.name}</strong><small>{user.email}</small></div><button className="icon-button" aria-label={t('logout')} title={t('logout')} onClick={logout} style={{width:31,height:31,border:0}}><LogOut size={15}/></button></div></div></aside>
 <main className="main"><div className="content"><header className="topbar"><div className="breadcrumb"><span className="desktop-only">Vulnora</span><span>/</span><strong>{t(view)}</strong></div><div className="top-actions"><button className="icon-button" aria-label="Search" onClick={()=>setPaletteOpen(true)} title="Ctrl / Cmd + K"><Search size={17}/></button><button className="icon-button" aria-label={t('language')} onClick={switchLanguage}><Globe2 size={17}/></button><button className="icon-button" aria-label={t('appearance')} onClick={()=>setTheme(v=>v==='light'?'dark':'light')}>{theme==='light'?<Moon size={17}/>:<Sun size={17}/>}</button><button className="icon-button" aria-label={t('notifications')} onClick={()=>navigate('notifications')}><Bell size={17}/></button></div></header>
 {view==='overview'&&<Overview workspaceId={workspaceId!} t={t} lang={lang} navigate={navigate} refreshKey={refresh}/>}
 {view==='projects'&&<Projects workspace={workspace} t={t} lang={lang} navigate={navigate} onChanged={()=>setRefresh(v=>v+1)}/>}
 {view==='findings'&&<Findings workspace={workspace} t={t} lang={lang} onChanged={()=>setRefresh(v=>v+1)}/>}
 {view==='remediation'&&<Findings workspace={workspace} t={t} lang={lang} onlyOpen onChanged={()=>setRefresh(v=>v+1)}/>}
 {view==='dependencies'&&<Dependencies workspace={workspace} t={t}/>}
 {view==='scans'&&<ScanCenter workspace={workspace} t={t} lang={lang}/>}
 {view==='reports'&&<Reports workspace={workspace} t={t} lang={lang}/>}
 {view==='notifications'&&<Notifications workspace={workspace} t={t} lang={lang}/>}
 {view==='settings'&&<SettingsPanel workspace={workspace} t={t} lang={lang} theme={theme} setTheme={setTheme} switchLanguage={switchLanguage}/>}
 </div></main>
 <nav className="mobile-nav" aria-label="Mobile navigation">{([['overview',Radar],['projects',FolderKanban],['findings',ShieldAlert],['scans',ScanSearch],['settings',Settings]] as typeof navPrimary).map(([id,Icon])=><button key={id} className={view===id?'active':''} onClick={()=>navigate(id)}><Icon size={20}/><span>{t(id)}</span></button>)}</nav>
 {paletteOpen&&<Modal title="Search / جست‌وجو" onClose={()=>setPaletteOpen(false)}><SearchBox value={paletteQuery} onChange={setPaletteQuery} placeholder="Find a project, package or CVE…"/><div style={{maxHeight:320,overflow:'auto',marginTop:14}}>{commandResults.filter(x=>x.name.toLowerCase().includes(paletteQuery.toLowerCase())).slice(0,20).map(x=><button key={x.id} onClick={()=>navigate(x.type==='project'?'projects':'findings')} style={{border:0,width:'100%',background:'none',textAlign:'start',padding:13,borderBottom:'1px solid var(--border)',color:'var(--ink)'}}><span className="badge-mini" style={{marginInlineEnd:10}}>{x.type}</span><span className="mono ltr">{x.name}</span></button>)}</div><div style={{marginTop:15,color:'var(--muted)',fontSize:10}}>⌘K / Ctrl+K</div></Modal>}
 </div>;
}
