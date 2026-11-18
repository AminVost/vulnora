'use client';
import {ReactNode,useEffect,useState} from 'react';
import {AlertCircle,Inbox,Search,X} from 'lucide-react';
import {T} from '@/lib/client';
export function Button({children,onClick,variant='primary',small=false,disabled=false,type='button',title}:{children:ReactNode,onClick?:()=>void,variant?:'primary'|'secondary'|'ghost'|'danger',small?:boolean,disabled?:boolean,type?:'submit'|'button',title?:string}){
 return <button type={type} title={title} disabled={disabled} onClick={onClick} className={`btn ${variant==='primary'?'':`btn-${variant}`} ${small?'btn-small':''}`}>{children}</button>;
}
export function Modal({title,children,onClose,wide=false}:{title:string,children:ReactNode,onClose:()=>void,wide?:boolean}){
 useEffect(()=>{const esc=(e:KeyboardEvent)=>{if(e.key==='Escape')onClose();};document.addEventListener('keydown',esc);return()=>document.removeEventListener('keydown',esc);},[onClose]);
 return <div className="modal-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget)onClose();}} role="presentation"><section className={`modal fade-in ${wide?'wide':''}`} role="dialog" aria-modal="true" aria-label={title}><div className="modal-head"><h2>{title}</h2><button className="icon-button" onClick={onClose} aria-label="Close"><X size={17}/></button></div>{children}</section></div>;
}
export function Empty({title,description,action,icon}:{title:string,description:string,action?:ReactNode,icon?:ReactNode}){return <div className="empty"><div className="empty-icon">{icon??<Inbox size={24}/>}</div><h3>{title}</h3><p>{description}</p>{action}</div>;}
export function SearchBox({value,onChange,placeholder}:{value:string,onChange:(s:string)=>void,placeholder:string}){return <label className="search-input"><Search size={16}/><input value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder}/></label>;}
export function Severity({value}:{value:string}){return <span className={`severity ${value.toLowerCase()}`}>{value}</span>;}
export function Status({value}:{value:string}){return <span className={`status-pill ${value.toLowerCase().replace(/[^a-z]/g,'')}`}>{value.replaceAll('_',' ')}</span>;}
export function Notice({children,warn=false}:{children:ReactNode,warn?:boolean}){return <div className={`notice ${warn?'warn':''}`}><AlertCircle size={16} style={{flexShrink:0,marginTop:3}}/>{children}</div>;}
export function ErrorMessage({message}:{message:string|null}){return message?<div className="error-msg" role="alert">{message}</div>:null;}
export function Spinner(){return <span className="loading" aria-label="Loading"/>;}
export function PageTitle({title,description,action,eyebrow}:{title:string,description?:string,action?:ReactNode,eyebrow?:string}){return <div className="page-heading"><div>{eyebrow&&<div className="eyebrow" style={{marginBottom:6}}>{eyebrow}</div>}<h1>{title}</h1>{description&&<p>{description}</p>}</div>{action}</div>;}
