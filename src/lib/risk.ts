export type Severity='critical'|'high'|'medium'|'low'|'unknown';
export const OPEN_STATUSES=['open','triaged','in_progress','ready_for_verification','reopened'];
export function normalizedSeverity(value:unknown,cvss:number|null=null):Severity {
 if(cvss!==null&&Number.isFinite(cvss)){
  if(cvss>=9)return 'critical'; if(cvss>=7)return 'high'; if(cvss>=4)return 'medium'; if(cvss>0)return 'low';
 }
 const t=String(value??'').toLowerCase();
 if(['critical','high','medium','moderate','low'].includes(t))return t==='moderate'?'medium':t as Severity;
 return 'unknown';
}
export function riskProfile(input:{severity:Severity,kev:boolean|null,epss:number|null,criticality:string,environment:string,exposed:boolean,direct:boolean}) {
 const base={critical:65,high:45,medium:25,low:10,unknown:0}[input.severity];
 const signals:string[]=[];
 if(input.severity!=='unknown')signals.push(`${input.severity.toUpperCase()} severity`);
 if(input.kev===true)signals.push('listed in CISA KEV (known exploited)');
 if(input.epss!==null&&input.epss>=0.5)signals.push(`high EPSS probability (${Math.round(input.epss*100)}%)`);
 if(input.environment==='production')signals.push('production environment (user-declared)');
 if(input.exposed)signals.push('internet-exposed service (user-declared)');
 if(input.criticality==='critical')signals.push('business-critical application');
 if(input.direct)signals.push('direct dependency');
 // Lack of severity and exploitation evidence means no defensible numeric risk score.
 if(input.severity==='unknown'&&input.kev!==true&&input.epss===null)return {score:null,priority:'unknown',reason:'Insufficient severity or exploitation data'};
 const score=Math.min(100,base+(input.kev===true?25:0)+(input.epss!==null&&input.epss>=0.5?10:0)+
 (input.environment==='production'?6:0)+(input.exposed?6:0)+(input.criticality==='critical'?5:0)+(input.direct?3:0));
 const priority=score>=80?'critical':score>=60?'high':score>=35?'medium':'low';
 return {score,priority,reason:signals.length?signals.join(' · '):'Risk inferred from available intelligence'};
}
