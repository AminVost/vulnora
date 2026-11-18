import {describe,it,expect} from 'vitest';
import {parseLockfile,parseSpdx,parseCycloneDX} from '../src/lib/dependencies';
import {normalizedSeverity,riskProfile} from '../src/lib/risk';
describe('dependency evidence',()=>{
 it('reads exact resolved npm versions instead of manifest ranges',()=>{
  const lock={lockfileVersion:3,packages:{'':{dependencies:{lodash:'^4.0.0'}},'node_modules/lodash':{version:'4.17.20'}}};
  expect(parseLockfile('package-lock.json',JSON.stringify(lock))[0]).toMatchObject({name:'lodash',version:'4.17.20',direct:true});
 });
 it('imports Packagist locked versions',()=>{
  expect(parseLockfile('composer.lock',JSON.stringify({packages:[{name:'symfony/http-foundation',version:'v5.4.0'}]}))[0]).toMatchObject({ecosystem:'Packagist',name:'symfony/http-foundation'});
 });
 it('recognizes SPDX purl version',()=>{
  const doc={spdxVersion:'SPDX-2.3',packages:[{SPDXID:'SPDXRef-pkg',externalRefs:[{referenceLocator:'pkg:npm/lodash@4.17.20'}]}]};
  expect(parseSpdx(doc)[0]).toMatchObject({name:'lodash',version:'4.17.20'});
 });
 it('recognizes CycloneDX purl version',()=>{
  const doc={bomFormat:'CycloneDX',components:[{purl:'pkg:composer/symfony/http-foundation@v5.4.0'}]};
  expect(parseCycloneDX(doc)[0]).toMatchObject({ecosystem:'Packagist'});
 });
});
describe('explainable prioritization',()=>{
 it('does not invent scores for missing data',()=>{
  expect(riskProfile({severity:'unknown',kev:null,epss:null,criticality:'low',environment:'unknown',exposed:false,direct:false}).score).toBeNull();
 });
 it('ranks exploited critical production above low',()=>{
  const base={criticality:'critical',environment:'production',exposed:true,direct:true,epss:0.6};
  const a=riskProfile({...base,severity:'critical',kev:true});
  const b=riskProfile({...base,severity:'low',kev:false});
  expect(a.score!).toBeGreaterThan(b.score!); expect(a.reason).toContain('KEV');
 });
 it('keeps unsupported scores unknown',()=>expect(normalizedSeverity(undefined)).toBe('unknown'));
});
