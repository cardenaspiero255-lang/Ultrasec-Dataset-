// Owner-local smoke tests for reviewed synthetic snippets. vm is NOT a security sandbox.
// Never run arbitrary unreviewed source. Network/process/filesystem sinks are mocked.
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const path = require('node:path');

function observe(row, input, allow = false, key = 'key1') {
  const calls = [];
  const account = {admin:false};
  const modules = {
    'node:path':path,
    'node:crypto':crypto,
    'node:fs':{readFileSync:p => { calls.push(['file',p]); return p; }},
    'node:child_process':{
      execSync:s => {calls.push(['shell',s]); return s;},
      execFileSync:(exe,args) => {calls.push(['argv',exe,args]); return args;}
    }
  };
  const context = vm.createContext({
    require:name => {if (!(name in modules)) throw Error('unsupported module'); return modules[name];},
    fetch:url => {calls.push(['fetch',url]); return url;},
    input, account, permissions:{canView:() => allow},
    redirect:s => {calls.push(['redirect',s]); return s;},
    logger:{info:s => {calls.push(['log',s]); return s;}},
    db:{query:(s,args) => {calls.push(['query',s,args]); return args || s;}}, key
  });
  const name = row.code.match(/function\s+(case_\d+)\s*\(/)?.[1];
  if (!name) throw Error('missing entry point');
  const second = {'mass-assignment':'account','missing-authorization':'permissions',
    'open-redirect':'redirect','sensitive-logging':'logger','sql-injection':'db',
    'weak-message-digest':'key'}[row.family];
  let result, rejected=false;
  try {result = vm.runInContext(row.code+'\n'+name+'(input'+(second?','+second:'')+')',context,{timeout:100});}
  catch(e) {if (/forbidden|outside root|JSON|Unexpected token/.test(e.message)) rejected=true; else throw e;}
  return {result,rejected,calls,account};
}

function check(row) {
  const f=row.family;
  const attacks={'code-injection':'1+2','html-injection':'<b>probe</b>',
    'mass-assignment':{admin:true,display_name:'Alice'},'missing-authorization':'user',
    'open-redirect':'//outside.invalid','sensitive-logging':'SYNTHETIC_SECRET',
    'sql-injection':"' OR 1=1 --",'ssrf':'http://127.0.0.1/probe',
    'path-traversal':'../outside.txt','command-injection':'hello; PROBE',
    'weak-message-digest':'hello','weak-randomness':'hello'};
  if (!(f in attacks)) throw Error('unsupported family');
  const a=observe(row,attacks[f]);
  let exposed,benign;
  const b=observe(row,f==='mass-assignment'?{display_name:'Alice'}:f==='code-injection'?'123':f==='open-redirect'?'/home':'hello',true);
  switch(f) {
    case 'code-injection': exposed=a.result===3;benign=b.result===123;break;
    case 'html-injection': exposed=a.result?.includes('<b>probe</b>');benign=b.result==='<div>hello</div>';break;
    case 'mass-assignment': exposed=a.account.admin;benign=b.account.display_name==='Alice';break;
    case 'missing-authorization': exposed=a.result?.private_account==='sample';benign=b.result?.private_account==='sample';break;
    case 'open-redirect': exposed=a.result==='//outside.invalid';benign=b.result==='/home';break;
    case 'sensitive-logging': exposed=a.calls.some(c=>c[1].includes('SYNTHETIC_SECRET'));benign=b.calls.length===1;break;
    case 'sql-injection': exposed=a.calls.some(c=>c[0]==='query' && !c[2]);benign=b.calls.length===1 && (b.calls[0][2]?.[0]==='hello'||b.calls[0][1].includes("'hello'"));break;
    case 'ssrf': exposed=a.result==='http://127.0.0.1/probe';benign=b.calls.length===1;break;
    case 'path-traversal': exposed=a.result==='/srv/outside.txt';benign=b.result==='/srv/example_data/hello';break;
    case 'command-injection': exposed=a.calls.some(c=>c[0]==='shell');benign=b.calls.length===1;break;
    case 'weak-message-digest': exposed=a.result===observe(row,'hello',false,'key2').result;benign=typeof b.result==='string' && b.result.length>0;break;
    case 'weak-randomness': exposed=/^[a-z0-9]+$/.test(a.result) && a.result.length<32;benign=typeof b.result==='string' && b.result.length>0;break;
  }
  // Randomness check is only an output-format heuristic, never cryptographic evidence.
  return {attack_observed:!!exposed,benign_contract_pass:!!benign,
    expected_label_behavior:!!exposed===(row.label==='vulnerable')};
}
function evaluate(rows) {
  return rows.filter(r=>r.language==='javascript').map(r=>{
    const out={id:r.id,pair_id:r.pair_id,family:r.family,
      code_sha256:crypto.createHash('sha256').update(r.code).digest('hex')};
    try {Object.assign(out,check(r));out.status=out.expected_label_behavior&&out.benign_contract_pass?'PASS':'FAIL';}
    catch(e) {out.status='ERROR';out.error=e.name;}
    return out;
  });
}
if (require.main===module) {
  const [input,output]=process.argv.slice(2);
  if (!input||!output) throw Error('Usage: node behavioral_js.cjs INPUT.jsonl PRIVATE_OUTPUT.json');
  const rows=fs.readFileSync(input,'utf8').trim().split('\n').map(s=>JSON.parse(s));
  if (!rows.length || !rows.some(r=>r.language==='javascript')) throw Error('empty JavaScript cohort');
  const results=evaluate(rows);
  fs.writeFileSync(output,JSON.stringify({scope:'INTERNAL_SYNTHETIC_SMOKE_ONLY',results},null,2),{flag:'wx',mode:0o600});
  console.log(JSON.stringify({records:results.length,pass:results.filter(r=>r.status==='PASS').length}));
  if(results.some(r=>r.status!=='PASS')) process.exitCode=1;
}
module.exports={check,evaluate};
