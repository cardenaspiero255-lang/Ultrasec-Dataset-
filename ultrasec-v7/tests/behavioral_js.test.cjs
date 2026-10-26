const test=require('node:test');
const assert=require('node:assert/strict');
const {check,evaluate}=require('../tools/behavioral_js.cjs');
const row=(code,label='vulnerable',family='html-injection')=>({code,label,family,language:'javascript',id:'fixture',pair_id:'fixture-pair'});
test('vulnerable HTML and safe HTML are distinguished',()=>{
  assert.equal(check(row('function case_1(x){return "<div>"+x+"</div>"}')).expected_label_behavior,true);
  assert.equal(check(row('function case_1(x){return "<div>"+x.replaceAll("<","&lt;").replaceAll(">","&gt;")+"</div>"}','mitigated_example')).expected_label_behavior,true);
});
test('incorrect mitigation label fails',()=>{
  assert.equal(evaluate([row('function case_1(x){return "<div>"+x+"</div>"}','mitigated_example')])[0].status,'FAIL');
});
test('constant sanitized output cannot pass benign control',()=>{
  assert.equal(evaluate([row('function case_1(x){return "safe"}','mitigated_example')])[0].status,'FAIL');
});
test('syntax error is an error, never a pass',()=>{
  assert.equal(evaluate([row('function case_1(x){BROKEN')])[0].status,'ERROR');
});
test('unknown family fails closed',()=>{
  assert.equal(evaluate([row('function case_1(x){return x}','vulnerable','unknown')])[0].status,'ERROR');
});
