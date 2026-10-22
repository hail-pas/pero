const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('services/user-center/ui/static/js/forms.js', 'utf8');
let response;
let sent;
const context = {window:{Pero:{t:key=>key}},document:{cookie:'pero_csrf=current'},FormData,URLSearchParams,
  fetch:async (_url,options)=>{sent=options;return response;}};
vm.runInNewContext(source,context);
const post = context.window.PeroForms.postForm;
(async()=>{
  for (const [type,body] of [['text/html','<html>Login</html>'],['application/json','invalid'],['application/json','null'],['application/json','[]']]) {
    response = new Response(body,{headers:{'Content-Type':type}});
    await assert.rejects(post('/submit',new FormData()));
  }
  response = new Response(JSON.stringify({error:'unauthorized'}),{headers:{'Content-Type':'application/json'}});
  await assert.rejects(post('/submit',new FormData()));
  response = new Response(JSON.stringify({code:0,message:'ok'}),{headers:{'Content-Type':'application/json'}});
  const form = new FormData(); form.set('csrf_token','stale');
  assert.equal((await post('/submit',form)).message,'ok');
  assert.equal(sent.body.get('csrf_token'),'current');
  assert.equal(sent.redirect,'error');
  console.log('forms: HTML, invalid JSON, authentication errors and CSRF refresh passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
