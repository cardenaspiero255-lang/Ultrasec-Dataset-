'use strict'
const assert = require('node:assert/strict')
const path = require('node:path')
const Koa = require(path.resolve(process.cwd()))
const supertest = require(path.resolve(process.cwd(), 'node_modules', 'supertest'))
const variant = process.argv[2]
if (!['VULNERABLE', 'PATCHED'].includes(variant)) {
  process.stderr.write('Expected VULNERABLE or PATCHED\n')
  process.exitCode = 2
} else {
  ;(async () => {
    const app = new Koa()
    app.use(ctx => { ctx.response.back('/safe') })
    const sent = supertest(app.callback())
    const benign = await sent.get('/').set('Referer', '/dashboard')
    const absent = await sent.get('/')
    const malicious = await sent.get('/').set('Referer', '//untrusted.invalid/path')
    assert.equal(benign.status,302)
    assert.equal(benign.headers.location,'/dashboard')
    assert.equal(absent.headers.location,'/safe')
    const exposed = malicious.headers.location === '//untrusted.invalid/path'
    assert.equal(exposed,variant==='VULNERABLE')
    console.log(JSON.stringify({project:'koajs/koa',variant,legitimate_relative:benign.headers.location,missing_referrer:absent.headers.location,malicious_location:malicious.headers.location,external_redirect_allowed:exposed,oracle:exposed?'EXPECTED_RED':'EXPECTED_GREEN',scope:'native Koa HTTP callback'}))
  })().catch(err=>{console.error(err);process.exitCode=1})
}
