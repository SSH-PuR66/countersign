// Optional browser regression: Playwright and an installed Edge browser.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const origin=process.env.SEALBREAK_ORIGIN||'http://127.0.0.1:8892';
(async()=>{
 const browser=await chromium.launch({channel:'msedge',headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:600},reducedMotion:'no-preference'});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 try {
  await page.goto(origin+'/demos/carbon-copy/');
  await page.waitForFunction(()=>document.querySelector('#status').textContent.startsWith('2 LOCAL'));
  // Deliberately do not pre-scroll or wait for IntersectionObserver.
  await page.locator('#play').click();
  await page.waitForFunction(()=>document.body.dataset.step==='3'&&document.body.dataset.playing==='false',null,{timeout:10000});
  await page.locator('#play').click();
  await page.waitForFunction(()=>document.body.dataset.step==='1',null,{timeout:5000});
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.waitForFunction(()=>document.body.dataset.playing==='false');
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.waitForFunction(()=>document.querySelector('#play').disabled);
  await page.locator('#step').click();
  assert.equal(await page.locator('body').getAttribute('data-step'),'2');
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({passed:true,first_click_playback:true,replay:true,offscreen_pause:true,reduced_motion_manual_step:true,page_errors:errors}));
 } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
