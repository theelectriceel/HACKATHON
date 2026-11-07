// Browser QA for our local test application only.
const path = require('path');
let chromium;
try { ({chromium}=require('playwright')); }
catch { ({chromium}=require(path.join(process.env.USERPROFILE,'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'))); }
(async()=>{
 const browser = await chromium.launch({headless:true,channel:'chrome'});
 const page = await browser.newPage({viewport:{width:1440,height:1050},deviceScaleFactor:1});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8766',{waitUntil:'networkidle'});
 await page.getByRole('button',{name:'Load genuine saved runs'}).click();
 await page.waitForTimeout(1200);
 await page.screenshot({path:path.resolve('artifacts/demo-agent.png'),fullPage:true});
 console.log(JSON.stringify({title:await page.title(),errors,scenario:await page.locator('#scenario').inputValue(),cards:await page.locator('.result-card').count(),horizontalOverflow:await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)}));
 await page.getByRole('button',{name:'RAG test application'}).click();
 await page.getByRole('button',{name:'Load saved comparison'}).click();
 await page.waitForTimeout(1000);
 await page.screenshot({path:path.resolve('artifacts/demo-rag.png'),fullPage:true});
 await page.getByRole('button',{name:'Security assessment'}).click();
 await page.waitForTimeout(800);
 await page.getByRole('button',{name:'Check policy change'}).click();
 await page.locator('#expansion-result .notice').waitFor();
 if(!(await page.locator('#expansion-result').textContent()).includes('permits an action'))throw new Error('Policy expansion explanation missing');
 await page.screenshot({path:path.resolve('artifacts/demo-assessment.png'),fullPage:true});
 await page.setViewportSize({width:390,height:844});
 await page.getByRole('button',{name:'Agent comparison'}).click();
 await page.screenshot({path:path.resolve('artifacts/demo-mobile.png'),fullPage:true});
 console.log(JSON.stringify({mobileOverflow:await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),errors}));
 if(errors.length)throw new Error(errors.join('; '));
 await browser.close();
})().catch(e=>{console.error(e.message);process.exitCode=1});
