"""End-to-end clipboard test in a real browser against a running server.

    SAWNN_DEMO=1 uvicorn server.app:app --port 8011 &
    python tests/e2e/clipboard_e2e.py [--chrome /path/to/chrome]
"""
import asyncio, json, sys
CHROME = sys.argv[sys.argv.index('--chrome') + 1] if '--chrome' in sys.argv else None
from playwright.async_api import async_playwright
R = {}
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path=CHROME, args=['--no-sandbox'] if CHROME else [])
        ctx = await b.new_context(permissions=['clipboard-read', 'clipboard-write'], viewport={'width': 420, 'height': 900})
        pg = await ctx.new_page()
        await pg.goto('http://localhost:8011/app'); await pg.wait_for_timeout(1200)
        url = '‎https://login.uaepass.example.com/auth‏'   # copied from an Arabic chat: invisible marks included
        await pg.evaluate(f"navigator.clipboard.writeText({json.dumps(url)})")
        await pg.click('#input'); await pg.keyboard.press('Control+V'); await pg.wait_for_timeout(200)
        R['ctrl_v'] = await pg.input_value('#input')
        await pg.click('#clear-btn'); R['clear'] = await pg.input_value('#input')
        await pg.click('#paste-btn'); await pg.wait_for_timeout(300); R['paste_button'] = await pg.input_value('#input')
        await pg.fill('#input', 'https://login.uaepass.example.com/auth'); await pg.keyboard.down('Shift'); await pg.keyboard.press('Home'); await pg.keyboard.up('Shift')
        await pg.keyboard.press('Control+C'); await pg.wait_for_timeout(200)
        R['ctrl_c_selection'] = await pg.evaluate("navigator.clipboard.readText()")
        await pg.click('#input'); await pg.keyboard.press('End'); await pg.keyboard.press('Enter'); await pg.wait_for_timeout(2500)
        R['enter_scan_verdict'] = await pg.text_content('#v-word')
        await pg.evaluate("navigator.clipboard.writeText('')")
        await pg.click('#v-copy .copy-btn'); await pg.wait_for_timeout(300)
        R['copy_link_button'] = await pg.evaluate("navigator.clipboard.readText()")
        R['toast'] = await pg.text_content('#clip-toast')
        # checker with a redirect sample: copy final destination + chain from the Command report
        await pg.goto('http://localhost:8011/command'); await pg.wait_for_timeout(800)
        await ctx.grant_permissions(['clipboard-read', 'clipboard-write'])
        await pg.set_viewport_size({'width': 1440, 'height': 900})
        await pg.fill('#l-email', 'admin@sawnn.demo'); await pg.fill('#l-pass', 'SawnnDemo2026!'); await pg.click('#login-form button[type=submit]'); await pg.wait_for_timeout(1500)
        await pg.evaluate("api('/api/demo/seed', {})"); await pg.wait_for_timeout(4000)
        await pg.evaluate("show('domain')"); await pg.wait_for_timeout(500)
        await pg.evaluate("navigator.clipboard.writeText('tamm-camping-permit.top/pay')")
        await pg.click('#scan-url'); await pg.keyboard.press('Meta+V') ; await pg.keyboard.press('Control+V'); await pg.wait_for_timeout(200)
        R['command_paste'] = await pg.input_value('#scan-url')
        await pg.keyboard.press('Enter'); await pg.wait_for_timeout(3000)
        R['command_enter_scan'] = (await pg.text_content('.verdict-banner .vb-word'))
        # open the synthetic redirect sample report and use its copy buttons
        await pg.evaluate("api('/api/v1/scan/SCAN-DEMO-REDIRECT1').then(r => renderScan(r, document.querySelector('#scan-out') || document.querySelector('#v-domain .report') || document.querySelector('#v-domain')))")
        await pg.wait_for_timeout(1500)
        btns = await pg.query_selector_all('.copy-row .copy-btn')
        labels = [await x.text_content() for x in btns]
        R['command_copy_buttons'] = labels
        for want in ('Copy final destination', 'Copy redirect chain'):
            i = labels.index(want); await btns[i].click(); await pg.wait_for_timeout(300)
            R[want] = await pg.evaluate("navigator.clipboard.readText()")
        await b.close()
asyncio.run(main())
print(json.dumps(R, indent=1, ensure_ascii=False))
