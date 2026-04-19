const { chromium } = require('@playwright/test');

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  
  await page.route('**/api/v1/auth/login', route => route.fulfill({
    status: 200, json: { access_token: 'fake-token' }
  }));
  await page.route('**/api/v1/tokens/**', route => {
    if (route.request().url().includes('/generate')) return route.continue();
    route.fulfill({
      status: 200, json: { items: [{ trace_id: '1234567890123456', status: 'ACTIVE', created_at: Date.now() }] }
    });
  });

  await page.addInitScript(() => {
    const originalFetch = window.fetch;
    window.fetch = async (input, init) => {
      console.log('FETCH INTERCEPTED:', input.toString());
      if (input.toString().includes('/api/v1/events/stream')) {
        const stream = new ReadableStream({
          start(controller) {
            console.log('STREAM STARTED');
            setTimeout(() => {
              controller.enqueue(new TextEncoder().encode('event: revocation\n'));
              controller.enqueue(new TextEncoder().encode('data: {"trace_id":"1234567890123456"}\n\n'));
              controller.close();
              console.log('STREAM ENQUEUED AND CLOSED');
            }, 1000);
          }
        });
        return new Response(stream, {
          status: 200, headers: { 'Content-Type': 'text/event-stream' }
        });
      }
      return originalFetch(input, init);
    };
  });

  await page.goto('http://localhost:5173/');
  await page.fill('input[type="email"]', 'test@example.com');
  await page.fill('input[type="password"]', 'pass');
  await page.click('button[type="submit"]');

  await page.waitForTimeout(4000);
  await browser.close();
})();
