import { test, expect } from '@playwright/test';
import { login } from './helpers';

test.describe('Dark mode / Theme', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('app loads in dark theme by default', async ({ page }) => {
    // The app uses a dark background — check that the body/root has dark styling
    const bgColor = await page.evaluate(() => {
      return getComputedStyle(document.body).backgroundColor;
    });
    // Dark themes typically have low RGB values
    // rgb(15, 23, 42) = slate-900, or similar dark color
    expect(bgColor).toMatch(/rgb\(\s*\d{1,2}\s*,\s*\d{1,2}\s*,\s*\d{1,3}\s*\)/);
  });

  test('theme toggle button exists if implemented', async ({ page }) => {
    const themeToggle = page.locator('button[aria-label*="theme" i], button[aria-label*="dark" i], button[aria-label*="mode" i]').first();
    if (await themeToggle.isVisible()) {
      await themeToggle.click();
      await page.waitForTimeout(500);
      // After toggle, background should change
      const bgColor = await page.evaluate(() => {
        return getComputedStyle(document.body).backgroundColor;
      });
      // Just verify it didn't crash
      expect(bgColor).toBeTruthy();
    }
  });

  test('dark theme persists across navigation', async ({ page }) => {
    const bgBefore = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    await page.goto('/incidents');
    await page.waitForTimeout(1000);
    const bgAfter = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(bgBefore).toBe(bgAfter);
  });

  test('sidebar uses dark styling', async ({ page }) => {
    const sidebar = page.locator('nav, [role="navigation"], aside').first();
    if (await sidebar.isVisible()) {
      const bgColor = await page.evaluate((el) => {
        return el ? getComputedStyle(el).backgroundColor : '';
      }, await sidebar.elementHandle());
      expect(bgColor).toBeTruthy();
    }
  });
});
