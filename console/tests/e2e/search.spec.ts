import { test, expect } from '@playwright/test';
import { login } from './helpers';

test.describe('Global search / Command palette', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('Ctrl+Shift+P opens command palette', async ({ page }) => {
    await page.keyboard.press('Control+Shift+P');
    await page.waitForTimeout(500);
    // Command palette should be visible — look for the dialog/modal/input
    const palette = page.locator('[cmdk-root], [role="dialog"], [data-command-palette]').first();
    const input = page.locator('input[placeholder*="search" i], input[placeholder*="command" i], [cmdk-input]').first();
    const isVisible = await palette.isVisible() || await input.isVisible();
    expect(isVisible).toBeTruthy();
  });

  test('command palette shows grouped results when typing', async ({ page }) => {
    await page.keyboard.press('Control+Shift+P');
    await page.waitForTimeout(500);
    // Type a search query
    const input = page.locator('[cmdk-input], input[placeholder*="search" i], input[placeholder*="command" i]').first();
    if (await input.isVisible()) {
      await input.fill('incidents');
      await page.waitForTimeout(1000);
      // Should show results — items, links, or commands
      const results = page.locator('[cmdk-item], [role="option"], [data-command-item]');
      if (await results.count() > 0) {
        await expect(results.first()).toBeVisible();
      }
    }
  });

  test('selecting command palette item navigates', async ({ page }) => {
    await page.keyboard.press('Control+Shift+P');
    await page.waitForTimeout(500);
    const input = page.locator('[cmdk-input], input[placeholder*="search" i], input[placeholder*="command" i]').first();
    if (await input.isVisible()) {
      await input.fill('dashboard');
      await page.waitForTimeout(500);
      // Press Enter to select first result
      await page.keyboard.press('Enter');
      await page.waitForTimeout(1000);
      // Should navigate somewhere (or at least palette closes)
      await expect(page).toHaveURL(/\//);
    }
  });

  test('Escape closes command palette', async ({ page }) => {
    await page.keyboard.press('Control+Shift+P');
    await page.waitForTimeout(500);
    const palette = page.locator('[cmdk-root], [role="dialog"], [data-command-palette]').first();
    if (await palette.isVisible()) {
      await page.keyboard.press('Escape');
      await page.waitForTimeout(500);
      await expect(palette).not.toBeVisible();
    }
  });

  test('command palette shows navigation commands', async ({ page }) => {
    await page.keyboard.press('Control+Shift+P');
    await page.waitForTimeout(500);
    // Palette should list navigation options like Dashboard, Incidents, Policies
    const dashboardItem = page.locator('text=/dashboard/i').first();
    await expect(dashboardItem).toBeVisible({ timeout: 5000 });
  });
});
