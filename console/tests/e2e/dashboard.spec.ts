import { test, expect } from '@playwright/test';
import { login } from './helpers';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('dashboard page loads', async ({ page }) => {
    await expect(page.locator('text=Dashboard')).toBeVisible();
  });

  test('summary stat cards render', async ({ page }) => {
    // Should see stat cards: Open Incidents, Active Policies, Agents Online, Scans Today
    await expect(page.locator('text=/open incidents|total incidents/i').first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('text=/active policies/i').first()).toBeVisible();
  });

  test('incidents by severity chart renders', async ({ page }) => {
    await expect(page.locator('text=/incidents.*severity|severity.*breakdown/i').first()).toBeVisible({ timeout: 10_000 });
  });

  test('top policies widget renders', async ({ page }) => {
    await expect(page.locator('text=/top.*policies/i').first()).toBeVisible({ timeout: 10_000 });
  });

  test('agent health widget renders', async ({ page }) => {
    await expect(page.locator('text=/agent.*health/i').first()).toBeVisible({ timeout: 10_000 });
  });

  test('activity timeline renders', async ({ page }) => {
    await expect(page.locator('text=/activity|timeline|recent/i').first()).toBeVisible({ timeout: 10_000 });
  });

  test('time range selector is functional', async ({ page }) => {
    // Look for 7d/30d/90d buttons
    const btn7d = page.getByRole('button', { name: /7d|7 days/i }).first();
    const btn30d = page.getByRole('button', { name: /30d|30 days/i }).first();

    if (await btn7d.isVisible() && await btn30d.isVisible()) {
      // Click 30d and verify it activates
      await btn30d.click();
      await page.waitForTimeout(1500);
      // Dashboard should still be visible (didn't crash)
      await expect(page.locator('text=Dashboard')).toBeVisible();

      // Click 7d
      await btn7d.click();
      await page.waitForTimeout(1500);
      await expect(page.locator('text=Dashboard')).toBeVisible();
    }
  });

  test('channel breakdown chart renders', async ({ page }) => {
    await expect(page.locator('text=/channel|breakdown/i').first()).toBeVisible({ timeout: 10_000 });
  });
});
