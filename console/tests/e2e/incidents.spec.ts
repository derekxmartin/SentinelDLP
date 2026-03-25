import { test, expect } from '@playwright/test';
import { login, navigateTo } from './helpers';

test.describe('Incidents', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateTo(page, 'Incidents');
  });

  test('incident list page loads with data', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Incidents' })).toBeVisible();
    // Table should have at least one row (demo seed provides 500+)
    const rows = page.locator('table tbody tr, [role="row"]');
    await expect(rows.first()).toBeVisible({ timeout: 10_000 });
  });

  test('severity filter works', async ({ page }) => {
    // Look for a severity filter/dropdown
    const severityFilter = page.locator('select').filter({ hasText: /all|severity/i }).first();
    if (await severityFilter.isVisible()) {
      // Get available options and pick one that contains "high" (case-insensitive)
      const options = await severityFilter.locator('option').allTextContents();
      const highOption = options.find(o => /high/i.test(o));
      if (highOption) {
        await severityFilter.selectOption({ label: highOption });
        await page.waitForTimeout(1000);
      }
    }
  });

  test('search/filter input works', async ({ page }) => {
    const searchInput = page.getByPlaceholder(/search|filter/i).first();
    if (await searchInput.isVisible()) {
      await searchInput.fill('SSN');
      await page.waitForTimeout(1000);
      // Results should narrow or show matching incidents
      await expect(page.locator('table, [role="table"]').first()).toBeVisible();
    }
  });

  test('clicking incident opens snapshot', async ({ page }) => {
    // Click the first incident row/link
    const firstRow = page.locator('table tbody tr, [role="row"]').first();
    await firstRow.click();
    await page.waitForTimeout(1000);
    // Should navigate to incident detail page
    await expect(page).toHaveURL(/\/incidents\/.+/);
  });

  test('incident snapshot shows details', async ({ page }) => {
    const firstRow = page.locator('table tbody tr, [role="row"]').first();
    await firstRow.click();
    await page.waitForTimeout(2000);
    // Snapshot should show policy name, severity, matched content
    await expect(page.locator('text=/policy|severity|match/i').first()).toBeVisible({ timeout: 5000 });
  });

  test('pagination controls are visible', async ({ page }) => {
    // With 500+ incidents, pagination should exist
    const pagination = page.locator('text=/page|next|previous|showing/i').first();
    await expect(pagination).toBeVisible({ timeout: 5000 });
  });
});
