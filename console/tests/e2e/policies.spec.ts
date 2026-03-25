import { test, expect } from '@playwright/test';
import { login, navigateTo } from './helpers';

test.describe('Policies', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateTo(page, 'Policies');
  });

  test('policy list page loads', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Policies' })).toBeVisible();
    // Should have at least one policy from demo seed
    const rows = page.locator('table tbody tr, [role="row"]');
    await expect(rows.first()).toBeVisible({ timeout: 10_000 });
  });

  test('create new policy button exists', async ({ page }) => {
    const createBtn = page.getByRole('button', { name: /create|new|add/i }).first();
    await expect(createBtn).toBeVisible();
  });

  test('clicking create opens policy editor', async ({ page }) => {
    const createBtn = page.getByRole('button', { name: /create|new|add/i }).first();
    await createBtn.click();
    await page.waitForTimeout(1000);
    // Should navigate to policy editor or open a modal
    const editorVisible = await page.locator('text=/policy.*editor|create.*policy|new.*policy/i').first().isVisible();
    const urlChanged = /policies\/(new|create)/.test(page.url());
    expect(editorVisible || urlChanged).toBeTruthy();
  });

  test('policy row has clickable elements', async ({ page }) => {
    // Verify policy rows exist and have interactive elements
    const rows = page.locator('table tbody tr, [role="row"]');
    await expect(rows.first()).toBeVisible({ timeout: 10_000 });
    // Check for edit/view links or buttons within the row
    const interactive = page.locator('table tbody tr a, table tbody tr button, table tbody tr [role="link"]');
    const count = await interactive.count();
    expect(count).toBeGreaterThan(0);
  });

  test('policy detail view accessible', async ({ page }) => {
    // Find and click any link that goes to a policy detail
    const policyLink = page.locator('a[href*="/policies/"]').first();
    if (await policyLink.isVisible()) {
      await policyLink.click();
      await page.waitForTimeout(2000);
      await expect(page.locator('text=/name|severity|status/i').first()).toBeVisible({ timeout: 5000 });
    }
  });
});
