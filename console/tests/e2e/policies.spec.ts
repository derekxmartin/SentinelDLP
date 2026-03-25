import { test, expect } from '@playwright/test';
import { login, navigateTo } from './helpers';

test.describe('Policies', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateTo(page, 'Policies');
  });

  test('policy list page loads', async ({ page }) => {
    await expect(page.locator('text=Policies')).toBeVisible();
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

  test('clicking existing policy opens editor', async ({ page }) => {
    const firstRow = page.locator('table tbody tr, [role="row"]').first();
    await firstRow.click();
    await page.waitForTimeout(1000);
    await expect(page).toHaveURL(/\/policies\/.+/);
  });

  test('policy editor has required fields', async ({ page }) => {
    const firstRow = page.locator('table tbody tr, [role="row"]').first();
    await firstRow.click();
    await page.waitForTimeout(2000);
    // Editor should show name, severity, status fields
    await expect(page.locator('text=/name|severity|status/i').first()).toBeVisible({ timeout: 5000 });
  });
});
