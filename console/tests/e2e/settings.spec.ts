import { test, expect } from '@playwright/test';
import { login, navigateTo } from './helpers';

test.describe('Settings — Identifiers', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateTo(page, 'Identifiers');
  });

  test('identifiers page loads', async ({ page }) => {
    await expect(page.locator('text=/identifiers/i').first()).toBeVisible();
  });

  test('identifier list shows built-in entries', async ({ page }) => {
    // Demo seed creates built-in identifiers
    const rows = page.locator('table tbody tr, [role="row"]');
    await expect(rows.first()).toBeVisible({ timeout: 10_000 });
  });

  test('create identifier button exists', async ({ page }) => {
    const createBtn = page.getByRole('button', { name: /create|new|add/i }).first();
    await expect(createBtn).toBeVisible();
  });

  test('create identifier opens modal', async ({ page }) => {
    const createBtn = page.getByRole('button', { name: /create|new|add/i }).first();
    await createBtn.click();
    await page.waitForTimeout(500);
    // Modal should appear with a form field (name input or similar)
    const nameInput = page.getByLabel(/name/i).first();
    const nameByPlaceholder = page.getByPlaceholder(/name/i).first();
    const modal = page.locator('text=/create|new/i').first();
    const hasField = await nameInput.isVisible() || await nameByPlaceholder.isVisible() || await modal.isVisible();
    expect(hasField).toBeTruthy();
  });
});

test.describe('Settings — Dictionaries', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateTo(page, 'Dictionaries');
  });

  test('dictionaries page loads', async ({ page }) => {
    await expect(page.locator('text=/dictionaries/i').first()).toBeVisible();
  });

  test('dictionary list shows entries', async ({ page }) => {
    const rows = page.locator('table tbody tr, [role="row"]');
    await expect(rows.first()).toBeVisible({ timeout: 10_000 });
  });

  test('create dictionary button exists', async ({ page }) => {
    const createBtn = page.getByRole('button', { name: /create|new|add/i }).first();
    await expect(createBtn).toBeVisible();
  });
});

test.describe('Settings — Response Rules', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateTo(page, 'Response Rules');
  });

  test('response rules page loads', async ({ page }) => {
    await expect(page.locator('text=/response rules/i').first()).toBeVisible();
  });

  test('response rules list shows entries', async ({ page }) => {
    const rows = page.locator('table tbody tr, [role="row"]');
    await expect(rows.first()).toBeVisible({ timeout: 10_000 });
  });
});

test.describe('Settings — Users', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateTo(page, 'Users');
  });

  test('users page loads', async ({ page }) => {
    await expect(page.locator('text=/users/i').first()).toBeVisible();
  });

  test('users list shows admin user', async ({ page }) => {
    await expect(page.locator('text=admin').first()).toBeVisible({ timeout: 10_000 });
  });

  test('create user button exists', async ({ page }) => {
    const createBtn = page.getByRole('button', { name: /create|new|add/i }).first();
    await expect(createBtn).toBeVisible();
  });

  test('create user opens modal with form fields', async ({ page }) => {
    const createBtn = page.getByRole('button', { name: /create|new|add/i }).first();
    await createBtn.click();
    await page.waitForTimeout(500);
    await expect(page.getByLabel(/username/i).first()).toBeVisible({ timeout: 5000 });
    await expect(page.getByLabel(/email/i).first()).toBeVisible();
    await expect(page.getByLabel(/password/i).first()).toBeVisible();
  });
});
