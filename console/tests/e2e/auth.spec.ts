import { test, expect } from '@playwright/test';
import { login, logout } from './helpers';

test.describe('Auth flows', () => {
  test('login with valid credentials redirects to dashboard', async ({ page }) => {
    await login(page);
    await expect(page).toHaveURL('/');
    await expect(page.locator('text=Dashboard')).toBeVisible();
  });

  test('login with invalid credentials shows error', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel(/username/i).fill('admin');
    await page.getByLabel(/password/i).fill('wrongpassword');
    await page.getByRole('button', { name: /sign in|log in/i }).click();
    await expect(page.locator('text=/invalid|incorrect|denied/i')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/\/login/);
  });

  test('unauthenticated user is redirected to login', async ({ page }) => {
    await page.goto('/incidents');
    await expect(page).toHaveURL(/\/login/);
  });

  test('logout redirects to login page', async ({ page }) => {
    await login(page);
    await logout(page);
    await expect(page).toHaveURL(/\/login/);
  });

  test('token refresh keeps session alive', async ({ page }) => {
    await login(page);
    // Navigate around to trigger API calls with token
    await page.goto('/incidents');
    await page.waitForTimeout(1000);
    // Page should not redirect to login (token still valid or refreshed)
    await expect(page).not.toHaveURL(/\/login/);
  });

  test('login page shows AkesoDLP branding', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('text=/AkesoDLP|Akeso/i')).toBeVisible();
  });
});
