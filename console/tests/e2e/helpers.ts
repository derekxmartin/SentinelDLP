import { type Page, expect } from '@playwright/test';

/** Log in as the admin user and wait for the dashboard to load. */
export async function login(page: Page, username = 'admin', password = 'AkesoDLP2026!') {
  await page.goto('/login');
  await page.getByLabel(/username/i).fill(username);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole('button', { name: /sign in|log in/i }).click();
  // Wait for redirect to dashboard
  await expect(page).toHaveURL('/', { timeout: 10_000 });
}

/** Log out via the sidebar or profile menu. */
export async function logout(page: Page) {
  const logoutBtn = page.getByRole('button', { name: /log ?out|sign ?out/i });
  if (await logoutBtn.isVisible()) {
    await logoutBtn.click();
  } else {
    // Fallback: navigate directly
    await page.goto('/login');
  }
  await expect(page).toHaveURL(/\/login/);
}

/** Navigate to a sidebar link by text. */
export async function navigateTo(page: Page, linkText: string) {
  await page.getByRole('link', { name: new RegExp(linkText, 'i') }).first().click();
  // Small settle time for page load
  await page.waitForTimeout(500);
}

/** Wait for API responses to settle after navigation. */
export async function waitForApi(page: Page, urlPattern: string | RegExp) {
  await page.waitForResponse(
    (resp) => {
      const url = resp.url();
      if (typeof urlPattern === 'string') return url.includes(urlPattern);
      return urlPattern.test(url);
    },
    { timeout: 10_000 },
  );
}
