import { test, expect } from "@playwright/test";

const base = "http://127.0.0.1:8443";
const token = "dev-token-long-enough-for-the-check";

test("the running demo's console opens a shell in the browser", async ({ page }) => {
  page.on("pageerror", (e) => console.log("PAGEERROR:", e.message));
  page.on("console", (m) => {
    if (m.type() === "error") console.log("CONSOLE ERROR:", m.text());
  });

  await page.goto(`${base}/ui/`);
  await page.getByPlaceholder("token").fill(token);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("fleet")).toBeVisible();
  console.log("SIGNED IN");

  // From the device's own page: the fleet list is a list of links now, so there is no id
  // to retype — click the row and it lands there.
  const row = page.locator('[data-device="treadmill-4821"]');
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.click();
  const devicePage = page.getByTestId("device-page");
  await expect(devicePage).toBeVisible({ timeout: 30_000 });
  await devicePage.getByTestId("reason").fill("checking the console by hand");
  await devicePage.getByTestId("open").click();

  await expect(page.locator(".oarlock-term .xterm")).toBeVisible({ timeout: 30_000 });
  console.log("TERMINAL MOUNTED");
  console.log("BAR:", await page.locator(".oarlock-bar").innerText());

  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.type("echo BROWSER-SHELL-WORKS");
  await page.keyboard.press("Enter");
  await expect(page.locator(".xterm-rows")).toContainText("BROWSER-SHELL-WORKS", {
    timeout: 30_000,
  });
  console.log("COMMAND RAN IN THE BROWSER");

  await page.keyboard.type("exit");
  await page.keyboard.press("Enter");
  await page.getByRole("button", { name: "Leave" }).click();
  await page.screenshot({ path: "/tmp/oarlock-console.png", fullPage: true });
  console.log("SCREENSHOT /tmp/oarlock-console.png");
});
