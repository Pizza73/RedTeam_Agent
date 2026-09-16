import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const routes = [
  ["/dashboard", "Domain Administrator Escalation"],
  ["/missions/new", "Create Mission Draft"],
  ["/interventions", "Human Interventions"],
  ["/knowledge", "Collected Intelligence"],
  ["/settings/providers", "C2 & Tool Access"],
  ["/settings/llm", "VLLM Settings"],
] as const;

for (const [route, heading] of routes) {
  test(`${route} renders its operator surface`, async ({ page }) => {
    await page.goto(route);
    await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
    await expect(page.getByText("Mock mode", { exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Agent activity" })).toBeVisible();
  });
}

test("mock capability check completes without external dispatch", async ({ page }) => {
  await page.goto("/settings/llm");
  await page.getByRole("button", { name: /test connection & capabilities/i }).click();
  await expect(page.getByText("Profile meets the required capability contract.")).toBeVisible();
});

test("tool command templates stay collapsed until requested", async ({ page }) => {
  await page.goto("/settings/providers");
  await page.getByRole("tab", { name: "Tools (MCP) Control" }).click();

  const groups = page.locator("details.tool-operation-group");
  await expect(groups).toHaveCount(1);
  await expect(page.locator("details.tool-operation-group[open]")).toHaveCount(0);

  const impacket = page.locator('details[data-tool="Impacket"]');
  await impacket.locator("summary").click();
  await expect(impacket).toHaveAttribute("open", "");
  await expect(impacket.getByText("impacket.rpc.endpoint_map(target_ref=<approved-target-ref>)", { exact: true })).toBeVisible();
  await expect(impacket.getByText("impacket.smb.list_shares(target_ref=<approved-target-ref>)", { exact: true })).toBeVisible();
  await expect(impacket.getByText("impacket-secretsdump", { exact: true })).toHaveCount(0);
});

test("Sliver is the default C2 draft but remains blocked without a Beacon", async ({ page }) => {
  await page.goto("/settings/providers");
  await expect(page.getByLabel("Preferred C2")).toHaveValue("sliver");
  await expect(page.getByRole("heading", { name: "Sliver", exact: true })).toBeVisible();
  await expect(page.getByText("not present", { exact: true })).toBeVisible();
  await expect(page.getByText(/live HTTP Beacon pass the Provider Human Gate/)).toBeVisible();
});

test("primary operator surfaces have no serious accessibility violations", async ({ page }) => {
  for (const route of ["/dashboard", "/missions/new", "/interventions", "/knowledge", "/settings/providers", "/settings/llm"]) {
    await page.goto(route);
    const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
    const blocking = results.violations.filter((violation) => violation.impact === "critical" || violation.impact === "serious");
    expect(blocking, `${route}: ${blocking.map((violation) => `${violation.id} (${violation.nodes.length})`).join(", ")}`).toEqual([]);
  }
});

test("knowledge relationships use the mobile step view on narrow screens", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/knowledge");
  await expect(page.getByRole("list", { name: "Escalation path relationships" })).toBeVisible();
  await expect(page.locator(".graph-canvas")).toBeHidden();
  await page.getByRole("button", { name: "Mission flow" }).click();
  await expect(page.getByRole("region", { name: "Agent activity" })).toBeVisible();
});
