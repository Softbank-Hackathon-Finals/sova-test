// Browser acceptance against an authenticated host. The caller supplies the
// session; this helper never creates resources or calls an operating API.
import assert from "node:assert/strict";

const menus = {
  overview: "워크스페이스",
  apps: "앱 배포",
  migration: "환경 이전",
  topology: "워크로드 지도",
  network: "네트워크 아틀라스",
  security: "보안·거버넌스",
  delivery: "IaC·고객 환경",
  monitoring: "모니터링",
  timeline: "실행 타임라인",
  analysis: "의존성·후보 비교",
  ai: "AI·리허설",
  costs: "비용·예산",
};

export async function qualifyNavigation(page) {
  const checked = [];
  const writes = [];
  const watch = (r) => {
    if (!["GET", "HEAD"].includes(r.method()))
      writes.push(new URL(r.url()).pathname);
  };
  page.on("request", watch);
  try {
    for (const [view, title] of Object.entries(menus)) {
      const button = page.locator(`nav [data-view="${view}"]`);
      assert.equal(await button.isEnabled(), true, `${view}: menu disabled`);
      await button.click();
      assert.equal(await page.locator("#view-title").textContent(), title);
      assert.equal(await page.locator('nav [aria-current="page"]').count(), 1);
      assert.equal(await button.getAttribute("aria-current"), "page");
      if (view === "topology") {
        assert.equal(
          await page
            .locator(
              '#response-workspace svg[aria-label="실클러스터 워크로드 관계"]',
            )
            .isVisible(),
          true,
        );
        assert.equal(
          await page.locator("#terminal-response-workspace").isVisible(),
          false,
        );
        const advanced = page.getByText("고급 · 기존 무상태 대응 시험 도구", {
          exact: true,
        });
        await advanced.click();
        assert.equal(
          await page.locator("#terminal-response-workspace").isVisible(),
          true,
        );
        await advanced.click();
      } else {
        assert.equal(await page.locator("#sova-live-pages").isVisible(), true);
        assert.equal(
          await page.locator("#terminal-response-workspace").isVisible(),
          false,
        );
      }
      if (view === "security") {
        assert.equal(
          await page.locator("#observed-security").isVisible(),
          true,
        );
        assert.equal(
          await page.locator("#observed-controls").isVisible(),
          true,
        );
      }
      if (["costs", "delivery", "ai"].includes(view)) {
        assert.ok(
          (await page
            .locator('#sova-live-pages [data-connection="unconnected"]')
            .count()) >= 1,
        );
        assert.equal(
          await page.locator("#registration-panel").isVisible(),
          false,
        );
        assert.equal(
          await page
            .locator("#sova-live-pages input, #sova-live-pages form")
            .count(),
          0,
        );
      }
      if (view === "costs") {
        const text = await page.locator("#sova-live-pages").innerText();
        assert.ok(text.includes("현재 금액 미확인"));
        assert.ok(!/0원|\$0|₩0|0\.00/.test(text));
      }
      checked.push(view);
    }
    await page.locator('nav [data-view="monitoring"]').click();
    const observed = await page.evaluate(async () => {
      const r = await fetch("/v1/observed-workload");
      if (!r.ok) throw Error("Actual observation unavailable");
      const v = await r.json();
      return {
        environments: v.environments.length,
        resources: v.graph?.nodes?.length ?? 0,
      };
    });
    assert.ok(
      observed.environments > 0 && observed.resources > 0,
      "Actual cluster data required",
    );
    await page.waitForFunction(
      () => document.querySelectorAll("#sova-live-pages tbody tr").length > 2,
    );
    const mobile = await page.viewportSize();
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    if (mobile) await page.setViewportSize(mobile);
    await page.locator('nav [data-view="topology"]').click();
    assert.deepEqual(
      writes,
      [],
      "Sidebar navigation must not dispatch mutations",
    );
    return {
      checked,
      actual_observed_environments: observed.environments,
      actual_observed_resources: observed.resources,
      navigation_mutations: 0,
      mobile_overflow: false,
    };
  } finally {
    page.off("request", watch);
  }
}
