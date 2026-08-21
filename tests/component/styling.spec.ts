// R-011: the component's CSS collides with a host application despite scoping.
//
// The harness page is deliberately hostile — a universal selector that changes the box
// model and the font, `all: revert-layer` on every element the component uses, a
// magenta body, `line-height: 3`, dashed red borders on buttons, 22px text. It is not
// a realistic host page; it is every mistake a host page could make, at once.
//
// The test runs in both directions, because "scoped" is two claims: the host does not
// break us, and we do not touch the host.

import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!window.harness);
});

test("the component survives a hostile host page", async ({ page }) => {
  await page.evaluate(() =>
    window.harness.mount({ ready: { recording: true, mode: "gateway" } } as never),
  );
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();

  const term = page.locator(".oarlock-term");
  const styles = await term.evaluate((el) => {
    const cs = getComputedStyle(el);
    return {
      boxSizing: cs.boxSizing,
      fontSize: cs.fontSize,
      lineHeight: cs.lineHeight,
      display: cs.display,
      background: cs.backgroundColor,
      color: cs.color,
    };
  });

  // Our own font size and line height, not the host's 22px/3.
  expect(styles.fontSize).toBe("14px");
  expect(styles.lineHeight).toBe("21px");
  expect(styles.display).toBe("flex");
  // Not the host's magenta-on-green.
  expect(styles.background).not.toBe("rgb(255, 0, 255)");
  expect(styles.color).not.toBe("rgb(0, 255, 0)");

  // The bar is laid out, not stacked into a column by the host's rules.
  const bar = await page.locator(".oarlock-bar").evaluate((el) => {
    const cs = getComputedStyle(el);
    return { display: cs.display, alignItems: cs.alignItems };
  });
  expect(bar.display).toBe("flex");
  expect(bar.alignItems).toBe("center");

  // The terminal has real, non-degenerate dimensions — the failure mode of a flex
  // child with no min-height is a terminal 0 pixels tall that still "renders".
  const box = await page.locator(".oarlock-screen").boundingBox();
  expect(box!.height).toBeGreaterThan(200);
  expect(box!.width).toBeGreaterThan(400);
});

test("the component does not restyle the host page", async ({ page }) => {
  const before = await page.evaluate(() => {
    const cs = getComputedStyle(document.body);
    return { bg: cs.backgroundColor, color: cs.color, font: cs.fontFamily, size: cs.fontSize };
  });

  await page.evaluate(() =>
    window.harness.mount({ ready: { recording: true, mode: "gateway" } } as never),
  );
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();

  const after = await page.evaluate(() => {
    const cs = getComputedStyle(document.body);
    return { bg: cs.backgroundColor, color: cs.color, font: cs.fontFamily, size: cs.fontSize };
  });
  // A reset of ours would be an uninvited change to somebody else's page. The host's
  // choices are terrible and they stay exactly as terrible as they were.
  expect(after).toEqual(before);
});

test("every rule in the stylesheet is scoped, and every property namespaced", async ({ page }) => {
  const audit = await page.evaluate(() => {
    const offenders: { selector: string; reason: string; sheet: string }[] = [];
    const stray: string[] = [];
    let audited = 0;

    // Identify *our* sheets by where they came from, not by what they contain: an
    // audit that only inspects selectors already mentioning "oarlock" cannot catch a
    // bare `button { }` rule, which is the exact mistake R-011 is about.
    const ours = (sheet: CSSStyleSheet): string | null => {
      const node = sheet.ownerNode as HTMLElement | null;
      const id = node?.dataset?.["viteDevId"] ?? sheet.href ?? "";
      return /oarlock\.css|tokens\.css|player\.css/.test(id) ? id : null;
    };

    for (const sheet of Array.from(document.styleSheets)) {
      const origin = ours(sheet as CSSStyleSheet);
      if (!origin) continue;
      let rules: CSSRule[];
      try {
        rules = Array.from(sheet.cssRules);
      } catch {
        continue;
      }
      const walk = (list: CSSRule[]) => {
        for (const rule of list) {
          if (rule instanceof CSSGroupingRule) {
            walk(Array.from(rule.cssRules));
            continue;
          }
          if (!(rule instanceof CSSStyleRule)) continue;
          audited += 1;
          for (const decl of Array.from(rule.style)) {
            if (!decl.startsWith("--")) continue;
            // Ours are --oarlock-*. A dependency's documented variables are also
            // legitimate — player.css deliberately sets asciinema's --term-color-* from
            // our generated tokens, which is how replay and live sessions stay one
            // terminal. What must not appear is a name in neither space, because that is
            // a property that can collide with the host's own.
            if (/^--(oarlock-|term-|xterm-)/.test(decl)) continue;
            stray.push(decl);
          }
          for (const part of rule.selectorText.split(",").map((s) => s.trim())) {
            // Three namespaces are legitimate and nothing else is: ours, xterm's, and
            // asciinema-player's — the latter two arrive global from stylesheets we
            // import, for the reasons given in oarlock.css and player.css. What must
            // never appear is a bare element selector or an unnamespaced class, because
            // that is what reaches into the host's page.
            // Anchored, not positioned: what matters is that *something* in the
            // selector confines it to a namespace, wherever it appears. `div.ap-wrapper
            // .title-bar` is anchored by `.ap-wrapper` even though `.title-bar` is a bare
            // class, and `div.ap-term canvas` is anchored even though `canvas` is an
            // element. What must never appear is a selector with no anchor at all —
            // `button {}`, `p { color: red }` — because that reaches into the host page.
            if (/\.(oarlock-|xterm|ap-|asciinema-player-)/.test(part)) continue;
            offenders.push({
              selector: part,
              reason: "neither scoped to .oarlock- nor namespaced .xterm",
              sheet: origin,
            });
          }
        }
      };
      walk(rules);
    }
    return { offenders, stray, audited };
  });

  // A sheet that failed to load would make the two assertions below vacuous, which is
  // the failure mode of every audit test.
  expect(audit.audited, "no rules were audited — did the stylesheet load?").toBeGreaterThan(20);
  expect(audit.offenders, JSON.stringify(audit.offenders)).toEqual([]);
  // A property that is not --oarlock-* is one that can collide with the host's.
  expect(audit.stray, JSON.stringify(audit.stray)).toEqual([]);
});

test("mounting does not modify the host page", async ({ page }) => {
  // Deliberately narrower than it looks, and worth saying why: the stylesheet is loaded
  // when the module is imported, not when the component mounts, so a before/after
  // comparison around mount() cannot see stylesheet-level leakage — the audit above is
  // what covers that. What this covers is the other half: mounting must not stamp
  // attributes on <html> or <body>, reparent anything, or inject a rule that reaches
  // outside the component.
  //
  // It does inject stylesheets, and that is not a defect to assert away: xterm creates
  // its own <style> at open() for per-instance character metrics. So the assertion is
  // about their *content* — everything injected stays inside one of the two namespaces.
  const snapshot = () =>
    page.evaluate(() => ({
      bodyAttrs: [...document.body.attributes].map((a) => `${a.name}=${a.value}`).sort(),
      htmlAttrs: [...document.documentElement.attributes].map((a) => `${a.name}=${a.value}`).sort(),
      bodyClass: document.body.className,
      directChildren: document.body.childElementCount,
      styleNodes: document.querySelectorAll("style, link[rel=stylesheet]").length,
    }));

  const before = await snapshot();
  await page.evaluate(() =>
    window.harness.mount({ ready: { recording: true, mode: "gateway" } } as never),
  );
  await expect(page.locator(".oarlock-term .xterm")).toBeVisible();
  const after = await snapshot();

  expect(after.bodyAttrs).toEqual(before.bodyAttrs);
  expect(after.htmlAttrs).toEqual(before.htmlAttrs);
  expect(after.bodyClass).toEqual(before.bodyClass);
  // One new child: the component's own root, in the host element it was given.
  expect(after.directChildren).toEqual(before.directChildren);

  // Whatever was injected has to stay in its lane.
  const escapes = await page.evaluate((existing) => {
    const nodes = [...document.querySelectorAll("style")].slice(existing);
    const out: string[] = [];
    for (const node of nodes) {
      const sheet = node.sheet;
      if (!sheet) continue;
      for (const rule of Array.from(sheet.cssRules)) {
        if (!(rule instanceof CSSStyleRule)) continue;
        for (const part of rule.selectorText.split(",").map((s) => s.trim())) {
          if (part.includes(".oarlock-") || /(^|[\s>+~])\.xterm/.test(part)) continue;
          out.push(part);
        }
      }
    }
    return out;
  }, before.styleNodes);
  expect(escapes, `injected rules that escape both namespaces: ${escapes.join(", ")}`).toEqual([]);
});

test("the tokens are defined on the bare root, not only under a theme selector", async ({
  page,
}) => {
  // The component has to render correctly in a host that has stamped no theme at all,
  // which is the majority case. A token whose only definition sits behind a dark
  // selector renders one theme's text on the other theme's ground.
  await page.evaluate(() =>
    window.harness.mount({ ready: { recording: true, mode: "gateway" } } as never),
  );
  const missing = await page.locator(".oarlock-term").evaluate((el) => {
    const cs = getComputedStyle(el);
    const needed = [
      "--oarlock-bg",
      "--oarlock-bg-raised",
      "--oarlock-bg-terminal",
      "--oarlock-border",
      "--oarlock-fg",
      "--oarlock-fg-muted",
      "--oarlock-state-recorded",
      "--oarlock-state-unrecorded",
      "--oarlock-state-observed",
      "--oarlock-state-reconnecting",
      "--oarlock-state-ended",
      "--oarlock-state-refused",
    ];
    return needed.filter((p) => cs.getPropertyValue(p).trim() === "");
  });
  expect(missing, `undefined tokens: ${missing.join(", ")}`).toEqual([]);
});

test("both themes resolve, and neither leaves text on its own ground", async ({ page }) => {
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.evaluate(() =>
      window.harness.mount({ ready: { recording: true, mode: "gateway" } } as never),
    );
    await expect(page.locator(".oarlock-term .xterm")).toBeVisible();

    const { fg, bg } = await page.locator(".oarlock-term").evaluate((el) => {
      const cs = getComputedStyle(el);
      return { fg: cs.color, bg: cs.backgroundColor };
    });
    expect(fg, `${scheme}: no foreground`).not.toBe("");
    expect(bg, `${scheme}: transparent background borrows the host's ground`).not.toBe(
      "rgba(0, 0, 0, 0)",
    );
    expect(fg, `${scheme}: foreground equals background`).not.toBe(bg);
  }
});

