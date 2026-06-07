import { describe, expect, it, vi } from "vitest";
import type { ScanFinding } from "./types";
import {
  buildRepairPlan,
  emptyProgress,
  errorMessage,
  extractFindingFlagName,
  findingKey,
  formatRepairPlanText,
  formatAccountLabel,
  groupByVerdict,
  hasTauriRuntime,
  importBadgeTitle,
  parseFindingDetails,
  pathFieldAction,
  providerLabel,
  relativeTime,
  shouldShowAccountInventory,
  shortTime,
  truncate,
} from "./App";

function finding(
  verdict: ScanFinding["verdict"],
  overrides: Partial<ScanFinding> = {},
): ScanFinding {
  return {
    module: "memory",
    verdict,
    description: `${verdict} finding`,
    details: null,
    timestamp: "2026-05-06T12:34:56.000Z",
    ...overrides,
  };
}

describe("App UI helpers", () => {
  it("shows account inventory only after a live scan completes", () => {
    const report = {
      scan_id: "scan",
      timestamp: "2026-05-06T12:34:56.000Z",
      machine_id: "machine",
      os_info: "Windows 11",
      overall_verdict: "Clean" as const,
      findings: [],
      hmac_signature: "sig",
    };
    const importMeta = {
      signatureValid: true,
      ageSeconds: 30,
      stale: false,
      sourcePath: "/tmp/report.json",
    };

    expect(shouldShowAccountInventory("idle", null, null)).toBe(false);
    expect(shouldShowAccountInventory("scanning", report, null)).toBe(false);
    expect(shouldShowAccountInventory("complete", null, null)).toBe(false);
    expect(shouldShowAccountInventory("complete", report, importMeta)).toBe(false);
    expect(shouldShowAccountInventory("complete", report, null)).toBe(true);
  });

  it("builds pending progress entries for every backend scanner", () => {
    expect(emptyProgress()).toEqual({
      process_scanner: { state: "pending" },
      file_scanner: { state: "pending" },
      client_settings_scanner: { state: "pending" },
      prefetch_scanner: { state: "pending" },
    });
  });

  it("detects Tauri only from the injected runtime marker", () => {
    expect(hasTauriRuntime()).toBe(false);

    vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
    expect(hasTauriRuntime()).toBe(true);
    vi.unstubAllGlobals();
  });

  it("uses details in finding keys so same-tick findings stay distinct", () => {
    const base = finding("Suspicious", {
      description: "same",
      details: "Path: C:\\one",
    });

    expect(findingKey(base)).not.toBe(
      findingKey({ ...base, details: "Path: C:\\two" }),
    );
  });

  it("groups already-sorted findings without reordering them", () => {
    const flagged = finding("Flagged", { description: "first" });
    const suspiciousA = finding("Suspicious", { description: "second" });
    const suspiciousB = finding("Suspicious", { description: "third" });
    const clean = finding("Clean", { description: "fourth" });

    expect(groupByVerdict([flagged, suspiciousA, suspiciousB, clean])).toEqual([
      { verdict: "Flagged", items: [flagged] },
      { verdict: "Suspicious", items: [suspiciousA, suspiciousB] },
      { verdict: "Clean", items: [clean] },
    ]);
  });

  it("parses pipe-separated detail fields and preserves freeform leftovers", () => {
    expect(
      parseFindingDetails("Flag: DFFlagDebug | Value: true | raw tail"),
    ).toEqual({
      fields: [
        { label: "Flag", value: "DFFlagDebug" },
        { label: "Value", value: "true" },
      ],
      freeform: "raw tail",
    });
  });

  it("preserves multiline grouped finding values", () => {
    expect(
      parseFindingDetails(
        "PID: 1848 | Exact curated matches: 2 total\n- A=1\n- B=2 | Detection: live",
      ),
    ).toEqual({
      fields: [
        { label: "PID", value: "1848" },
        { label: "Exact curated matches", value: "2 total\n- A=1\n- B=2" },
        { label: "Detection", value: "live" },
      ],
      freeform: null,
    });
  });

  it("splits comma detail fields only at capitalized key boundaries", () => {
    expect(
      parseFindingDetails("Path: C:\\Roblox, Player\\Client.exe, Hash: abc123"),
    ).toEqual({
      fields: [
        { label: "Path", value: "C:\\Roblox, Player\\Client.exe" },
        { label: "Hash", value: "abc123" },
      ],
      freeform: null,
    });
  });

  it("does not treat loose prose as key-value details", () => {
    expect(parseFindingDetails("contains WriteProcessMemory: but no field")).toEqual({
      fields: [],
      freeform: "contains WriteProcessMemory: but no field",
    });
  });

  it("creates reveal actions from file evidence paths", () => {
    expect(
      pathFieldAction(
        finding("Suspicious", {
          module: "file_scanner",
          details:
            "Path: C:\\Users\\<user>\\AppData\\Local\\Bloxstrap, Player\\ClientAppSettings.json, Hash: abc123",
        }),
      ),
    ).toEqual({
      path: "C:\\Users\\<user>\\AppData\\Local\\Bloxstrap, Player\\ClientAppSettings.json",
      title:
        "Reveal evidence in folder: C:\\Users\\<user>\\AppData\\Local\\Bloxstrap, Player\\ClientAppSettings.json",
    });
  });

  it("creates reveal actions from prefetch evidence paths", () => {
    expect(
      pathFieldAction(
        finding("Suspicious", {
          module: "prefetch_scanner",
          details: "Prefetch file: C:\\Windows\\Prefetch\\TOOL.EXE-123.pf, Last modified: today",
        }),
      ),
    ).toEqual({
      path: "C:\\Windows\\Prefetch\\TOOL.EXE-123.pf",
      title: "Reveal evidence in folder: C:\\Windows\\Prefetch\\TOOL.EXE-123.pf",
    });
  });

  it("extracts quoted FFlag names from scanner descriptions", () => {
    expect(
      extractFindingFlagName('Critical FFlag detected: "DFIntS2PhysicsSenderRate" = 1'),
    ).toBe("DFIntS2PhysicsSenderRate");
    expect(extractFindingFlagName("ClientAppSettings.json file exists")).toBe(null);
  });

  it("groups client-settings findings into one auto repair plan per file", () => {
    const plan = buildRepairPlan([
      finding("Flagged", {
        module: "client_settings_scanner",
        description: 'Critical FFlag detected: "DFIntS2PhysicsSenderRate" = 1',
        details: "Path: C:\\Users\\<user>\\Roblox\\ClientSettings\\ClientAppSettings.json | Category: DESYNC",
      }),
      finding("Suspicious", {
        module: "client_settings_scanner",
        description:
          'Suspicious FFlag detected: "DFIntCullFactorPixelThresholdMainViewHighQuality" = 10000',
        details: "Path: C:\\Users\\<user>\\Roblox\\ClientSettings\\ClientAppSettings.json | Category: VISUAL",
      }),
    ]);

    expect(plan).toHaveLength(1);
    expect(plan[0]).toMatchObject({
      kind: "auto",
      verdict: "Flagged",
      title: "Repair FFlag settings",
      evidencePath:
        "C:\\Users\\<user>\\Roblox\\ClientSettings\\ClientAppSettings.json",
      findingCount: 2,
    });
    expect(plan[0].flags).toEqual([
      "DFIntCullFactorPixelThresholdMainViewHighQuality",
      "DFIntS2PhysicsSenderRate",
    ]);
  });

  it("keeps prefetch and inconclusive findings out of auto repair", () => {
    const plan = buildRepairPlan([
      finding("Suspicious", {
        module: "prefetch_scanner",
        description: "Known tool execution history found",
        details: "Prefetch file: C:\\Windows\\Prefetch\\TOOL.EXE-123.pf, Last modified: today",
      }),
      finding("Inconclusive", {
        module: "client_settings_scanner",
        description: "Could not read ClientAppSettings.json: Access denied",
        details: "Path: C:\\Roblox\\ClientSettings\\ClientAppSettings.json",
      }),
    ]);

    expect(plan.map((item) => item.kind)).toEqual(["diagnostic", "diagnostic"]);
    expect(plan.some((item) => item.kind === "auto")).toBe(false);
  });

  it("formats repair plan copy text", () => {
    const text = formatRepairPlanText([
      {
        id: "auto|path",
        kind: "auto",
        verdict: "Flagged",
        module: "client_settings_scanner",
        title: "Repair FFlag settings",
        detail: "Back up and clean 1 override in C:\\x.json.",
        evidencePath: "C:\\x.json",
        flags: ["DFIntS2PhysicsSenderRate"],
        findingCount: 1,
      },
    ]);

    expect(text).toContain("Prism repair plan");
    expect(text).toContain("[Flagged / auto-repairable]");
    expect(text).toContain("DFIntS2PhysicsSenderRate");
  });

  it("formats non-Error failures without losing message fields", () => {
    expect(errorMessage("plain failure")).toBe("plain failure");
    expect(errorMessage({ message: "structured failure" })).toBe("structured failure");
    expect(errorMessage({ code: "E_FAIL" })).toBe('{"code":"E_FAIL"}');
  });

  it("formats verified account labels", () => {
    expect(providerLabel("discord")).toBe("Discord");
    expect(
      formatAccountLabel({ username: "ev", display_name: "Evelyn" }),
    ).toBe("Evelyn (@ev)");
    expect(
      formatAccountLabel({ username: "ev", display_name: "ev" }),
    ).toBe("ev");
    expect(
      formatAccountLabel({ username: "ev", display_name: null }),
    ).toBe("ev");
  });

  it("formats import badge titles with signature and staleness state", () => {
    expect(
      importBadgeTitle({
        signatureValid: true,
        ageSeconds: 90,
        stale: false,
        sourcePath: "/tmp/report.json",
      }),
    ).toBe("signature OK · 2m old\n/tmp/report.json");

    expect(
      importBadgeTitle({
        signatureValid: false,
        ageSeconds: 7200,
        stale: true,
        sourcePath: "/tmp/old.json",
      }),
    ).toBe(
      "signature INVALID · 2h old (exceeds 30m freshness window)\n/tmp/old.json",
    );
  });

  it("truncates long labels and leaves short labels intact", () => {
    expect(truncate("abcdef", 6)).toBe("abcdef");
    expect(truncate("abcdef", 4)).toBe("abcd…");
  });

  it("formats relative times at UI thresholds", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-06T12:00:00.000Z"));

    expect(relativeTime(new Date("2026-05-06T11:59:58.000Z"))).toBe("just now");
    expect(relativeTime(new Date("2026-05-06T11:59:30.000Z"))).toBe("30s ago");
    expect(relativeTime(new Date("2026-05-06T11:30:00.000Z"))).toBe("30m ago");
    expect(relativeTime(new Date("2026-05-06T09:00:00.000Z"))).toBe("3h ago");

    vi.useRealTimers();
  });

  it("renders short times without throwing for valid ISO timestamps", () => {
    expect(shortTime("2026-05-06T12:34:56.000Z")).toMatch(/\d{2}:\d{2}/);
  });
});
