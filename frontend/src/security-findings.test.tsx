import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SecurityFindingsPanel from "./components/SecurityFindingsPanel";

const finding = {
  id: 7,
  title: "Missing HSTS",
  severity: "MEDIUM",
  status: "FAIL",
  category: "TLS",
  hostname: "example.test",
  confidence: "HIGH",
  remediation: { status: "OPEN", verification_status: "NOT_REQUESTED", history: [] },
  first_detected: "2026-01-01T00:00:00Z",
};

describe("security findings management panel", () => {
  beforeEach(() => {
    global.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/security-findings/7") && (!init?.method || init.method === "GET")) {
        return { ok: true, json: async () => ({ ...finding, description: "HSTS is absent", evidence: { header: null } }) } as Response;
      }
      if (url.endsWith("/security-findings") || url.includes("/security-findings?")) {
        return { ok: true, json: async () => ({ items: [finding], total: 1, pages: 1, counts: { severity: { MEDIUM: 1 }, status: { FAIL: 1 }, remediation: { OPEN: 1 } } }) } as Response;
      }
      if (url.includes("/security-assessments") && init?.method === "POST") return { ok: true, json: async () => ({ id: 42 }) } as Response;
      if (url.includes("/security-assessments/42/reports")) return { ok: true, json: async () => ({ items: [{ format: "json", generated_at: "2026-01-01T00:00:00Z" }] }) } as Response;
      return { ok: true, json: async () => ({ ...finding, remediation: { ...finding.remediation, status: "ACKNOWLEDGED" } }) } as Response;
    }) as typeof fetch;
  });

  it("renders counts, filters, details and remediation controls", async () => {
    render(<SecurityFindingsPanel />);
    expect(await screen.findByText(/Missing HSTS/)).toBeInTheDocument();
    expect(screen.getByText("Security findings and remediation")).toBeInTheDocument();
    fireEvent.click(screen.getByText(/Missing HSTS/));
    expect(await screen.findByText("HSTS is absent")).toBeInTheDocument();
    expect(screen.getByText("Remediation workflow")).toBeInTheDocument();
    expect(screen.getByText("No remediation actions recorded.")).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText("Hostname"), { target: { value: "example.test" } });
  });

  it("does not present an empty result as a clean result", async () => {
    (global.fetch as any).mockImplementation(async () => ({
      ok: true,
      json: async () => ({ items: [], total: 0, pages: 0, counts: {} }),
    }));
    render(<SecurityFindingsPanel />);
    await waitFor(() => expect(screen.getByText("No findings match the selected filters.")).toBeInTheDocument());
    expect(screen.queryByText("SAFE")).not.toBeInTheDocument();
  });

  it("exposes report preview and export controls for a created assessment", async () => {
    render(<SecurityFindingsPanel scan={{ id: 11, url: "https://example.test/" }} />);
    fireEvent.click(screen.getByText("Create assessment"));
    expect(await screen.findByText("Preview report")).toBeInTheDocument();
    expect(screen.getByText("Download pdf")).toBeInTheDocument();
    expect(screen.getByText(/Previous exports:/)).toBeInTheDocument();
  });
});
