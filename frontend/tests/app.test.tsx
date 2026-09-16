import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { App } from "../src/App";

function renderRoute(route: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><App/></MemoryRouter></QueryClientProvider>);
}

describe("operator console", () => {
  it("shows the English dashboard and attack phase rail", async () => {
    renderRoute("/dashboard");
    expect(await screen.findByRole("heading", { name: "Review the final transition to Domain Admin" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Authorization boundary" })).toBeInTheDocument();
    expect(await screen.findByText("Initial Access")).toBeInTheDocument();
    expect(screen.getByText("No external dispatch")).toBeInTheDocument();
  });

  it("runs a mocked VLLM capability check", async () => {
    const user = userEvent.setup();
    renderRoute("/settings/llm");
    await user.click(await screen.findByRole("button", { name: /test connection & capabilities/i }));
    expect(await screen.findByText("Profile meets the required capability contract.", {}, { timeout: 2000 })).toBeInTheDocument();
    expect(screen.getByText("Unknown-field rejection")).toBeInTheDocument();
  });

  it("shows complete approval bindings before an operator decision", async () => {
    const user = userEvent.setup();
    renderRoute("/interventions");
    await user.click(await screen.findByRole("button", { name: /controlled administrative group transition/i }));
    expect(screen.getByText("Directory Membership Change (Training Adapter)")).toBeInTheDocument();
    expect(screen.getByText("group:LAB.EXAMPLE/Domain Admins")).toBeInTheDocument();
    expect(screen.getByText("sha256:da8f7c14ab90e211")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /approve bound intent/i })).toBeEnabled();
  });

  it("keeps planning choice separate from approval", async () => {
    const user = userEvent.setup();
    renderRoute("/interventions");
    await user.click(await screen.findByRole("button", { name: /choose the final evidence refresh/i }));
    expect(screen.getAllByText(/does not authorize execution/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /approve/i })).not.toBeInTheDocument();
  });

  it("marks Other target types as unresolved", async () => {
    const user = userEvent.setup();
    renderRoute("/missions/new");
    await user.selectOptions(await screen.findByLabelText("Target type"), "other");
    expect(screen.getByText(/stored as an unresolved draft/i)).toBeInTheDocument();
  });

  it("presents the knowledge graph as focused relationship views", async () => {
    const user = userEvent.setup();
    renderRoute("/knowledge");

    expect(await screen.findByRole("heading", { name: "Escalation path" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Escalation path", pressed: true })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Open details for Domain Admins" }).length).toBeGreaterThan(0);

    await user.click(screen.getAllByRole("button", { name: "Open details for Domain Admins" })[0]);
    expect(screen.getByRole("complementary", { name: "Selected knowledge node details" })).toBeInTheDocument();
    expect(screen.getByText("Final transition is pending explicit approval")).toBeInTheDocument();
    expect(screen.getByText("pending transition")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(screen.getByRole("heading", { name: "Infrastructure" })).toBeInTheDocument();
    expect(screen.queryByRole("complementary", { name: "Selected knowledge node details" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open details for LAB\\analyst01" })).not.toBeInTheDocument();
  });

  it("switches collected intelligence to a YAML-inspired structured inventory", async () => {
    const user = userEvent.setup();
    renderRoute("/knowledge");

    expect(await screen.findByRole("button", { name: "Graph view", pressed: true })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Structured view" }));

    expect(screen.getByRole("button", { name: "Structured view", pressed: true })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Structured inventory" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Structured knowledge inventory" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Redacted provenance inventory" })).toBeInTheDocument();
    expect(screen.getAllByText("artifact-redacted-112").length).toBeGreaterThan(0);
    expect(screen.getAllByText("derived_findings:")).toHaveLength(4);
    expect(screen.queryByRole("heading", { name: "Escalation path" })).not.toBeInTheDocument();
  });

  it("separates C2 selection from MCP tool control", async () => {
    const user = userEvent.setup();
    renderRoute("/settings/providers");

    expect(await screen.findByRole("tab", { name: "C2 Selection", selected: true })).toBeInTheDocument();
    const c2Select = screen.getByLabelText("Preferred C2");
    expect(c2Select).toHaveTextContent("Tuoni");
    expect(c2Select).toHaveTextContent("Sliver");
    expect(c2Select).not.toHaveTextContent("Cobalt Strike");
    expect(c2Select).toHaveValue("sliver");
    expect(screen.getByRole("heading", { name: "Sliver" })).toBeInTheDocument();
    expect(screen.getByText("not present")).toBeInTheDocument();
    await user.selectOptions(c2Select, "tuoni");
    expect(screen.getByRole("heading", { name: "Tuoni Commercial" })).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Tools (MCP) Control" }));
    expect(screen.getByRole("heading", { name: "Impacket MCP" })).toBeInTheDocument();
    expect(screen.getByText("RPC endpoint map")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Impacket" })).toBeInTheDocument();
    expect(screen.getAllByText("impacket.rpc.endpoint_map").length).toBeGreaterThan(0);
    expect(screen.getByText("TCP/135 only; bounded response")).toBeInTheDocument();
    expect(screen.queryByText(/NetExec/i)).not.toBeInTheDocument();
  });

  it("allows policy changes only for registered Impacket operations", async () => {
    const user = userEvent.setup();
    renderRoute("/settings/providers");
    await user.click(await screen.findByRole("tab", { name: "Tools (MCP) Control" }));

    const policy = screen.getByLabelText("Policy for SMB authentication");
    expect(policy).toBeEnabled();
    await user.selectOptions(policy, "disabled");
    expect(policy).toHaveValue("disabled");
  });

  it("collapses tool groups and reveals read-only command templates on demand", async () => {
    const user = userEvent.setup();
    const { container } = renderRoute("/settings/providers");
    await user.click(await screen.findByRole("tab", { name: "Tools (MCP) Control" }));

    const groups = Array.from(container.querySelectorAll<HTMLDetailsElement>("details.tool-operation-group"));
    expect(groups).toHaveLength(1);
    expect(groups.every((group) => !group.open)).toBe(true);

    const impacket = container.querySelector<HTMLDetailsElement>('details[data-tool="Impacket"]');
    expect(impacket).not.toBeNull();
    await user.click(impacket!.querySelector("summary")!);
    expect(impacket).toHaveAttribute("open");
    expect(impacket).toHaveTextContent("impacket.rpc.endpoint_map(target_ref=<approved-target-ref>)");
    expect(impacket).not.toHaveTextContent("impacket-secretsdump");
  });

  it("saves only a mocked provider policy draft", async () => {
    const user = userEvent.setup();
    renderRoute("/settings/providers");
    await user.click(await screen.findByRole("tab", { name: "Review Policy" }));
    await user.click(screen.getByRole("button", { name: "Save policy draft" }));
    expect(await screen.findByText(/No Mission was activated/i)).toBeInTheDocument();
  });
});
