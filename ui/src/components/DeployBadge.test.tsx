import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { DeployBadge } from "./ui.tsx";

describe("<DeployBadge> component", () => {
  afterEach(() => {
    cleanup();
  });

  it("explains that pending deployments wait for agent sync", () => {
    render(<DeployBadge state="pending" />);

    const badge = screen.getByTitle("waiting for agent sync");
    expect(badge).toHaveTextContent("pending · waiting for sync");
  });
});
