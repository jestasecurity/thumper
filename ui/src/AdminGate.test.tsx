import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import AdminGate from "./AdminGate.tsx";
import { clearAdminToken, getAdminToken, setAdminToken } from "./api/auth.ts";

describe("<AdminGate> component", () => {
  beforeEach(() => {
    const values = new Map<string, string>();
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
      clear: () => values.clear(),
      key: (index: number) => Array.from(values.keys())[index] ?? null,
      get length() {
        return values.size;
      },
    } as Storage;

    Object.defineProperty(globalThis, "localStorage", {
      value: storage,
      configurable: true,
    });
  });

  afterEach(() => {
    cleanup();
    clearAdminToken();
  });

  it("prompts for an admin token when none is stored", () => {
    render(
      <AdminGate>
        <main>Dashboard content</main>
      </AdminGate>
    );

    expect(screen.getByRole("heading", { name: "Thumper" })).toBeInTheDocument();
    expect(screen.getByLabelText("Admin token")).toHaveFocus();
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    expect(screen.queryByText("Dashboard content")).not.toBeInTheDocument();
  });

  it("trims and stores the token before showing the app", () => {
    render(
      <AdminGate>
        <main>Dashboard content</main>
      </AdminGate>
    );

    fireEvent.change(screen.getByLabelText("Admin token"), {
      target: { value: "  secret-token  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(getAdminToken()).toBe("secret-token");
    expect(screen.getByText("Dashboard content")).toBeInTheDocument();
    expect(screen.queryByLabelText("Admin token")).not.toBeInTheDocument();
  });

  it("shows the app immediately when a token is already stored", () => {
    setAdminToken("existing-token");

    render(
      <AdminGate>
        <main>Dashboard content</main>
      </AdminGate>
    );

    expect(screen.getByText("Dashboard content")).toBeInTheDocument();
    expect(screen.queryByLabelText("Admin token")).not.toBeInTheDocument();
  });
});
