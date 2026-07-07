import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render } from "@testing-library/react";
import { Modal } from "./ui.tsx";
import "@testing-library/jest-dom/vitest";

describe("<Modal> component", () => {
  afterEach(() => {
    cleanup();
  });

  it("focuses the first dialog control and restores previous focus on close", () => {
    const opener = document.createElement("button");
    opener.textContent = "Open";
    document.body.appendChild(opener);
    opener.focus();

    const { getByRole, unmount } = render(
      <Modal onClose={() => {}}>
        <button>Confirm</button>
      </Modal>,
    );

    expect(getByRole("button", { name: "Confirm" })).toHaveFocus();

    unmount();

    expect(opener).toHaveFocus();
    opener.remove();
  });

  it("keeps focus stable across onClose prop changes and uses the latest Escape handler", () => {
    const firstClose = vi.fn();
    const latestClose = vi.fn();

    const { getByRole, rerender } = render(
      <Modal onClose={firstClose}>
        <button>First</button>
        <button>Second</button>
      </Modal>,
    );

    const first = getByRole("button", { name: "First" });
    const second = getByRole("button", { name: "Second" });
    expect(first).toHaveFocus();

    second.focus();
    rerender(
      <Modal onClose={latestClose}>
        <button>First</button>
        <button>Second</button>
      </Modal>,
    );

    expect(second).toHaveFocus();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(firstClose).not.toHaveBeenCalled();
    expect(latestClose).toHaveBeenCalledTimes(1);
  });
});
