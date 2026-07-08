import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { Modal } from "./ui.tsx";

describe("<Modal> component", () => {
  afterEach(() => {
    cleanup();
    document.body.innerHTML = "";
  });

  it("focuses the dialog and closes on Escape", () => {
    const onClose = vi.fn();

    render(
      <Modal onClose={onClose}>
        <h2>Confirm action</h2>
      </Modal>
    );

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveFocus();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("restores focus when unmounted", () => {
    const priorButton = document.createElement("button");
    document.body.appendChild(priorButton);
    priorButton.focus();

    const { unmount } = render(
      <Modal onClose={() => {}}>
        <h2>Confirm action</h2>
      </Modal>
    );

    expect(screen.getByRole("dialog")).toHaveFocus();

    unmount();

    expect(priorButton).toHaveFocus();
  });
});
