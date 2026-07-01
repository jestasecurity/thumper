import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";
import PageTitle from "./PageTitle.tsx";
import "@testing-library/jest-dom/vitest";

// React 18 renders <title> inside the component's container; React 19 hoists
// document metadata (<title>/<meta>/<link>) into <head>. Read the rendered
// title from wherever the running React version places it, so this suite stays
// green both now (React 18) and once #191/#192 move the app to React 19.
function renderedTitleText(container: HTMLElement): string | null {
  const el =
    container.querySelector("title") ?? document.head.querySelector("title");
  return el?.textContent ?? null;
}

describe("<PageTitle> component", () => {
  afterEach(() => {
    cleanup();
    // React 19 may leave its hoisted <title> in <head> after unmount in jsdom;
    // clear it so the next test never reads a stale title via the head fallback.
    document.head.querySelectorAll("title").forEach((t) => t.remove());
  });

  const unknownTitles = [
    "",
    " ",
    "  ",
  ];

  const titles = [
    "1",
    "x",
    "Lorem",
    "Lorem Ipsum",
    " Lorem Ipsum",
    "Lorem Ipsum ",
    " Lorem Ipsum ",
  ];

  it.each(unknownTitles)("renders title of app if page title is unknown", (title) => {
    const { container } = render(<PageTitle title={title} />);
    expect(renderedTitleText(container)).toBe("Thumper");
  });

  it.each(titles)("renders expected title of a page", (title) => {
    const { container } = render(<PageTitle title={title} />);
    expect(renderedTitleText(container)).toBe(title.trim() + " · Thumper");
  });
});
