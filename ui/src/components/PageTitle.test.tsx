import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import PageTitle from "./PageTitle.tsx";
import "@testing-library/jest-dom/vitest";

describe("<PageTitle> component", () => {
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
    const {getByText} = render(<PageTitle title={title} />);
    expect(getByText("Thumper")).toBeInTheDocument();
  });

  it.each(titles)("renders expected title of a page", (title) => {
    const {getByText} = render(<PageTitle title={title} />);
    expect(getByText(title.trim() + " · Thumper")).toBeInTheDocument();
  });
});
