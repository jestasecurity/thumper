import { APP_NAME } from "../config/app.ts";
import { useMemo } from "react";
import { TITLE_SEPARATOR } from "../config/pageTitle.ts";

type Props = {
  title: string
}

export default function PageTitle({title}: Props) {
  const fullTitle = useMemo(() => {
    const clearTitle = title.trim();

    if (!clearTitle) {
      return APP_NAME;
    }

    return clearTitle + TITLE_SEPARATOR + APP_NAME;
  }, [title]);

  return (
    <title>{fullTitle}</title>
  );
}
