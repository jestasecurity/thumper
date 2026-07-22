import { useState } from "react";

// Plugin name -> brand logo in /public/brands. Unknown providers fall back to a
// monogram tile, so a new honeytoken plugin still renders cleanly with no asset.
const BRANDS: Record<string, string> = {
  datadog: "/brands/datadog.svg",
  salesforce: "/brands/salesforce.svg",
  aws: "/brands/aws.svg",
};

export default function ProviderLogo({
  plugin,
  label,
  size = 28,
}: {
  plugin: string;
  label?: string;
  size?: number;
}) {
  const [broken, setBroken] = useState(false);
  const src = BRANDS[plugin];
  const alt = label ?? plugin;

  if (src && !broken) {
    return (
      <img
        className="provider-logo"
        src={src}
        alt={alt}
        title={alt}
        width={size}
        height={size}
        onError={() => setBroken(true)}
      />
    );
  }
  // Monogram fallback: first letter on a neutral tile.
  return (
    <span
      className="provider-logo provider-logo-fallback"
      title={alt}
      style={{ width: size, height: size, fontSize: size * 0.45 }}
    >
      {(alt[0] ?? "?").toUpperCase()}
    </span>
  );
}
