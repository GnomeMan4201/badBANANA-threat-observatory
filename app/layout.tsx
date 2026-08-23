import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://badbanana-threat-observatory.badbanana6969.workers.dev"),
  title: "badBANANA // THREAT OBSERVATORY",
  description: "Evidence-first threat telemetry with current state, material-change replay, provenance, and approximate public-IP geography.",
  openGraph: {
    title: "badBANANA // THREAT OBSERVATORY",
    description: "Evidence-first threat telemetry with current state, material-change replay, provenance, and approximate public-IP geography.",
    images: ["/og.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "badBANANA // THREAT OBSERVATORY",
    description: "Evidence-first threat telemetry with current state, material-change replay, provenance, and approximate public-IP geography.",
    images: ["/og.png"],
  },
  icons: {
    icon: "/favicon.png",
    shortcut: "/favicon.png",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
