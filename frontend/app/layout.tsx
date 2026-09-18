import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "iCheck · Infrastructure Operations",
  description: "AI-native infrastructure monitoring, identity, alerts, and operations.",
  other: {
    "codex-preview": "development",
  },
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
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

