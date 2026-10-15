import type { Metadata } from "next";
import SessionBoundary from "./session-boundary";
import SkipToMain from "./skip-to-main";
import "./globals.css";

export const metadata: Metadata = {
  title: "iCheck · Infrastructure Operations",
  description: "AI-native infrastructure monitoring, identity, alerts, and operations.",
  other: process.env.ICHECK_FRONTEND_TARGET === "native" ? {} : {
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
      <body className="antialiased"><SkipToMain /><SessionBoundary>{children}</SessionBoundary></body>
    </html>
  );
}

