import localFont from "next/font/local";
import type { Metadata, Viewport } from "next";
import "katex/dist/katex.min.css";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { ToasterProvider } from "@/components/toaster-provider";
import { I18nProvider } from "@/i18n/client-provider";

// Vendored upstream fonts keep production/static builds independent of Google TLS.
const sans = localFont({
  src: "./fonts/geist.ttf",
  weight: "400 700",
  style: "normal",
  display: "swap",
  variable: "--font-geist"
});

const mono = localFont({
  src: "./fonts/geist-mono.ttf",
  weight: "400 600",
  style: "normal",
  display: "swap",
  variable: "--font-geist-mono"
});

const serif = localFont({
  src: [
    { path: "./fonts/instrument-serif-regular.ttf", weight: "400", style: "normal" },
    { path: "./fonts/instrument-serif-italic.ttf", weight: "400", style: "italic" }
  ],
  display: "swap",
  adjustFontFallback: "Times New Roman",
  variable: "--font-instrument-serif"
});

export const metadata: Metadata = {
  title: "OSIR Anywhere",
  description: "Remote control plane for coding agents",
  applicationName: "OSIR Anywhere",
  manifest: "/site.webmanifest",
  icons: {
    icon: [
      {
        url: "/favicon-dark-mode.png",
        type: "image/png",
        media: "(prefers-color-scheme: dark)"
      },
      {
        url: "/favicon-light-mode.png",
        type: "image/png",
        media: "(prefers-color-scheme: light)"
      },
      {
        url: "/favicon-dark-mode.png",
        type: "image/png"
      }
    ],
    apple: [
      {
        url: "/apple-touch-icon.png",
        sizes: "180x180",
        type: "image/png"
      }
    ]
  },
  appleWebApp: {
    capable: true,
    title: "OSIR Anywhere",
    statusBarStyle: "black-translucent"
  }
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  colorScheme: "dark light",
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#0a0a0b" },
    { media: "(prefers-color-scheme: light)", color: "#fafaf9" }
  ]
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${sans.variable} ${mono.variable} ${serif.variable} antialiased`}>
        <I18nProvider>
          <ThemeProvider defaultTheme="dark">
            {children}
            <ToasterProvider />
          </ThemeProvider>
        </I18nProvider>
      </body>
    </html>
  );
}
