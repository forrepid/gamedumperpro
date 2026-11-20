import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "UnrealDumperX - UE4/UE5 Dump & SDK Otomasyon Araci",
  description:
    "Windows icin Unreal Engine dumper: GObjects/GNames otomatik konumlama, FName havuzu, SDK uretimi, vtable cozumcu, runtime offset kesfi ve kernel driver destegi.",
  keywords: ["Unreal Engine", "dumper", "SDK", "UE4", "UE5", "C++", "Windows"],
  icons: {
    icon: "https://z-cdn.chatglm.cn/z-ai/static/logo.svg",
  },
  openGraph: {
    title: "UnrealDumperX",
    description: "UE4/UE5 dump & SDK otomasyon araci",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
