import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  /* config options here */
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  // Bu sandbox cgroup bellek limiti ~1.65 GB; Turbopack buyuk analiz grafigini
  // derlerken tepe yapip OOM kill yiyor. Turbopack onbellegini kisitla ki
  // GC erken devreye girsin (dev stabilligi icin - Gorev 4 testleri).
  turbopack: {
    memoryLimit: 768 * 1024 * 1024,
  },
};

export default nextConfig;
