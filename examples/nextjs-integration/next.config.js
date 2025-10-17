/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    appDir: true,
  },
  env: {
    API_BASE_URL: process.env.API_BASE_URL || 'http://localhost:8080',
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.API_BASE_URL || 'http://localhost:8080'}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;