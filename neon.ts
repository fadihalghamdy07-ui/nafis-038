import { defineConfig } from '@neon/config/v1';

export default defineConfig({
  functions: {
    nafisapi: {
      name: 'Nafis 038 secure API',
      source: './functions/nafis-api.mjs',
      env: {
        NAFIS_ADMIN_EMAIL: process.env.NAFIS_ADMIN_EMAIL!,
        NAFIS_ADMIN_PASSWORD_HASH: process.env.NAFIS_ADMIN_PASSWORD_HASH!,
        NAFIS_SESSION_SECRET: process.env.NAFIS_SESSION_SECRET!,
        NAFIS_ALLOWED_ORIGINS: process.env.NAFIS_ALLOWED_ORIGINS || 'https://fadihalghamdy07-ui.github.io',
        NAFIS_STUDENT_PORTAL_ENABLED: process.env.NAFIS_STUDENT_PORTAL_ENABLED || 'false',
      },
    },
  },
  triggers: {
    nafisWeeklyResults: {
      type: 'schedule',
      function: 'nafisapi',
      cron: '0 15 * * 6',
      functionPath: '/internal/publish-results',
      enabled: true,
    },
  },
});
