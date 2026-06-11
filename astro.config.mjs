import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// Production site URL. Used for sitemap, RSS, and canonical links.
export default defineConfig({
  site: 'https://threatunpacked.com',
  integrations: [sitemap()],
  markdown: {
    shikiConfig: {
      theme: 'github-dark',
      wrap: false,
    },
  },
});
