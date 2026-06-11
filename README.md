# Threat Unpacked

Source for [threatunpacked.com](https://threatunpacked.com) — operational malware
analysis. Built with [Astro](https://astro.build); content and UI are kept
strictly separate so the look can be iterated without touching the writing.

## Structure

```
src/
  content/posts/   ← the writing (Markdown). UI work never edits this.
  content/pages/   ← About / Featured Investigations
  layouts/         ← page shells (UI)
  components/       ← header, footer, cards (UI)
  styles/global.css ← design tokens: colors, type, spacing (UI)
  pages/           ← routes (home, [...permalink], about, rss, 404)
public/images/     ← post images (localized from WordPress)
scripts/migrate-wordpress.mjs ← one-shot WordPress → Markdown importer
```

The accent color, fonts, light/dark themes — everything visual — live in
`src/styles/global.css` and the component `<style>` blocks. Change a token,
restyle the whole site.

## Develop

```bash
npm install
npm run dev       # local dev server
npm run build     # static build → dist/
npm run preview   # serve the built site
```

## Re-import from WordPress (if needed)

```bash
npm run migrate   # pulls posts/pages/images from the WordPress.com REST API
```

## Deploy

Static output in `dist/`. Hosted free; the `threatunpacked.com` domain points
here via DNS while remaining registered at its registrar.
