import { defineCollection, z } from 'astro:content';

// ── CONTENT LAYER ────────────────────────────────────────────────
// Everything under src/content/ is your writing. The UI never edits
// it; it only reads these fields. Keep prose here, design elsewhere.

const posts = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string().default(''),
    pubDate: z.coerce.date(),
    updatedDate: z.coerce.date().optional(),
    // Original WordPress permalink, e.g. /2026/03/12/slug/ — preserved
    // so existing links and search results keep working.
    permalink: z.string(),
    heroImage: z.string().optional(),
    // Card thumbnail only (does NOT render as a cover on the post page).
    // Use when you want a homepage thumbnail without a duplicate top image.
    thumb: z.string().optional(),
    series: z.string().optional(),
    seriesPart: z.number().optional(),
    tags: z.array(z.string()).default([]),
    draft: z.boolean().default(false),
  }),
});

const pages = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string().default(''),
  }),
});

const studies = defineCollection({
  type: 'data',
  schema: z.object({
    title: z.string(),
    cves: z.array(z.string()).default([]),
    product: z.string(),
    category: z.enum(['windows', 'web_infrastructure', 'patch_triage', 'malware_re']),
    verdict: z.string(),
    verdictClass: z.enum(['reproduced', 'inthewild', 'patchdiff', 'triage', 'chainre', 'mixed']),
    detail: z.string(),
    permalink: z.string().optional(),
    date: z.coerce.date(),
  }),
});

export const collections = { posts, pages, studies };
