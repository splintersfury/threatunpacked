import type { CollectionEntry } from 'astro:content';

export function readingTime(body: string): number {
  const words = body.trim().split(/\s+/).length;
  return Math.max(1, Math.round(words / 200));
}

export function postHref(post: CollectionEntry<'posts'>): string {
  return post.data.permalink;
}

export function byDateDesc(a: CollectionEntry<'posts'>, b: CollectionEntry<'posts'>): number {
  return b.data.pubDate.valueOf() - a.data.pubDate.valueOf();
}

// A short, terminal-flavored "filename" for a post (decorative).
export function fileName(post: CollectionEntry<'posts'>): string {
  if (post.data.seriesPart) return `driver-analyzer-pt${post.data.seriesPart}.md`;
  const s = post.slug;
  if (s.includes('netfilter')) return 'netfilter-driver.md';
  return s.split('-').slice(0, 3).join('-') + '.md';
}

// First image referenced anywhere in the post — used as a thumbnail when
// there's no explicit heroImage, so every card has a visual.
export function thumbFor(post: CollectionEntry<'posts'>): string | undefined {
  if (post.data.thumb) return post.data.thumb;
  if (post.data.heroImage) return post.data.heroImage;
  const m = post.body.match(/\]\((\/images\/[^)\s]+)/);
  return m ? m[1] : undefined;
}

// URL-safe tag slug, e.g. "Open-Director" -> "open-director".
export function slugifyTag(tag: string): string {
  return tag.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

// YYYY-MM-DD for mono metadata rows. Uses local date parts so it doesn't
// shift a day across timezones (the way toISOString() would).
export function isoDate(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
