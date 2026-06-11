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
