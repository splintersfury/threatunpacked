// ─────────────────────────────────────────────────────────────────
// WordPress → Astro content migration.
//
// Pulls posts + pages from the WordPress.com REST API (canonical
// source), converts the rendered HTML to Markdown, downloads every
// referenced image locally into public/images/, rewrites the URLs,
// and writes Markdown files into src/content/. Re-runnable.
//
//   node scripts/migrate-wordpress.mjs
// ─────────────────────────────────────────────────────────────────
import { writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import TurndownService from 'turndown';
import { gfm } from 'turndown-plugin-gfm';

const SITE = 'threatunpacked.com';
const API = `https://public-api.wordpress.com/wp/v2/sites/${SITE}`;
const ROOT = path.resolve(import.meta.dirname, '..');
const POSTS_DIR = path.join(ROOT, 'src/content/posts');
const PAGES_DIR = path.join(ROOT, 'src/content/pages');
const IMG_DIR = path.join(ROOT, 'public/images');

const td = new TurndownService({
  headingStyle: 'atx',
  codeBlockStyle: 'fenced',
  bulletListMarker: '-',
  emDelimiter: '*',
});
td.use(gfm);
// Keep <figure>/<figcaption> readable: drop the wrapper, keep caption as italic line.
td.addRule('figure', {
  filter: 'figure',
  replacement: (content) => '\n\n' + content.trim() + '\n\n',
});
td.addRule('figcaption', {
  filter: 'figcaption',
  replacement: (content) => content.trim() ? `\n*${content.trim()}*\n` : '',
});

const NAMED = {
  nbsp: ' ', amp: '&', lt: '<', gt: '>', quot: '"', apos: "'",
  hellip: '…', mdash: '—', ndash: '–', rsquo: '’', lsquo: '‘',
  rdquo: '”', ldquo: '“', times: '×', deg: '°', copy: '©',
};
function decodeEntities(s = '') {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&([a-zA-Z]+);/g, (m, n) => (n in NAMED ? NAMED[n] : m));
}
const stripHtml = (s = '') => decodeEntities(s.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
}

const imageMap = new Map(); // remoteUrl -> /images/local.ext
function localNameFor(url, slug) {
  const clean = url.split('?')[0].split('#')[0];
  let base = path.basename(clean) || 'image';
  base = base.replace(/[^a-zA-Z0-9._-]/g, '-');
  if (!/\.[a-zA-Z0-9]{2,5}$/.test(base)) base += '.png';
  return `${slug}-${base}`.toLowerCase();
}
async function downloadImage(url, slug) {
  if (imageMap.has(url)) return imageMap.get(url);
  const name = localNameFor(url, slug);
  const dest = path.join(IMG_DIR, name);
  const webPath = `/images/${name}`;
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`${r.status}`);
    const buf = Buffer.from(await r.arrayBuffer());
    await writeFile(dest, buf);
    console.log(`  ↓ image ${webPath} (${(buf.length / 1024).toFixed(0)}kb)`);
  } catch (e) {
    console.warn(`  ! image failed, keeping remote URL: ${url} (${e.message})`);
    imageMap.set(url, url);
    return url;
  }
  imageMap.set(url, webPath);
  return webPath;
}

// Collect image URLs from rendered HTML before turndown so we can map them.
async function localizeImages(html, slug) {
  const urls = new Set();
  for (const m of html.matchAll(/<img[^>]+src=["']([^"']+)["']/gi)) urls.add(m[1]);
  for (const m of html.matchAll(/<a[^>]+href=["']([^"']+\.(?:png|jpe?g|gif|webp|svg))["']/gi)) urls.add(m[1]);
  let out = html;
  for (const u of urls) {
    if (/^https?:\/\//.test(u)) {
      const local = await downloadImage(u, slug);
      out = out.split(u).join(local);
    } else if (/(^|\/)images\//.test(u)) {
      // Relative ../images/foo.png references (legacy, may be broken) →
      // map to /images/ so the build resolves; drop the file in to fix.
      const fixed = '/images/' + u.split('images/').pop();
      out = out.split(u).join(fixed);
      console.warn(`  ! relative image mapped to ${fixed} (may be missing): ${u}`);
    }
  }
  return out;
}

function fm(obj) {
  const esc = (v) => `"${String(v).replace(/"/g, '\\"')}"`;
  const lines = ['---'];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) lines.push(`${k}: [${v.map(esc).join(', ')}]`);
    else if (typeof v === 'number' || typeof v === 'boolean') lines.push(`${k}: ${v}`);
    else lines.push(`${k}: ${esc(v)}`);
  }
  lines.push('---');
  return lines.join('\n');
}

// Detect "(Part N)" in a title → series metadata for nicer UI grouping.
function seriesInfo(title) {
  const m = title.match(/(.+?)\s*\(Part\s*(\d+)\)/i);
  if (!m) return {};
  return { series: m[1].trim(), seriesPart: Number(m[2]) };
}

async function main() {
  for (const d of [POSTS_DIR, PAGES_DIR, IMG_DIR]) if (!existsSync(d)) await mkdir(d, { recursive: true });

  console.log('Fetching posts…');
  const posts = await getJSON(`${API}/posts?per_page=100&_embed=wp:featuredmedia`);
  console.log(`  ${posts.length} posts`);

  for (const p of posts) {
    const title = stripHtml(p.title.rendered);
    const slug = p.slug;
    const permalink = new URL(p.link).pathname;
    let hero;
    const media = p._embedded?.['wp:featuredmedia']?.[0]?.source_url;
    if (media) hero = await downloadImage(media, slug);

    const htmlLocalized = await localizeImages(p.content.rendered, slug);
    let md = td.turndown(htmlLocalized).replace(/\n{3,}/g, '\n\n').trim();

    const front = fm({
      title,
      description: stripHtml(p.excerpt?.rendered || '').slice(0, 280),
      pubDate: p.date,
      updatedDate: p.modified !== p.date ? p.modified : undefined,
      permalink,
      heroImage: hero,
      ...seriesInfo(title),
    });
    await writeFile(path.join(POSTS_DIR, `${slug}.md`), `${front}\n\n${md}\n`);
    console.log(`✓ post  ${slug}.md`);
  }

  console.log('Fetching pages…');
  const pages = await getJSON(`${API}/pages?per_page=100`);
  for (const p of pages) {
    const title = stripHtml(p.title.rendered);
    const slug = p.slug;
    const htmlLocalized = await localizeImages(p.content.rendered, slug);
    const md = td.turndown(htmlLocalized).replace(/\n{3,}/g, '\n\n').trim();
    const front = fm({ title, description: '' });
    await writeFile(path.join(PAGES_DIR, `${slug}.md`), `${front}\n\n${md}\n`);
    console.log(`✓ page  ${slug}.md`);
  }

  console.log(`\nDone. ${imageMap.size} images processed.`);
}

main().catch((e) => { console.error(e); process.exit(1); });
