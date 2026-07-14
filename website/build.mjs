import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifests, parseManifest } from "../catalog/lib/manifest.mjs";

const websiteRoot = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(websiteRoot, "..");
const publicRoot = resolve(websiteRoot, "public");
const catalog = parseManifest(await readFile(resolve(repoRoot, "catalog/catalog.toml"), "utf8"), "catalog/catalog.toml");
const packages = (await loadManifests(resolve(repoRoot, "catalog/packages"))).map(({ manifest }) => manifest);
const mappings = packages.reduce((total, pkg) => total + pkg.sources.length, 0);
const categories = [...new Set(packages.flatMap((pkg) => pkg.categories))].sort();
const platforms = [...new Set(packages.flatMap((pkg) => pkg.sources.map((source) => source.platform)))].sort();
const generatedNotice = "Generated from catalog/packages/*.toml. DO NOT EDIT; regenerate with: node website/build.mjs";
const outputs = new Map();

function configuredHttpsUrl(name, fallback, trailingSlash) {
  const raw = process.env[name]?.trim() || fallback;
  let parsed;
  try { parsed = new URL(raw); } catch { throw new Error(`${name} must be an absolute HTTPS URL`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(`${name} must be an HTTPS URL without credentials, query, or fragment`);
  }
  const normalized = parsed.href.replace(/\/+$/, "");
  return trailingSlash ? `${normalized}/` : normalized;
}

const siteUrl = configuredHttpsUrl("SIORB_SITE_URL", "https://example.invalid/siorb/", true);
const repositoryUrl = process.env.SIORB_REPOSITORY_URL?.trim()
  ? configuredHttpsUrl("SIORB_REPOSITORY_URL", "", false)
  : null;

const escapeHtml = (value) => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#39;");
const titleCase = (value) => value.split("-").map((part) => part === "macos" ? "macOS" : part === "opensuse" ? "openSUSE" : part[0].toUpperCase() + part.slice(1)).join(" ");
const unique = (values) => [...new Set(values)].sort();
const rootFor = (path) => "../".repeat(path.split("/").length - 1);
const canonical = (path) => new URL(path === "index.html" ? "" : path.replace(/index\.html$/, ""), siteUrl).href;
const repositoryLink = (path, label) => repositoryUrl
  ? `<a href="${escapeHtml(`${repositoryUrl}${path}`)}">${escapeHtml(label)}</a>`
  : `<span>${escapeHtml(label)} (configured by the deploying repository)</span>`;

function layout(path, { title, description, body, scripts = true }) {
  const root = rootFor(path);
  const fullTitle = title === "Catalog" ? "Siorb package catalog" : `${title} · Siorb catalog`;
  return `<!doctype html>
<!-- ${generatedNotice} -->
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="${escapeHtml(description)}">
  <meta name="theme-color" content="#18124f">
  <meta property="og:type" content="website">
  <meta property="og:title" content="${escapeHtml(fullTitle)}">
  <meta property="og:description" content="${escapeHtml(description)}">
  <meta property="og:url" content="${canonical(path)}">
  <meta name="twitter:card" content="summary">
  <link rel="canonical" href="${canonical(path)}">
  <link rel="stylesheet" href="${root}assets/styles.css">
  <link rel="manifest" href="${root}site.webmanifest">
  <title>${escapeHtml(fullTitle)}</title>
</head>
<body>
  <a class="skip-link" href="#main-content">Skip to main content</a>
  <header class="site-header">
    <div class="header-inner">
      <a class="brand" href="${root}index.html" aria-label="Siorb catalog home">Siorb</a>
      <nav class="site-nav" aria-label="Primary navigation">
        <a href="${root}index.html">Packages</a>
        <a href="${root}categories/index.html">Categories</a>
        <a href="${root}platforms/index.html">Platforms</a>
        <a href="${root}install/index.html">Install</a>
        <a href="${root}contribute/index.html">Contribute</a>
        <a href="${root}security/index.html">Security</a>
      </nav>
    </div>
  </header>
  <main id="main-content">${body}</main>
  <footer class="site-footer">
    <div class="footer-inner">
      <p>Catalog ${escapeHtml(catalog.version)} · bundled development fixture; CLI authentication is authoritative</p>
      <p>${repositoryLink("", "Source and releases")} · No runtime backend</p>
    </div>
  </footer>
  ${scripts ? `<script src="${root}assets/app.js" defer></script>` : ""}
</body>
</html>
`;
}

function badges(values) {
  return `<ul class="badge-list">${values.map((value) => `<li class="badge">${escapeHtml(titleCase(value))}</li>`).join("")}</ul>`;
}

function packageCard(pkg, heading = "h2") {
  const packagePlatforms = unique(pkg.sources.map((source) => source.platform));
  const search = [pkg.id, pkg.name, pkg.description, ...pkg.aliases, ...pkg.search_terms, ...pkg.categories].join(" ");
  return `<article class="card" data-package-card data-search="${escapeHtml(search)}" data-categories="${escapeHtml(pkg.categories.join(" "))}" data-platforms="${escapeHtml(packagePlatforms.join(" "))}">
    <${heading}><a href="${heading === "h2" ? "packages/" : "../packages/"}${pkg.id}.html">${escapeHtml(pkg.name)}</a></${heading}>
    <p><code>${escapeHtml(pkg.id)}</code></p>
    <p>${escapeHtml(pkg.description)}</p>
    ${badges(packagePlatforms)}
  </article>`;
}

const homeBody = `
  <section class="hero" aria-labelledby="catalog-title">
    <p class="eyebrow">Offline-first package discovery</p>
    <h1 id="catalog-title">One intent. Native installs.</h1>
    <p class="lede">Search logical software names and inspect the exact native mappings Siorb can resolve on Windows, macOS, and Linux.</p>
    <div class="stats" aria-label="Catalog status">
      <span class="stat"><strong>${packages.length}</strong> packages</span>
      <span class="stat"><strong>${mappings}</strong> reviewed mappings</span>
      <span class="stat">Bundled development fixture · not a production signature claim</span>
    </div>
  </section>
  <section aria-labelledby="browse-title">
    <h2 id="browse-title">Browse packages</h2>
    <div class="search-panel">
      <div class="field">
        <label for="package-search">Search by name, alias, or capability</label>
        <input id="package-search" type="search" autocomplete="off" placeholder="Try firefox, editor, or kubernetes">
      </div>
      <div class="field">
        <label for="category-filter">Category</label>
        <select id="category-filter"><option value="">All categories</option>${categories.map((value) => `<option value="${value}">${escapeHtml(titleCase(value))}</option>`).join("")}</select>
      </div>
      <div class="field">
        <label for="platform-filter">Platform</label>
        <select id="platform-filter"><option value="">All platforms</option>${platforms.map((value) => `<option value="${value}">${escapeHtml(titleCase(value))}</option>`).join("")}</select>
      </div>
      <p id="result-status" class="result-status" role="status" aria-live="polite">${packages.length} packages</p>
    </div>
    <div class="card-grid">${packages.map((pkg) => packageCard(pkg)).join("\n")}</div>
  </section>`;
outputs.set("index.html", layout("index.html", { title: "Catalog", description: "Browse the bundled Siorb semantic catalog fixture with client-side search and exact native backend mappings.", body: homeBody }));

for (const pkg of packages) {
  const packagePlatforms = unique(pkg.sources.map((source) => source.platform));
  const backends = unique(pkg.sources.map((source) => source.backend));
  const aliases = pkg.aliases.length ? pkg.aliases.map((alias) => `<code>${escapeHtml(alias)}</code>`).join(", ") : "None";
  const command = `siorb install ${pkg.id}`;
  const body = `
    <p class="eyebrow">${escapeHtml(titleCase(pkg.categories[0]))}</p>
    <h1>${escapeHtml(pkg.name)}</h1>
    <p class="lede">${escapeHtml(pkg.description)}</p>
    <div class="command-box"><code>${escapeHtml(command)}</code><button type="button" data-copy-command="${escapeHtml(command)}" aria-label="Copy install command for ${escapeHtml(pkg.name)}">Copy</button></div>
    <div class="detail-grid">
      <section aria-labelledby="sources-title">
        <h2 id="sources-title">Reviewed sources</h2>
        <div class="table-scroll"><table class="source-table">
          <thead><tr><th>Platform</th><th>Backend</th><th>Exact package ID</th><th>Channel</th><th>Trust and evidence</th></tr></thead>
          <tbody>${pkg.sources.map((source) => `<tr><td>${escapeHtml(titleCase(source.platform))}</td><td>${escapeHtml(source.backend)}</td><td><code>${escapeHtml(source.package_id)}</code></td><td>${escapeHtml(source.channel)}</td><td>${escapeHtml(source.trust)} · <a href="${escapeHtml(source.evidence)}" rel="external nofollow">review source</a></td></tr>`).join("")}</tbody>
        </table></div>
      </section>
      <aside class="panel" aria-labelledby="metadata-title">
        <h2 id="metadata-title">Package metadata</h2>
        <dl class="definition-list">
          <dt>Canonical ID</dt><dd><code>${escapeHtml(pkg.id)}</code></dd>
          <dt>Aliases</dt><dd>${aliases}</dd>
          <dt>License</dt><dd>${escapeHtml(pkg.license)}</dd>
          <dt>Channels</dt><dd>${escapeHtml(pkg.channels.join(", "))}</dd>
          <dt>Platforms</dt><dd>${escapeHtml(packagePlatforms.map(titleCase).join(", "))}</dd>
          <dt>Backends</dt><dd>${escapeHtml(backends.join(", "))}</dd>
          <dt>Verification</dt><dd>${escapeHtml(pkg.verification)}</dd>
          <dt>Reviewed</dt><dd><time datetime="${escapeHtml(pkg.reviewed_at)}">${escapeHtml(pkg.reviewed_at)}</time></dd>
          <dt>Upstream</dt><dd><a href="${escapeHtml(pkg.homepage)}" rel="external">${escapeHtml(pkg.homepage)}</a></dd>
        </dl>
      </aside>
    </div>`;
  outputs.set(`packages/${pkg.id}.html`, layout(`packages/${pkg.id}.html`, { title: pkg.name, description: pkg.description, body }));
}

function browseIndex(kind, values) {
  const singular = kind.slice(0, -1);
  const cards = values.map((value) => {
    const matching = packages.filter((pkg) => kind === "categories" ? pkg.categories.includes(value) : pkg.sources.some((source) => source.platform === value));
    return `<article class="card"><h2><a href="${value}.html">${escapeHtml(titleCase(value))}</a></h2><p>${matching.length} package${matching.length === 1 ? "" : "s"}</p></article>`;
  }).join("");
  return layout(`${kind}/index.html`, {
    title: titleCase(kind),
    description: `Browse Siorb packages by ${singular}.`,
    body: `<p class="eyebrow">Catalog facets</p><h1>${escapeHtml(titleCase(kind))}</h1><p class="lede">Browse reviewed logical packages by ${escapeHtml(singular)}.</p><div class="card-grid">${cards}</div>`,
  });
}
outputs.set("categories/index.html", browseIndex("categories", categories));
outputs.set("platforms/index.html", browseIndex("platforms", platforms));

for (const [kind, values] of [["categories", categories], ["platforms", platforms]]) {
  for (const value of values) {
    const matching = packages.filter((pkg) => kind === "categories" ? pkg.categories.includes(value) : pkg.sources.some((source) => source.platform === value));
    const label = titleCase(value);
    const body = `<p class="eyebrow">${escapeHtml(titleCase(kind.slice(0, -1)))}</p><h1>${escapeHtml(label)}</h1><p class="lede">${matching.length} reviewed package${matching.length === 1 ? "" : "s"} available for ${escapeHtml(label)}.</p><div class="card-grid">${matching.map((pkg) => packageCard(pkg, "h3")).join("")}</div>`;
    outputs.set(`${kind}/${value}.html`, layout(`${kind}/${value}.html`, { title: label, description: `Browse ${label} packages in the Siorb catalog.`, body }));
  }
}

outputs.set("install/index.html", layout("install/index.html", {
  title: "Install Siorb",
  description: "Install Siorb and begin with an auditable dry-run plan.",
  body: `<p class="eyebrow">Get started</p><h1>Install Siorb</h1><p class="lede">Download a verified release for your platform, verify its checksum and provenance, then inspect a plan before changing the machine.</p><section class="panel"><h2>First commands</h2><div class="command-box"><code>siorb --dry-run install firefox</code><button type="button" data-copy-command="siorb --dry-run install firefox">Copy</button></div><p>Use <code>siorb catalog status</code> to inspect catalog provenance and the CLI's authenticated metadata state.</p><p>${repositoryLink("/releases", "Download release artifacts and checksums")}</p></section>`,
}));

outputs.set("contribute/index.html", layout("contribute/index.html", {
  title: "Contribute mappings",
  description: "Review and contribute exact package mappings to the Siorb catalog.",
  body: `<p class="eyebrow">Catalog governance</p><h1>Contribute a mapping</h1><p class="lede">Every package is a human-reviewable TOML manifest. Contributions must preserve exact IDs, provenance, trust metadata, architecture selectors, and HTTPS evidence.</p><section class="panel"><h2>Review sequence</h2><ol><li>Edit one file under <code>catalog/packages/</code>.</li><li>Verify each exact ID in its native backend repository.</li><li>Update the evidence link and review date.</li><li>Run <code>node catalog/validate.mjs</code>, catalog generation, and the website stale check.</li></ol><p>${repositoryLink("/blob/main/CONTRIBUTING.md", "Read the complete contribution guide")}</p></section>`,
}));

outputs.set("security/index.html", layout("security/index.html", {
  title: "Security",
  description: "Report Siorb security issues and understand catalog trust metadata.",
  body: `<p class="eyebrow">Coordinated disclosure</p><h1>Security reporting</h1><p class="lede">Do not publish exploitable catalog, signature, resolver, or installer vulnerabilities in a public issue.</p><section class="panel"><h2>Report privately</h2><p>Follow the private contact and encryption instructions in the repository security policy. Include the affected catalog version, package ID, source ID, and a minimal reproduction without secrets.</p><p>${repositoryLink("/security/policy", "Open the security policy")}</p><h2>Catalog trust</h2><p>This static site is generated from the bundled development catalog fixture and does not assert production signature validity. The CLI independently verifies trusted-root, targets, snapshot, timestamp, version, expiry, threshold, and hash metadata before using an update.</p></section>`,
}));

outputs.set("404.html", layout("404.html", { title: "Page not found", description: "The requested Siorb catalog page was not found.", body: `<h1>Page not found</h1><p class="lede">The catalog page you requested does not exist.</p><p><a href="index.html">Return to package search</a></p>` }));

const searchIndex = packages.map((pkg) => ({
  id: pkg.id,
  name: pkg.name,
  description: pkg.description,
  aliases: pkg.aliases,
  categories: pkg.categories,
  platforms: unique(pkg.sources.map((source) => source.platform)),
  backends: unique(pkg.sources.map((source) => source.backend)),
  command: `siorb install ${pkg.id}`,
}));
outputs.set("search-index.json", `${JSON.stringify({ _generated: generatedNotice, schema_version: "1", packages: searchIndex })}\n`);
outputs.set("site.webmanifest", `${JSON.stringify({ _generated: generatedNotice, name: "Siorb package catalog", short_name: "Siorb", start_url: "./", display: "standalone", background_color: "#f7f8fc", theme_color: "#18124f" }, null, 2)}\n`);
outputs.set("robots.txt", `# ${generatedNotice}\nUser-agent: *\nAllow: /\nSitemap: ${siteUrl}sitemap.xml\n`);

const sitemapPaths = [...outputs.keys()].filter((path) => path.endsWith(".html") && path !== "404.html").sort();
outputs.set("sitemap.xml", `<?xml version="1.0" encoding="UTF-8"?>
<!-- ${generatedNotice} -->
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${sitemapPaths.map((path) => `  <url><loc>${escapeHtml(canonical(path))}</loc><lastmod>${catalog.reviewed_at}</lastmod></url>`).join("\n")}
</urlset>
`);

const appSource = await readFile(resolve(websiteRoot, "src/app.js"), "utf8");
const styleSource = await readFile(resolve(websiteRoot, "src/styles.css"), "utf8");
outputs.set("assets/app.js", `// ${generatedNotice}\n${appSource}`);
outputs.set("assets/styles.css", `/* ${generatedNotice} */\n${styleSource}`);

async function listFiles(root, prefix = "") {
  let names;
  try { names = await readdir(root, { withFileTypes: true }); } catch { return []; }
  const files = [];
  for (const name of names) {
    const path = prefix ? `${prefix}/${name.name}` : name.name;
    if (name.isDirectory()) files.push(...await listFiles(resolve(root, name.name), path));
    else files.push(path);
  }
  return files.sort();
}

if (process.argv.includes("--check")) {
  const problems = [];
  const actualFiles = await listFiles(publicRoot);
  for (const file of actualFiles) if (!outputs.has(file)) problems.push(`unexpected generated file: ${file}`);
  for (const [path, expected] of outputs) {
    let actual = "";
    try { actual = await readFile(resolve(publicRoot, path), "utf8"); } catch { problems.push(`missing generated file: ${path}`); continue; }
    if (actual !== expected) problems.push(`stale generated file: ${path}`);
  }
  if (problems.length) {
    console.error(problems.join("\n"));
    process.exitCode = 1;
  } else {
    console.log(`website current: ${outputs.size} files, ${packages.length} package pages`);
  }
} else {
  const actualFiles = await listFiles(publicRoot);
  for (const file of actualFiles) if (!outputs.has(file)) await rm(resolve(publicRoot, file));
  for (const [path, contents] of outputs) {
    const target = resolve(publicRoot, path);
    await mkdir(dirname(target), { recursive: true });
    const temporary = `${target}.tmp`;
    await writeFile(temporary, contents);
    await rename(temporary, target);
  }
  console.log(`generated website: ${outputs.size} files, ${packages.length} package pages`);
}
