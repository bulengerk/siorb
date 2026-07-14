import { readFile, readdir } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "public");

async function listFiles(directory, prefix = "") {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await listFiles(resolve(directory, entry.name), relative));
    else files.push(relative);
  }
  return files.sort();
}

const files = await listFiles(root);
const fileSet = new Set(files);
const htmlFiles = files.filter((file) => file.endsWith(".html"));
const packageFiles = files.filter((file) => /^packages\/[a-z0-9-]+\.html$/.test(file));
const errors = [];
const generatedNotice = "Generated from catalog/packages/*.toml. DO NOT EDIT; regenerate with: node website/build.mjs";

if (packageFiles.length < 100) errors.push(`expected at least 100 package pages, found ${packageFiles.length}`);

for (const file of htmlFiles) {
  const html = await readFile(resolve(root, file), "utf8");
  if (!html.includes(generatedNotice)) errors.push(`${file}: generated notice missing`);
  for (const marker of ['<html lang="en">', "<title>", '<main id="main-content">', 'class="skip-link"', 'aria-label="Primary navigation"']) {
    if (!html.includes(marker)) errors.push(`${file}: missing accessibility or metadata marker ${marker}`);
  }
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
  if (new Set(ids).size !== ids.length) errors.push(`${file}: duplicate HTML id`);
  for (const match of html.matchAll(/\shref="([^"]+)"/g)) {
    const href = match[1];
    if (/^(?:https?:|mailto:|#)/.test(href)) continue;
    const withoutSuffix = href.split(/[?#]/, 1)[0];
    const target = resolve(dirname(resolve(root, file)), withoutSuffix);
    let relative = target.slice(root.length + 1).replaceAll("\\", "/");
    if (relative === "") relative = "index.html";
    if (withoutSuffix.endsWith("/")) relative += "index.html";
    if (!extname(relative)) relative += "/index.html";
    if (!fileSet.has(relative)) errors.push(`${file}: broken internal link ${href} -> ${relative}`);
  }
}

const search = JSON.parse(await readFile(resolve(root, "search-index.json"), "utf8"));
if (search._generated !== generatedNotice) errors.push("search index generated notice is missing or stale");
if (search.packages.length !== packageFiles.length) errors.push("search index and package page count differ");
if (new Set(search.packages.map((pkg) => pkg.id)).size !== search.packages.length) errors.push("search index contains duplicate package IDs");
for (const pkg of search.packages) {
  if (!fileSet.has(`packages/${pkg.id}.html`)) errors.push(`search entry ${pkg.id} lacks a package page`);
  if (pkg.command !== `siorb install ${pkg.id}`) errors.push(`search entry ${pkg.id} has a non-canonical command`);
}

const manifest = JSON.parse(await readFile(resolve(root, "site.webmanifest"), "utf8"));
if (manifest._generated !== generatedNotice) errors.push("web manifest generated notice is missing or stale");
if (manifest.name !== "Siorb package catalog" || manifest.start_url !== "./") errors.push("web manifest identity is invalid");

const home = await readFile(resolve(root, "index.html"), "utf8");
if (!home.includes("Bundled development fixture · not a production signature claim")) errors.push("home page lacks the development-fixture trust qualification");
if (home.includes("✓") || home.includes("bundled trusted metadata")) errors.push("home page presents fixture trust as production-valid");
const security = await readFile(resolve(root, "security/index.html"), "utf8");
if (!security.includes("does not assert production signature validity")) errors.push("security page lacks the fixture trust disclaimer");

const sitemap = await readFile(resolve(root, "sitemap.xml"), "utf8");
const sitemapEntries = [...sitemap.matchAll(/<url><loc>/g)].length;
if (sitemapEntries !== htmlFiles.length - 1) errors.push(`sitemap has ${sitemapEntries} entries for ${htmlFiles.length - 1} indexable HTML files`);

if (errors.length) {
  console.error(errors.join("\n"));
  console.error(`website validation failed with ${errors.length} error(s)`);
  process.exitCode = 1;
} else {
  console.log(`website valid: ${htmlFiles.length} HTML files, ${packageFiles.length} package pages, ${sitemapEntries} sitemap entries`);
}
