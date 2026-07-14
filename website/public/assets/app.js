// Generated from catalog/packages/*.toml. DO NOT EDIT; regenerate with: node website/build.mjs
const normalize = (value) =>
  value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("en")
    .replace(/[^a-z0-9+.#-]+/g, " ")
    .trim();

const searchInput = document.querySelector("#package-search");
const categorySelect = document.querySelector("#category-filter");
const platformSelect = document.querySelector("#platform-filter");
const resultStatus = document.querySelector("#result-status");
const cards = [...document.querySelectorAll("[data-package-card]")];

function applyFilters() {
  if (!searchInput || !categorySelect || !platformSelect) return;
  const query = normalize(searchInput.value);
  const category = categorySelect.value;
  const platform = platformSelect.value;
  let visible = 0;
  for (const card of cards) {
    const matchesQuery = query === "" || normalize(card.dataset.search).includes(query);
    const matchesCategory = category === "" || card.dataset.categories.split(" ").includes(category);
    const matchesPlatform = platform === "" || card.dataset.platforms.split(" ").includes(platform);
    card.hidden = !(matchesQuery && matchesCategory && matchesPlatform);
    if (!card.hidden) visible += 1;
  }
  resultStatus.textContent = `${visible} package${visible === 1 ? "" : "s"}`;
  const url = new URL(window.location.href);
  query ? url.searchParams.set("q", searchInput.value.trim()) : url.searchParams.delete("q");
  category ? url.searchParams.set("category", category) : url.searchParams.delete("category");
  platform ? url.searchParams.set("platform", platform) : url.searchParams.delete("platform");
  history.replaceState(null, "", url);
}

if (searchInput && categorySelect && platformSelect) {
  const params = new URLSearchParams(window.location.search);
  searchInput.value = params.get("q") ?? "";
  categorySelect.value = params.get("category") ?? "";
  platformSelect.value = params.get("platform") ?? "";
  searchInput.addEventListener("input", applyFilters);
  categorySelect.addEventListener("change", applyFilters);
  platformSelect.addEventListener("change", applyFilters);
  applyFilters();
}

for (const button of document.querySelectorAll("[data-copy-command]")) {
  button.addEventListener("click", async () => {
    const command = button.dataset.copyCommand;
    try {
      await navigator.clipboard.writeText(command);
      button.textContent = "Copied";
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNode(button.previousElementSibling);
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = "Select and copy";
    }
    window.setTimeout(() => {
      button.textContent = "Copy";
    }, 1600);
  });
}
