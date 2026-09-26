// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Render Mermaid diagrams in the colour scheme of the selected mdBook theme.
// mdBook 0.5 renders the theme buttons with the id "mdbook-theme-<name>", so
// the plain "ayu" and "light" ids of older mdBook versions no longer match.

(() => {
  const darkThemes = ["ayu", "navy", "coal"];
  const lightThemes = ["light", "rust"];

  const classList = document.documentElement.classList;
  const lastThemeWasLight = !darkThemes.some((name) =>
    classList.contains(name),
  );

  mermaid.initialize({
    startOnLoad: true,
    theme: lastThemeWasLight ? "default" : "dark",
  });

  // Mermaid has no API to re-theme a diagram in place, so reload the page
  // when the reader switches between a light theme and a dark theme.
  const reloadOnSwitch = (name, shouldReload) => {
    const button = document.getElementById(`mdbook-theme-${name}`);
    if (button) {
      button.addEventListener("click", () => {
        if (shouldReload()) {
          window.location.reload();
        }
      });
    }
  };

  for (const name of darkThemes) {
    reloadOnSwitch(name, () => lastThemeWasLight);
  }

  for (const name of lightThemes) {
    reloadOnSwitch(name, () => !lastThemeWasLight);
  }
})();
