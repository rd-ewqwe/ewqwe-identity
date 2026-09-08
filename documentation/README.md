# ewQwe Identity Documentation

This documentation is maintained using [mdBook](https://rust-lang.github.io/mdBook/index.html).

## Installation and Initialization

### mdBook Installation

To install mdBook, follow [these instructions](https://rust-lang.github.io/mdBook/guide/installation.html).

```shell
cargo install mdbook
```

From the project root folder, initialize the documentation for mdBook with

```shell
mdbook init documentation
```

### Install the Mermaid preprocessor

The Mermaid preprocessor is used to render Mermaid diagrams in the documentation. The project and instructions are available on [GitHub](https://github.com/badboy/mdbook-mermaid).

```shell
cargo install mdbook-mermaid
```

To add Mermaid support to an existing documentation, from the project root folder, run

```shell
mdbook-mermaid install documentation
```

Where `documentation` is the documentation folder.

## Editing the documentation

Edit the files in the `documentation/src/` folder.
Edit the `SUMMARY.md` file to change the book structure and add new chapters.

Then serve the documentation locally from the `documentation` folder with:

```shell
mdbook serve --open
```

## License

EUPL-1.2 — see [LICENSE](LICENSE) at the repository root.
