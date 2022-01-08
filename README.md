# pinentry-bemenu

[Pinentry](https://www.gnupg.org/related_software/pinentry/index.en.html)
implementation based on [bemenu](https://github.com/Cloudef/bemenu)

## Building

```
meson build
meson compile -C build
```

### Dependencies

- meson
- ninja
- libgpg-error-devel
- libassuan-devel
- bemenu-devel
- popt-devel

## Installing

```
meson install -C build
```

## Screenshot

![Screenshot of pinentry-bemenu](./screenshot.png?raw=true)
