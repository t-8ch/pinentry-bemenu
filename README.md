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

## Configuration

pinentry-bemenu accespts most of the same configuration options as bemenu
itself.

You can pass them either in the environment variable `BEMENU_OPTS` or on the
commandline.

When passing them on the commandline you need to create a wrapper script which
passes the options because the `pinentry` setting in `gpg-agent.conf` does not
allow commandline arguments.

## Exit codes

```
| 0| Normal exit. communication via the assuan protocol                            |
|15| Could not initialize bemenu library. Users should try another pinentry program|
```

## Screenshot

![Screenshot of pinentry-bemenu](./screenshot.png?raw=true)
