# hid-replay

HID replay is a utility to create virtual HID devices via the uhid kernel module.
Typically the input is a recording created by [hid-recorder](https://github.com/hidutils/hid-recorder).


This is a Rust reimplementation of hid-replay from
[hid-tools](https://gitlab.freedesktop.org/libevdev/hid-tools/).

`hid-replay` needs access to the `/dev/uhid` device and typically needs
to run as root.

# Installation

A pre-built binary is available for our
[releases](https://github.com/hidutils/hid-replay/releases). Simply download the
`hid-replay.zip`, unpack it and you are good to go:
```
$ unzip hid-replay.zip
$ chmod +x hid-replay
$ sudo ./hid-replay
```

## Installation with `cargo`

The easiest is to install with cargo as root:

```
$ sudo cargo install hid-replay
$ sudo hid-replay path/to/recording
```

Alternatively leave out the `sudo` which installs installs in `$CARGO_HOME`
(usually `$HOME/.cargo`) and run with `pkexec` instead.

```
$ cargo install hid-replay
$ pkexec hid-replay path/to/recording
```
`pkexec` will ask for your user's password.

Alternatively you can install hid-replay so you can access it via
sudo:

## Sudo-compatible Installation

### Install as user in $CARGO_HOME

This is the default `cargo` installation but requires that you add the
path manually when running hid-replay:

```
$ cargo install hid-replay
$ sudo $HOME/.cargo/bin/hid-replay path/to/recording
```

### Install as root in /usr/local

Install hid-replay in `/usr/local/` which is typically part of the
default `$PATH`.

```
$ sudo CARGO_INSTALL_ROOT=/usr/local cargo install hid-replay
$ sudo hid-replay path/to/recording
```

### Allow access to the device to non-root users

This is the least safe option as once read access is granted, any
process can create virtual HID devices. This allows for malicious
interference with your running session.

```
$ cargo install hid-replay
$ sudo chmod o+r /dev/uhid
$ hid-replay path/to/recording
```
It is recommended to remove these permissions once need for
replaying is over:

```
$ sudo chmod o-r /dev/uhid
```
