# jrnlc - Command line based Journal

[![Language grade: C](https://img.shields.io/lgtm/grade/cpp/g/thexhr/jrnlc.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/thexhr/jrnlc/context:cpp)

jrnlc is a opinionated command line application to take notes likes a journal similar to [jrnl](https://jrnl.sh).  You can take notes by entering them on the command line or providing them from a file to jrnlc's standard input.  It supports full encryption of the journal, so that your notes remain secret.

## Usage

A more detailed description of jrnlc and its usage patters are shown in the [man page](https://xosc.org/jrnlc.html).

Create a new journal entry on the command line.  End it with Ctrl+d on a blank line.
```
$ jrnlc
[One title line, one blank line, then the body. End with ^D on a blank line]
test  title line

and here's the content
```

Show the last two journal entries:

```
$ jrnlc -n 2
[2021-12-11 15:09] Vel ut dolorem earum ratione.

Id dolorem ducimus quis consectetur corrupti vitae.
Modi corrupti incidunt repellat magni et nihil.
Ea similique qui commodi possimus est.


[2021-12-11 15:32] test  title line

and here's the content
```
Create a new journal entry from a file.  This way you can create your entry in your text editor of choice and simply import it into jrnlc.
```
$ cat sample_entry.txt
Vel ut dolorem earum ratione.

Id dolorem ducimus quis consectetur corrupti vitae.
Modi corrupti incidunt repellat magni et nihil.
Ea similique qui commodi possimus est.

$ jrnlc < sample_entry.txt
[One title line, one blank line, then the body. End with ^D on a blank line]
$
```

Encrypt the journal using a password.  Choose a good and strong password and remember it well (or use a password manager).
```
$ jrnlc -e
Encrypting journal...
Enter Password:
Enter Password again:
```

## Installation

jrnlc is written in C and known to work on the operating systems listed in the table below.  To compile it you need the following things:

* A recent C compiler (tested with both clang >= 11 and GCC >= 8)
* make (tested with both BSD and GNU make)
* [libsodium](https://doc.libsodium.org/) (tested with 1.0.18)
* [The JSON-C library](https://github.com/json-c/json-c) >= Version 13

### Dependencies

Install the dependencies as follows:

| Operating System | Commands and Notes |
| --- | --- |
| Arch Linux | `pacman -Syu gcc make json-c libsodium` |
| Debian Linux| `apt install libsodium-dev libjson-c-dev` |
| DragonFly BSD | `pkg install libsodium json-c` |
| Fedora Linux | `dnf install libsodium-devel json-c-devel` |
| FreeBSD | `pkg install libsodium json-c` |
| NetBSD | `pkgin install pkg-config libsodium json-c` |
| OpenBSD | `pkg_add libsodium json-c` |
| Ubuntu Linux| `apt install libsodium-dev libjson-c-dev` |
| Void Linux| `xbps-install gcc make libsodium-devel json-c-devel` |
| Windows | There is not native version, just use WSL |

If your operating system does not have `pkg-config` installed by default, you have to install it as well.

### Compilation and Installation

By default, the `Makefile` uses `pkg-config` to look for external includes and libraries.  If your distribution uses special path, you have to modify the Makefile accordingly.

Compile and install with the following commands:

```
$ make
# make install
```

### Important Notes regarding Encryption

By default, jrnlc stores your journal as plain text JSON file in either `$HOME/.jrnlc` or `$XGD_HOME/.jrnlc`.  Using the `-e` option, jrnlc will encrypt your journal.  All needed cryptographic material is stored in `key.json` in the above mentioned directory.  If you loose or modify this file you'll never be able to decrypt your journal again!  If you no longer want your journal to be encrypted, you can decrypt it and save it as plain text with the `-d` option.

Using the `-B` option, jrnlc will print an unencrypted JSON copy of your journal to `stderr`. Do this regularly and use other means (GPG, openssl) to protect the backup.

#### How secure is my encrypted Journal?

jrnlc encrypts your journal using _libsodium_ and the [XSalsa20](https://en.wikipedia.org/wiki/Salsa20) cipher with a random _nonce_.  The cipher uses a completely random symmetric key generated with _libsodium's_ `crypto_secretbox_keygen()` which itself takes care that enough good entropy is available.  This key is then encrypted using your password, so be sure to take a pick a strong one.  The weaker your password is, the faster an attacker could brute force it.

## FAQ

**There is already [jrnl](https://jrnl.sh), why should I use jrnlc?** I myself used jrnl for the last years and it's a great piece of software.  I just grew tired of fiddling around with Python and dependency upgrades over time, so I wrote jrnlc.  Further, jrnl has a lot of features I don't need.

**OK, how can I switch from jrnl to jrnlc?** Just export your journal with `jrnl --format json` and copy it to the location of your `journal.json`. jrnlc will automatically import the file on the next start.

**I forgot my password/messed up with the key.json file.  Can you decrypt my journal for me?** Sorry, no.  That's how cryptography works.  If you don't have a plain text backup around, your data is lost forever.

## License

jrnl is written by Matthias Schmidt and is licensed under the ISC license.  It includes some code from OpenBSD, the license and authors can be seen in the source code files.
