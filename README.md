# gocryptfs Create Folder

Creates a gocryptfs folder based on a plain folder without relying on gocryptfs/FUSE.

## Install

```
pip install pycryptdome
```

## Usage

```
python3 gocryptfs-create-folder.py OUTPUTDIR INPUTDIR
```

## Acknowledgement

Based on the **great** work of `gocryptfs-inspect`, see
- <https://github.com/maxpat78/gocryptfs-inspect>
- <https://github.com/slackner/gocryptfs-inspect>

For other features such as file- or filename decryption, see those repos

The EME code is a port of
- <https://github.com/rfjakob/eme>
with a look at
- <https://github.com/alexey-lapin/eme-java>
