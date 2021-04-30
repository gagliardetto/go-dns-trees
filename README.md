## go-dns-trees

DNS trust trees graph generator, written in Go. Inspired by https://github.com/mandatoryprogrammer/TrustTrees

### Install

You need to have GraphViz's dot installed on your machine, and available as `dot`.

See https://graphviz.org/download for more info.

### Example usage

```bash
go build -o dns-trees
./dns-trees example.com
```
