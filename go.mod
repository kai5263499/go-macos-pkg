module github.com/korylprince/go-macos-pkg

go 1.18

replace github.com/korylprince/goxar => ../goxar

require (
	github.com/korylprince/go-cpio-odc v0.9.4
	github.com/korylprince/goxar v0.0.0-20211111233330-e9f257bcdf25
	golang.org/x/crypto v0.8.0
)

require github.com/djherbis/times v1.5.0 // indirect
