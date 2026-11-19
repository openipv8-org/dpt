module openipv8.org/dpt

go 1.23

require (
	golang.org/x/sys v0.29.0
	golang.org/x/term v0.28.0
	openipv8.org/concomm v0.0.0
)

// concomm sits beside this repository until it is published as a module.
replace openipv8.org/concomm => ../concomm
