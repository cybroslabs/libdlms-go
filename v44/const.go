package v44

const (
	maxcodeword = 1525 // it should be constant according to itu
	maxstring   = 255
)

const (
	state_empty = iota
	state_codeword
	state_stringext
	state_ordinal
)
