package v44

type v44node struct {
	pos    int32
	side   int16 // this side should be common array of sorted things, but in this scale, it will be maybe ok, but later refactor that, move array to upper level
	down   int16
	length int16
}
