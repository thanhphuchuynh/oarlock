package main

// Rendering.
//
// Columns rather than a grid: an operator pipes this into `grep` and `awk`, and a box
// drawing is one more thing for those to trip over.

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

type table struct {
	w    *tabwriter.Writer
	cols int
}

func newTable(headers ...string) *table {
	t := &table{
		w:    tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0),
		cols: len(headers),
	}
	fmt.Fprintln(t.w, strings.Join(headers, "\t"))
	return t
}

func (t *table) row(cells ...string) {
	for i, c := range cells {
		if c == "" {
			// A dash rather than a gap, so a column an operator is scanning stays a
			// column when a value is missing.
			cells[i] = "-"
		}
	}
	fmt.Fprintln(t.w, strings.Join(cells, "\t"))
}

func (t *table) print() { _ = t.w.Flush() }

// printPairs renders one record as label/value lines.
func printPairs(kv ...string) {
	for i := 0; i+1 < len(kv); i += 2 {
		v := kv[i+1]
		if v == "" {
			continue // an absent field is absent, not an empty line
		}
		fmt.Printf("  %-16s %s\n", kv[i], v)
	}
}
