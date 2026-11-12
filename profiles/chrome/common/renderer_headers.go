package common

import (
	"strings"

	"github.com/enetx/http"
)

func rendererHeaderNames(headers http.Header) []string {
	type bucket struct {
		name string
		hash uint32
	}

	table := make([]bucket, 8)
	insert := func(table []bucket, entry bucket) {
		index := int(entry.hash) & (len(table) - 1)
		for step := 1; table[index].name != ""; step++ {
			index = (index + step) & (len(table) - 1)
		}
		table[index] = entry
	}

	count := 0
	for _, hint := range rendererFields {
		present := false
		for key := range headers {
			if strings.EqualFold(key, hint.name) {
				present = true
				break
			}
		}

		if !present {
			continue
		}

		insert(table, bucket{hint.name, hint.hash})

		count++
		if count*2 >= len(table) {
			old := table
			table = make([]bucket, len(old)*2)
			for _, entry := range old {
				if entry.name != "" {
					insert(table, entry)
				}
			}
		}
	}

	var names []string
	for _, entry := range table {
		if entry.name != "" {
			names = append(names, entry.name)
		}
	}

	return names
}
