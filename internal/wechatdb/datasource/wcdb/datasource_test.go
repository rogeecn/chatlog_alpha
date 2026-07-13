package wcdb

import "testing"

func TestMessageQueryFetchLimitAvoidsLargeFloorWithoutPostFilter(t *testing.T) {
	tests := []struct {
		name          string
		limit         int
		offset        int
		hasPostFilter bool
		want          int
	}{
		{name: "small plain query", limit: 2, want: 20},
		{name: "offset included", limit: 10, offset: 10, want: 100},
		{name: "keyword or sender filter", limit: 2, hasPostFilter: true, want: 1000},
		{name: "unbounded query", limit: 0, want: 0},
		{name: "hard cap", limit: 20000, want: 50000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := messageQueryFetchLimit(tc.limit, tc.offset, tc.hasPostFilter); got != tc.want {
				t.Fatalf("messageQueryFetchLimit() = %d, want %d", got, tc.want)
			}
		})
	}
}
