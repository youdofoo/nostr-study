package main

import "testing"

func Test_bech32Decode(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "hetare09",
			s:    "npub1vk6c8wge9fzpp97w2d27gw6qkxyxdg8eurnefthefgqruvg5697q4r537z",
			want: "65b583b9192a441097ce5355e43b40b18866a0f9e0e794aef94a003e3114d17c",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bech32Decode(tt.s); got != tt.want {
				t.Errorf("bech32Decode() = %v, want %v", got, tt.want)
			}
		})
	}
}
