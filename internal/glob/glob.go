// Package glob matches the wildcard language of IAM policy documents:
// '*' for any run of characters and '?' for exactly one. It is not a
// shell glob; '[', ']' and '\' are ordinary characters.
//
// The one subtlety is where '*' may roam. The IAM documentation states
// that a '*' which ends a colon-separated ARN segment, or ends the
// pattern, expands beyond the colon boundaries, while a '*' followed by
// anything else stays inside its segment. Action names carry a single
// ':' before the name, so for them the rule changes nothing.
package glob

import (
	"sort"
	"strconv"
	"strings"
)

// IsLiteral reports whether the pattern contains no wildcard.
func IsLiteral(p string) bool { return !strings.ContainsAny(p, "*?") }

// Match reports whether s is in the language of pattern. With fold set,
// matching ignores ASCII case, as IAM does for action names.
func Match(pattern, s string, fold bool) bool {
	if fold {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	return match(pattern, s)
}

// crosses reports whether the star at p[i] may match ':'.
func crosses(p string, i int) bool {
	return i+1 == len(p) || p[i+1] == ':'
}

func match(p, s string) bool {
	n, m := len(p), len(s)
	prev := make([]bool, m+1) // prev[j]: p[i+1:] matches s[j:]
	cur := make([]bool, m+1)
	prev[m] = true
	for i := n - 1; i >= 0; i-- {
		switch c := p[i]; c {
		case '*':
			free := crosses(p, i)
			cur[m] = prev[m]
			for j := m - 1; j >= 0; j-- {
				cur[j] = prev[j] || ((free || s[j] != ':') && cur[j+1])
			}
		case '?':
			cur[m] = false
			for j := m - 1; j >= 0; j-- {
				cur[j] = prev[j+1]
			}
		default:
			cur[m] = false
			for j := m - 1; j >= 0; j-- {
				cur[j] = s[j] == c && prev[j+1]
			}
		}
		prev, cur = cur, prev
	}
	return prev[0]
}

// Covers reports whether outer's language contains every string in
// inner's language: whether a grant on inner lies entirely within a
// grant on outer. It is exact, not heuristic, which is what lets the
// evaluator narrow a broad identity grant to a guardrail's resource
// without guessing.
//
// Both patterns are small automata. Inclusion holds when no string
// accepted by inner is rejected by outer, so the search walks inner's
// automaton one path at a time alongside the set of outer states that
// could be live, and fails the moment inner accepts while outer cannot.
func Covers(outer, inner string, fold bool) bool {
	if fold {
		outer, inner = strings.ToLower(outer), strings.ToLower(inner)
	}
	o, in := automaton(outer), automaton(inner)
	alphabet := alphabetOf(outer, inner)

	type state struct {
		ip int
		os string
	}
	sets := map[string][]int{}
	intern := func(set []int) string {
		k := encode(set)
		if _, ok := sets[k]; !ok {
			sets[k] = set
		}
		return k
	}

	visited := map[state]bool{}
	var stack []state
	start := intern(o.closure([]int{0}))
	for _, ip := range in.closure([]int{0}) {
		stack = append(stack, state{ip, start})
	}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[s] {
			continue
		}
		visited[s] = true
		oset := sets[s.os]
		if s.ip == len(inner) && !o.accepts(oset) {
			return false
		}
		for _, c := range alphabet {
			onext := intern(o.closure(o.step(oset, c)))
			for _, ip := range in.closure(in.step([]int{s.ip}, c)) {
				stack = append(stack, state{ip, onext})
			}
		}
	}
	return true
}

// automaton is a pattern read as a nondeterministic automaton whose
// states are positions in the pattern. A '*' loops on itself and moves
// on for free; everything else consumes exactly one character.
type automaton string

func (a automaton) accepts(set []int) bool {
	for _, k := range set {
		if k == len(a) {
			return true
		}
	}
	return false
}

// closure adds every position reachable without consuming a character.
func (a automaton) closure(set []int) []int {
	seen := map[int]bool{}
	var out []int
	var add func(k int)
	add = func(k int) {
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, k)
		if k < len(a) && a[k] == '*' {
			add(k + 1)
		}
	}
	for _, k := range set {
		add(k)
	}
	sort.Ints(out)
	return out
}

// step consumes c from every position in set. The byte 0 stands for any
// character that is not a literal of either pattern.
func (a automaton) step(set []int, c byte) []int {
	var out []int
	for _, k := range set {
		if k == len(a) {
			continue
		}
		switch a[k] {
		case '*':
			if c != ':' || crosses(string(a), k) {
				out = append(out, k)
			}
		case '?':
			out = append(out, k+1)
		default:
			if a[k] == c {
				out = append(out, k+1)
			}
		}
	}
	return out
}

// alphabetOf lists the characters that can tell the two patterns apart:
// every literal in either, ':' because segment-bound stars refuse it,
// and one stand-in for everything else.
func alphabetOf(patterns ...string) []byte {
	seen := map[byte]bool{':': true, 0: true}
	out := []byte{':', 0}
	for _, p := range patterns {
		for i := 0; i < len(p); i++ {
			c := p[i]
			if c == '*' || c == '?' || seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func encode(set []int) string {
	var b strings.Builder
	for _, k := range set {
		b.WriteString(strconv.Itoa(k))
		b.WriteByte(',')
	}
	return b.String()
}

// Overlaps reports whether some string lies in both languages: whether
// a rule on a could apply to anything a grant on b names. A rule whose
// resource neither covers nor overlaps a grant's resource is simply
// irrelevant to it, which is the common case and must not become a gap.
func Overlaps(a, b string, fold bool) bool {
	if fold {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	A, B := automaton(a), automaton(b)
	alphabet := alphabetOf(a, b)

	type state struct{ a, b string }
	sets := map[string][]int{}
	intern := func(set []int) string {
		k := encode(set)
		if _, ok := sets[k]; !ok {
			sets[k] = set
		}
		return k
	}

	visited := map[state]bool{}
	stack := []state{{intern(A.closure([]int{0})), intern(B.closure([]int{0}))}}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[s] {
			continue
		}
		visited[s] = true
		sa, sb := sets[s.a], sets[s.b]
		if len(sa) == 0 || len(sb) == 0 {
			continue
		}
		if A.accepts(sa) && B.accepts(sb) {
			return true
		}
		for _, c := range alphabet {
			stack = append(stack, state{
				intern(A.closure(A.step(sa, c))),
				intern(B.closure(B.step(sb, c))),
			})
		}
	}
	return false
}
