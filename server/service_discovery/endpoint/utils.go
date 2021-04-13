package endpoint

import (
	"math/rand"
	"sort"
	"time"
)

type Item struct {
	Score int
	Data  interface{}
}

type ItemList []Item

func (s ItemList) Len() int {
	return len(s)
}

func (s ItemList) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s ItemList) Less(i, j int) bool {
	return s[i].Score < s[j].Score
}

type FetchAlgorithm func(items ItemList, n int) []Item

func FetchMinN(items ItemList, n int) []Item {
	r := make([]Item, 0)
	if len(items) == 0 {
		return r
	}
	sort.Sort(items)
	for i, item := range items {
		if i >= n {
			break
		}
		r = append(r, item)
	}
	return r
}

func FetchMaxN(items ItemList, n int) []Item {
	r := make([]Item, 0)
	if len(items) == 0 {
		return r
	}
	sort.Sort(items)
	for i := len(items) - 1; i >= 0; i-- {
		if i >= n {
			break
		}
		r = append(r, items[i])
	}

	return r
}

func GenRandomNumbers(begin int, end int, count int) []int {
	nums := make([]int, 0)
	if end < begin || (end-begin) < count {
		return nums
	}
	qcMap := make(map[int]bool)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for len(nums) < count {
		num := int(r.Int31n(int32(end-begin))) + begin
		if _, ok := qcMap[num]; ok {
			continue
		} else {
			nums = append(nums, num)
			qcMap[num] = true
		}
	}

	return nums
}

func FetchRandomN(items ItemList, n int) []Item {
	r := make([]Item, 0)
	if len(items) <= n {
		for _, i := range items {
			r = append(r, i)
		}
		return r
	}
	nums := GenRandomNumbers(0, len(items), n)
	for _, i := range nums {
		r = append(r, items[i])
	}

	return r
}
