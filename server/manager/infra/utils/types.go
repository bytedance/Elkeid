package utils

func MustBeStringSlice(a []interface{}) []string {
	res := make([]string, 0, len(a))
	for _, v := range a {
		if s, ok := v.(string); ok {
			res = append(res, s)
		}
	}
	return res
}

func Ternary[T any](statement bool, a, b T) T {
	if statement {
		return a
	}
	return b
}
