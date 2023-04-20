package config

import (
	"fmt"
	"os"
	"strings"
)

type Quota string

func (q Quota) Format() (float64, float64, error) {
	if q == "" {
		return 0, 0, nil
	}
	var core, mem float64
	_, err := fmt.Sscanf(strings.ToUpper(string(q)), "%FC%FG", &core, &mem)
	if err != nil {
		return 0, 0, fmt.Errorf("parse quota %s failed, error: %w", string(q), err)
	}
	return core, mem, nil
}

func (q Quota) Verify() error {
	_, _, err := q.Format()
	return err
}

func (q Quota) UpdateServiceFile(path string) error {
	cpu, mem, err := q.Format()
	if err != nil {
		return err
	}
	if cpu == 0 && mem == 0 {
		return nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("open %s error: %w", path, err)
	}
	lines := strings.Split(string(bytes), "\n")
	newLines := make([]string, 0)
	for i := range lines {
		if cpu != 0 && strings.HasPrefix(lines[i], "CPUQuota=") {
			continue
		}
		if mem != 0 && strings.HasPrefix(lines[i], "MemoryMax=") {
			continue
		}
		if mem != 0 && strings.HasPrefix(lines[i], "MemoryLimit=") {
			continue
		}
		newLines = append(newLines, lines[i])
	}

	for i := range newLines {
		if newLines[i] == "[Service]" {
			quotaLines := make([]string, 0)
			if cpu != 0 {
				quotaLines = append(quotaLines, fmt.Sprintf("CPUQuota=%d%%", int(cpu*100)))
			}
			if mem != 0 {
				if mem >= 1 {
					quotaLines = append(quotaLines, fmt.Sprintf("MemoryMax=%dG", int(mem)))
					quotaLines = append(quotaLines, fmt.Sprintf("MemoryLimit=%dG", int(mem)))
				} else {
					quotaLines = append(quotaLines, fmt.Sprintf("MemoryMax=%dM", int(mem*1000)))
					quotaLines = append(quotaLines, fmt.Sprintf("MemoryLimit=%dM", int(mem*1000)))
				}
			}
			newLines = append(newLines[0:i+1], append(quotaLines, newLines[i+1:]...)...)
			break
		}
	}
	info, _ := os.Lstat(path)
	return os.WriteFile(path, []byte(strings.Join(newLines, "\n")), info.Mode())
}
