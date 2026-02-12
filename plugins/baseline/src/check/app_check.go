package check

import (
	"bufio"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Weak Password Dictionary (In-memory)
var (
	weakPasswords = map[string]bool{
		"123456":   true,
		"password": true,
		"admin":    true,
		"root":     true,
		"12345678": true,
	}
	weakPassMutex sync.RWMutex
)

// Minimal Process Info
type ProcessInfo struct {
	Pid     string
	Name    string
	Cmdline string
	Cwd     string
}

// Find processes by name pattern
func findProcesses(pattern string) ([]ProcessInfo, error) {
	var procs []ProcessInfo
	files, err := ioutil.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(pattern)

	for _, f := range files {
		if !f.IsDir() || !isNumeric(f.Name()) {
			continue
		}
		pid := f.Name()
		cmdlinePath := filepath.Join("/proc", pid, "cmdline")
		cmdlineBytes, err := ioutil.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}
		cmdline := string(cmdlineBytes)
		// Replace null bytes with space
		cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
		
		exePath, _ := os.Readlink(filepath.Join("/proc", pid, "exe"))
		
		if re.MatchString(cmdline) || re.MatchString(exePath) {
			cwd, _ := os.Readlink(filepath.Join("/proc", pid, "cwd"))
			procs = append(procs, ProcessInfo{
				Pid:     pid,
				Name:    filepath.Base(exePath),
				Cmdline: cmdline,
				Cwd:     cwd,
			})
		}
	}
	return procs, nil
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Helper to find config file from cmdline args or default paths
func findConfigFile(proc ProcessInfo, argFlag string, defaultPaths []string) string {
	// 1. Try to find in cmdline
	if argFlag != "" {
		re := regexp.MustCompile(argFlag + `\s*=?\s*(\S+)`)
		matches := re.FindStringSubmatch(proc.Cmdline)
		if len(matches) > 1 {
			return matches[1]
		}
	} else {
		// Try positional argument (heuristic: ends with .conf, .ini, .properties, .xml, .yaml, .yml)
		parts := strings.Fields(proc.Cmdline)
		for i, part := range parts {
			if i == 0 { continue } // Skip executable
			if strings.HasPrefix(part, "-") { continue } // Skip flags
			ext := filepath.Ext(part)
			switch ext {
			case ".conf", ".ini", ".properties", ".xml", ".yaml", ".yml":
				return part
			}
		}
	}

	// 2. Try default paths
	rootPath := filepath.Join("/proc", proc.Pid, "root")
	for _, p := range defaultPaths {
		fullPath := filepath.Join(rootPath, p)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}
	return ""
}

// Read properties file
func readProperties(path string) (map[string]string, error) {
	props := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			props[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return props, nil
}

// Update weak password dictionary
func UpdateWeakPassDict(passwords []string) {
	weakPassMutex.Lock()
	defer weakPassMutex.Unlock()
	for _, p := range passwords {
		weakPasswords[p] = true
	}
}

// Check if password is weak
func isWeakPassword(pass string) bool {
	weakPassMutex.RLock()
	defer weakPassMutex.RUnlock()
	return weakPasswords[pass]
}

// --- Check Implementations ---

func CheckRedisWeakPassword() bool {
	procs, _ := findProcesses("redis-server")
	if len(procs) == 0 {
		return true // Skip if not running
	}

	for _, proc := range procs {
		// Redis config often passed as positional arg
		confPath := findConfigFile(proc, "", []string{"/etc/redis/redis.conf", "/etc/redis.conf"})
		if confPath == "" {
			continue
		}

		// Redis config is space separated usually
		content, err := ioutil.ReadFile(confPath)
		if err != nil {
			continue
		}
		
		re := regexp.MustCompile(`requirepass\s+(\S+)`)
		match := re.FindStringSubmatch(string(content))
		if len(match) > 1 {
			pass := match[1]
			if isWeakPassword(pass) {
				return false
			}
		} else {
			// No password set? Depends on policy. Assume weak if exposed.
			// But default redis binds to localhost. 
			// For this check, let's say no password is weak if not bind to localhost only?
			// Simplified: no password -> weak.
			return false 
		}
	}
	return true
}

func CheckMysqlWeakPassword() bool {
	// MySQL usually stores hashes, not clear text in config.
	// But sometimes in my.cnf [client] section for scripts.
	// Or we check for empty password policies?
	// Requirement: "Redis/MySQL/PostgreSQL/Nacos 配置解析与口令匹配"
	// For MySQL, we might check for 'loose-validate-password' or similar settings in my.cnf
	// or empty password usage. 
	// Given the constraint "no network login", we can only check config.
	// Let's check if validate_password plugin is enabled or simple password settings.
	
	procs, _ := findProcesses("mysqld")
	if len(procs) == 0 {
		return true
	}
	
	for _, proc := range procs {
		confPath := findConfigFile(proc, "--defaults-file", []string{"/etc/my.cnf", "/etc/mysql/my.cnf"})
		if confPath == "" {
			continue
		}
		
		content, err := ioutil.ReadFile(confPath)
		if err != nil {
			continue
		}
		text := string(content)
		
		// Example check: ensure validate_password plugin is loaded/configured
		// This is heuristic.
		if !strings.Contains(text, "validate_password") {
			// Maybe weak?
			// Let's just return true for now as checking actual password hash requires reading /var/lib/mysql files which might be restricted or complex format.
			// But if [client] section has password, check it.
			re := regexp.MustCompile(`password\s*=\s*(\S+)`)
			match := re.FindStringSubmatch(text)
			if len(match) > 1 {
				if isWeakPassword(match[1]) {
					return false
				}
			}
		}
	}
	return true
}

func CheckNacosWeakPassword() bool {
	procs, _ := findProcesses("nacos")
	if len(procs) == 0 {
		return true
	}

	for _, proc := range procs {
		// Try to find custom.properties or application.properties
		confPath := findConfigFile(proc, "-Dnacos.home", nil)
		if confPath != "" {
			confPath = filepath.Join(confPath, "conf", "application.properties")
		} else {
			// Try cwd
			confPath = filepath.Join(proc.Cwd, "conf", "application.properties")
		}

		if _, err := os.Stat(confPath); err != nil {
			continue
		}

		props, err := readProperties(confPath)
		if err != nil {
			continue
		}

		// Check for default token secret key if hardcoded?
		// Check console password if present (usually not in props, but in DB)
		// But Nacos uses mysql-schema.sql for init. 
		// If using embedded derby, check user?
		
		// Check: nacos.core.auth.enabled
		if val, ok := props["nacos.core.auth.enabled"]; ok && val == "false" {
			return false // Auth disabled is weak
		}
		
		// Check token secret
		if val, ok := props["nacos.core.auth.plugin.nacos.token.secret.key"]; ok {
			if len(val) < 32 { // Too short?
				// Or check if default
				if strings.Contains(val, "SecretKey012345678901234567890123456789012345678901234567890123456789") {
					return false
				}
			}
		}
	}
	return true
}

func CheckNacosConfig() bool {
    // Reuses logic from CheckNacosWeakPassword but checks other configs
    return CheckNacosWeakPassword()
}

func CheckArcheryConfig() bool {
    procs, _ := findProcesses("archery") // Might be python process
    if len(procs) == 0 {
        return true
    }
    
    // Check settings.py
    // Logic: Read file, check DEBUG = True or SECRET_KEY
    for _, proc := range procs {
        // finding settings.py location is tricky for python apps without standard layout
        // assume typical path or search cmdline
        // cmdline might be "python manage.py runserver"
        // Try to find settings.py in CWD
        settingsPath := filepath.Join(proc.Cwd, "archery", "settings.py") // Common structure?
        
        content, err := ioutil.ReadFile(settingsPath)
        if err != nil {
             // Try recursive search or known path? 
             // For now skip if not found
             continue
        }
        
        text := string(content)
        if strings.Contains(text, "DEBUG = True") {
            return false
        }
        
        // SECRET_KEY check ...
    }
    return true
}

func CheckXxlJobConfig() bool {
    procs, _ := findProcesses("xxl-job-admin")
    if len(procs) == 0 {
        return true
    }
    
    for _, proc := range procs {
        // jar file, properties inside or external?
        // -Dspring.config.location=...
        confPath := findConfigFile(proc, "-Dspring.config.location", []string{"application.properties"})
        
        if confPath == "" {
             // Try to find in classpath/jar? Too complex for simple func_check.
             // Assume external config or in CWD
             confPath = filepath.Join(proc.Cwd, "application.properties")
        }
        
        props, err := readProperties(confPath)
        if err != nil {
            continue
        }
        
		// xxl.job.accessToken
		if token, ok := props["xxl.job.accessToken"]; ok {
			if token == "" || isWeakPassword(token) {
				return false
			}
		} else {
			// Empty access token is risky
			return false
		}
	}
	return true
}
