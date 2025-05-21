package helpers

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

func ParseKeyValueFile(filePath string) (map[string][]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	result := make(map[string][]byte)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format in file %s, expected key=value: %s", filePath, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		result[key] = []byte(value)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return result, nil
}

func PrintSummary(total, success, skipped, failed int, outputDir string, exportMode string, duration time.Duration) {
	fmt.Printf("\nSealing complete in %v:\n", duration)
	fmt.Printf("- Total secrets found: %d\n", total)
	fmt.Printf("- Successfully processed: %d\n", success)
	fmt.Printf("- Skipped: %d\n", skipped)
	fmt.Printf("- Failed: %d\n", failed)
	if exportMode == "yaml" {
		fmt.Printf("- Output directory: %s\n", outputDir)
	}
}

func ParseAdditionalData(fromLiterals, fromFiles []string) (map[string][]byte, error) {
	additionalData := make(map[string][]byte)

	for _, literal := range fromLiterals {
		parts := strings.SplitN(literal, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format for --from-literal: %s", literal)
		}
		additionalData[parts[0]] = []byte(parts[1])
	}

	for _, filePath := range fromFiles {
		kv, err := ParseKeyValueFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("error parsing file %s: %v", filePath, err)
		}
		for k, v := range kv {
			additionalData[k] = v
		}
	}

	return additionalData, nil
}
