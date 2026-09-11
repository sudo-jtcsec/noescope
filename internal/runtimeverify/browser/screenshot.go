package browser

import (
	"fmt"
	"os"
	"path/filepath"
)

func writeScreenshot(path string, image []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create screenshot directory: %w", err)
	}
	if err := os.WriteFile(path, image, 0600); err != nil {
		return fmt.Errorf("write screenshot: %w", err)
	}
	return nil
}
