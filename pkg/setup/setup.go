package setup

import (
	"embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

func RunSetup(embeddedFS embed.FS) error {
	fmt.Println("Starting DockerHunter setup...")

	// 1. Verify python3 exists
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("python3 is not installed or not in your PATH. Please install python3 first")
	}
	fmt.Printf("✓ Found python3 at %s\n", pythonPath)

	// 2. Initialize ~/.dockerhunter
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	baseDir := filepath.Join(home, ".dockerhunter")
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", baseDir, err)
	}
	fmt.Printf("✓ Initialized working directory: %s\n", baseDir)

	// 3. Extract default config files
	if err := extractEmbedded(embeddedFS, "config/config.yaml", filepath.Join(baseDir, "config.yaml")); err != nil {
		return fmt.Errorf("failed to extract config.yaml: %w", err)
	}

	rulesDest := filepath.Join(baseDir, "regex_rules.yaml")
	if err := extractEmbedded(embeddedFS, "config/regex_rules.yaml", rulesDest); err != nil {
		return fmt.Errorf("failed to extract regex_rules.yaml: %w", err)
	}
	fmt.Println("✓ Unpacked configuration and regex rules databases.")

	// 4. Extract validator directory recursively
	fmt.Println("Extracting Python validator files...")
	if err := extractDirRecursive(embeddedFS, "validator", baseDir); err != nil {
		return fmt.Errorf("failed to extract validator files: %w", err)
	}
	fmt.Println("✓ Python validator files extracted.")

	// 5. Create Python Virtual Environment
	venvDir := filepath.Join(baseDir, "venv")
	fmt.Println("Creating Python virtual environment (this may take a few seconds)...")
	cmd := exec.Command("python3", "-m", "venv", venvDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create virtual environment: %w", err)
	}
	fmt.Println("✓ Virtual environment created.")

	// 6. Install python dependencies
	pipPath := filepath.Join(venvDir, "bin", "pip")
	
	fmt.Println("Installing CPU-only PyTorch (this might take a minute)...")
	cmd = exec.Command(pipPath, "install", "torch", "--index-url", "https://download.pytorch.org/whl/cpu")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install PyTorch: %w", err)
	}

	fmt.Println("Installing remaining Python dependencies (fastapi, transformers, PyYAML, pydantic)...")
	reqPath := filepath.Join(baseDir, "validator", "requirements.txt")
	cmd = exec.Command(pipPath, "install", "-r", reqPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install dependencies from requirements.txt: %w", err)
	}
	fmt.Println("✓ Python requirements installed.")

	// 7. Pre-download Hugging Face Model if HF token is set or available
	fmt.Println("Pre-downloading HuggingFace model bigcode/starpii...")
	pyPath := filepath.Join(venvDir, "bin", "python")
	
	downloadScript := `
import os
from transformers import pipeline
token = os.environ.get("HUGGINGFACEHUB_API_TOKEN")
try:
    print("Caching Hugging Face pipeline...")
    pipeline("ner", model="bigcode/starpii", token=token if token else None)
    print("✓ Model successfully cached!")
except Exception as e:
    print(f"⚠️  Could not pre-cache model: {e}")
    print("Setup will complete, but model will download on the first scan.")
`

	cmd = exec.Command(pyPath, "-c", downloadScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	// Securely pass the HUGGINGFACEHUB_API_TOKEN in the environment
	cmd.Env = append(os.Environ(), "HUGGINGFACEHUB_API_TOKEN="+os.Getenv("HUGGINGFACEHUB_API_TOKEN"))
	_ = cmd.Run() // Let failure print warnings but proceed

	fmt.Println("\nSetup complete! You can now run:")
	fmt.Println("  dockerhunter scan <image>")
	return nil
}

func copyFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	return err
}

func extractEmbedded(fs embed.FS, src, dest string) error {
	// If file already exists, don't overwrite user's local config
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	srcFile, err := fs.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	return err
}

func extractDirRecursive(fs embed.FS, srcDir, destBase string) error {
	entries, err := fs.ReadDir(srcDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(srcDir, entry.Name())
		destPath := filepath.Join(destBase, srcPath)

		if entry.IsDir() {
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return err
			}
			if err := extractDirRecursive(fs, srcPath, destBase); err != nil {
				return err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return err
			}
			srcFile, err := fs.Open(srcPath)
			if err != nil {
				return err
			}
			destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				srcFile.Close()
				return err
			}
			_, copyErr := io.Copy(destFile, srcFile)
			srcFile.Close()
			destFile.Close()
			if copyErr != nil {
				return copyErr
			}
		}
	}
	return nil
}
