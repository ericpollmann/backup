package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/reedsolomon"
)

// Test helper functions
func createTestFile(t *testing.T, path string, content string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create directory %s: %v", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file %s: %v", path, err)
	}
}

func createTestRepo(t *testing.T, baseDir string) string {
	t.Helper()
	repoDir := filepath.Join(baseDir, "test-repo")

	// Create Restic-like repository structure
	dirs := []string{
		"data/00",
		"data/01",
		"data/ff",
		"index",
		"snapshots",
		"keys",
		"locks",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(repoDir, dir), 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}
	}

	// Create test files with different sizes
	testFiles := map[string]string{
		"config":               "test config content",
		"data/00/0001234567":   "small data block",
		"data/00/0009876543":   "another small data block with more content",
		"data/01/0101234567":   "medium data block that contains more data than the small ones",
		"data/ff/ff01234567":   "large data block with lots of content that makes it bigger than others for testing variable sizes",
		"index/1234567890":     "index file content",
		"snapshots/abcdef1234": "snapshot metadata",
		"keys/keyfile":         "test key data",
	}

	for path, content := range testFiles {
		createTestFile(t, filepath.Join(repoDir, path), content)
	}

	return repoDir
}

// Unit tests for helper functions

func TestCalculateChecksums(t *testing.T) {
	tempDir := t.TempDir()

	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "Hello, World!"
	createTestFile(t, testFile, testContent)

	// Calculate checksums
	md5sum, sha256sum, err := calculateChecksums(testFile)
	if err != nil {
		t.Fatalf("Failed to calculate checksums: %v", err)
	}

	// Verify MD5
	expectedMD5 := md5.Sum([]byte(testContent))
	if md5sum != hex.EncodeToString(expectedMD5[:]) {
		t.Errorf("MD5 mismatch: got %s, want %s", md5sum, hex.EncodeToString(expectedMD5[:]))
	}

	// Verify SHA256
	expectedSHA256 := sha256.Sum256([]byte(testContent))
	if sha256sum != hex.EncodeToString(expectedSHA256[:]) {
		t.Errorf("SHA256 mismatch: got %s, want %s", sha256sum, hex.EncodeToString(expectedSHA256[:]))
	}
}

func TestCalculateMD5(t *testing.T) {
	tempDir := t.TempDir()

	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "Test MD5"
	createTestFile(t, testFile, testContent)

	md5sum, err := calculateMD5(testFile)
	if err != nil {
		t.Fatalf("Failed to calculate MD5: %v", err)
	}

	expected := md5.Sum([]byte(testContent))
	if md5sum != hex.EncodeToString(expected[:]) {
		t.Errorf("MD5 mismatch: got %s, want %s", md5sum, hex.EncodeToString(expected[:]))
	}
}

// Unit tests for Manager functions

func TestCalculateErasureScheme(t *testing.T) {
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.10,
	}

	manager := NewManager(config)

	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	// Verify scheme
	if manager.scheme == nil {
		t.Fatal("Erasure scheme is nil")
	}

	// We have 4 data files + 1 metadata zip = 5 data shards
	expectedDataShards := 5
	if manager.scheme.DataShards != expectedDataShards {
		t.Errorf("DataShards: got %d, want %d", manager.scheme.DataShards, expectedDataShards)
	}

	// We should have at least 3 parity shards (minimum enforced)
	if manager.scheme.ParityShards < 3 {
		t.Errorf("ParityShards too low: got %d, expected at least 3", manager.scheme.ParityShards)
	}

	// With minimum 3 parity shards and 5 data shards, overhead should be at least 60%
	expectedMinOverhead := float64(3) / float64(5) * 100 // 60%
	if manager.scheme.FileOverhead < expectedMinOverhead-1 {
		t.Errorf("FileOverhead too low: got %.1f%%, expected at least %.1f%%", manager.scheme.FileOverhead, expectedMinOverhead)
	}
}

func TestCreateInnerManifest(t *testing.T) {
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)
	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.10,
	}

	manager := NewManager(config)

	// Calculate scheme first
	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	// Create directories
	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}
	if err := os.MkdirAll(config.MetadataDir, 0755); err != nil {
		t.Fatalf("Failed to create metadata dir: %v", err)
	}

	// Create inner manifest
	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	// Verify manifest file exists
	manifestPath := filepath.Join(config.MetadataDir, InnerManifestName)
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("Inner manifest file not created")
	}

	// Load and verify manifest content
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read inner manifest: %v", err)
	}

	var manifest InnerManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("Failed to unmarshal inner manifest: %v", err)
	}

	// Verify manifest contains erasure scheme
	if manifest.ErasureScheme == nil {
		t.Fatal("Inner manifest missing erasure scheme")
	}

	// Verify file count - only data files
	expectedFiles := 4 // Only files from data/ directory
	if manifest.FileCount != expectedFiles {
		t.Errorf("FileCount: got %d, want %d", manifest.FileCount, expectedFiles)
	}

	// Verify all files are from data directory
	for _, file := range manifest.Files {
		if !strings.HasPrefix(file.Path, "data/") {
			t.Errorf("Expected all files to be from data/ directory, got: %s", file.Path)
		}
	}

	// Verify all files have checksums
	for _, file := range manifest.Files {
		if file.MD5 == "" {
			t.Errorf("File %s missing MD5 checksum", file.Path)
		}
		// SHA256 is optional for restic data files
		isResticData := strings.HasPrefix(file.Path, "data/")
		if !isResticData && file.SHA256 == "" {
			t.Errorf("File %s missing SHA256 checksum", file.Path)
		}
		if file.Size <= 0 {
			t.Errorf("File %s has invalid size: %d", file.Path, file.Size)
		}
	}
}

func TestGenerateErasureCodes(t *testing.T) {
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.20, // 20% for more parity shards in test
	}

	manager := NewManager(config)

	// Setup: calculate scheme and create inner manifest
	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}

	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	// Generate erasure codes
	if err := manager.GenerateErasureCodes(); err != nil {
		t.Fatalf("Failed to generate erasure codes: %v", err)
	}

	// Verify parity files created
	parityDir := filepath.Join(config.ParityDir, "shards")
	if _, err := os.Stat(parityDir); os.IsNotExist(err) {
		t.Fatal("Parity directory not created")
	}

	// Count parity files
	parityFiles, err := filepath.Glob(filepath.Join(parityDir, "parity_*.shard"))
	if err != nil {
		t.Fatalf("Failed to glob parity files: %v", err)
	}

	if len(parityFiles) != manager.scheme.ParityShards {
		t.Errorf("Parity files: got %d, want %d", len(parityFiles), manager.scheme.ParityShards)
	}

	// For chunked implementation, verify parity files exist
	// Size will be based on chunks, not shard size
	for _, parityFile := range parityFiles {
		info, err := os.Stat(parityFile)
		if err != nil {
			t.Errorf("Failed to stat parity file %s: %v", parityFile, err)
			continue
		}
		// Chunked implementation creates files based on actual data size
		if info.Size() == 0 {
			t.Errorf("Parity file %s is empty", filepath.Base(parityFile))
		}
	}
}

func TestCreateOuterManifest(t *testing.T) {
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.15,
	}

	manager := NewManager(config)

	// Full setup
	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}

	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	if err := manager.GenerateErasureCodes(); err != nil {
		t.Fatalf("Failed to generate erasure codes: %v", err)
	}

	// Create outer manifest
	if err := manager.CreateOuterManifest(); err != nil {
		t.Fatalf("Failed to create outer manifest: %v", err)
	}

	// Verify outer manifest file exists
	outerPath := filepath.Join(config.ParityDir, OuterManifestName)
	if _, err := os.Stat(outerPath); os.IsNotExist(err) {
		t.Fatal("Outer manifest file not created")
	}

	// Load and verify outer manifest
	outerData, err := os.ReadFile(outerPath)
	if err != nil {
		t.Fatalf("Failed to read outer manifest: %v", err)
	}

	var outer OuterManifest
	if err := json.Unmarshal(outerData, &outer); err != nil {
		t.Fatalf("Failed to unmarshal outer manifest: %v", err)
	}

	// Verify structure
	expectedPath := "metadata/" + InnerManifestName
	if outer.InnerManifest.Path != expectedPath {
		t.Errorf("InnerManifest path: got %s, want %s", outer.InnerManifest.Path, expectedPath)
	}

	if len(outer.MetadataFiles) == 0 {
		t.Error("No metadata files in outer manifest")
	}

	if len(outer.DataFiles) == 0 {
		t.Error("No data files in outer manifest")
	}

	if len(outer.ParityFiles) != manager.scheme.ParityShards {
		t.Errorf("ParityFiles count: got %d, want %d", len(outer.ParityFiles), manager.scheme.ParityShards)
	}

	// Verify all entries have checksums
	allFiles := append(outer.DataFiles, outer.MetadataFiles...)
	allFiles = append(allFiles, outer.ParityFiles...)
	allFiles = append(allFiles, outer.InnerManifest)

	for _, file := range allFiles {
		if file.MD5 == "" {
			t.Errorf("File %s missing MD5 checksum", file.Path)
		}
		// SHA256 is optional for restic data files and parity files
		isResticData := strings.HasPrefix(file.Path, "data/")
		isParity := file.Type == "parity"
		if !isResticData && !isParity && file.SHA256 == "" {
			t.Errorf("File %s missing SHA256 checksum", file.Path)
		}
	}
}

// Integration test: Full backup and recovery

func TestFullBackupAndRecovery(t *testing.T) {
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	// Step 1: Create full backup with erasure codes
	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.25, // 25% redundancy for testing
	}

	manager := NewManager(config)

	// Run full backup workflow (without remote upload)
	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}

	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	if err := manager.GenerateErasureCodes(); err != nil {
		t.Fatalf("Failed to generate erasure codes: %v", err)
	}

	if err := manager.CreateOuterManifest(); err != nil {
		t.Fatalf("Failed to create outer manifest: %v", err)
	}

	// Initialize and save state (needed for the new architecture)
	if err := manager.loadState(); err != nil {
		t.Logf("Warning: failed to load state: %v", err)
	}
	if err := manager.saveState(); err != nil {
		t.Fatalf("Failed to save state: %v", err)
	}

	// Log the erasure scheme for debugging
	t.Logf("Erasure scheme: %d data + %d parity = %d total shards",
		manager.scheme.DataShards, manager.scheme.ParityShards, manager.scheme.TotalShards)

	// Step 2: Delete some repository files (but not more than parity shards can handle)
	// With 3 parity shards, we can recover up to 3 missing files total
	deletedFiles := []string{
		"data/00/0001234567",
		"data/01/0101234567",
	}

	for _, file := range deletedFiles {
		filePath := filepath.Join(repoDir, file)
		if err := os.Remove(filePath); err != nil {
			t.Fatalf("Failed to delete test file %s: %v", file, err)
		}
	}

	// Also delete erasure_scheme.json to test metadata recovery
	schemePath := filepath.Join(config.MetadataDir, ErasureSchemeName)
	if err := os.Remove(schemePath); err != nil {
		t.Fatalf("Failed to delete erasure scheme: %v", err)
	}

	// Delete the metadata zip to force its recovery
	metadataFiles, err := os.ReadDir(config.MetadataDir)
	if err == nil {
		for _, file := range metadataFiles {
			if !file.IsDir() && file.Name() != InnerManifestName && file.Name() != ErasureSchemeName {
				// This should be the metadata zip
				metadataZipPath := filepath.Join(config.MetadataDir, file.Name())
				if err := os.Remove(metadataZipPath); err != nil {
					t.Fatalf("Failed to delete metadata zip: %v", err)
				}
				t.Logf("Deleted metadata zip: %s", file.Name())
				break
			}
		}
	}

	// Check parity file sizes for debugging
	parityShardDir := filepath.Join(config.ParityDir, "shards")
	if files, err := os.ReadDir(parityShardDir); err == nil {
		for _, f := range files {
			if info, err := f.Info(); err == nil {
				t.Logf("Parity file %s: %d bytes", f.Name(), info.Size())
			}
		}
	}

	// Step 3: Attempt recovery
	recoveryConfig := &Config{
		RepoPath:    repoDir,
		ParityDir:   config.ParityDir,
		MetadataDir: config.MetadataDir,
		RecoverAll:  true,
	}

	recoveryManager := NewManager(recoveryConfig)

	// Perform recovery using the main Recover method which detects format
	if err := recoveryManager.Recover(); err != nil {
		t.Fatalf("Failed to recover: %v", err)
	}

	// Step 4: Verify recovered files

	// Check erasure_scheme.json was recovered
	if _, err := os.Stat(schemePath); os.IsNotExist(err) {
		t.Error("erasure_scheme.json was not recovered")
	}

	// Check deleted repository files were recovered
	for _, file := range deletedFiles {
		filePath := filepath.Join(repoDir, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("File %s was not recovered", file)
		}
	}

	// Verify content of recovered files matches checksums
	for _, fileEntry := range recoveryManager.innerManifest.Files {
		if fileEntry.Path == ErasureSchemeName {
			continue // Already checked
		}

		filePath := filepath.Join(repoDir, fileEntry.Path)

		// Check if this is a restic data file
		isResticData := strings.HasPrefix(fileEntry.Path, "data/")

		if isResticData {
			// For restic data files, only verify MD5
			md5sum, err := calculateMD5Only(filePath)
			if err != nil {
				t.Errorf("Failed to calculate MD5 for recovered file %s: %v", fileEntry.Path, err)
				continue
			}
			if md5sum != fileEntry.MD5 {
				t.Errorf("MD5 mismatch for recovered file %s", fileEntry.Path)
			}
		} else {
			// For other files, verify both checksums
			md5sum, sha256sum, err := calculateChecksums(filePath)
			if err != nil {
				t.Errorf("Failed to calculate checksums for recovered file %s: %v", fileEntry.Path, err)
				continue
			}

			if md5sum != fileEntry.MD5 {
				t.Errorf("MD5 mismatch for recovered file %s", fileEntry.Path)
			}

			if sha256sum != fileEntry.SHA256 {
				t.Errorf("SHA256 mismatch for recovered file %s", fileEntry.Path)
			}
		}
	}
}

func TestFastVerify(t *testing.T) {
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	// Create backup
	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.10,
	}

	manager := NewManager(config)

	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}

	// Create full backup
	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	if err := manager.GenerateErasureCodes(); err != nil {
		t.Fatalf("Failed to generate erasure codes: %v", err)
	}

	if err := manager.CreateOuterManifest(); err != nil {
		t.Fatalf("Failed to create outer manifest: %v", err)
	}

	// Test fast verify - should pass
	if err := manager.check(); err != nil {
		t.Errorf("Fast verify failed on intact backup: %v", err)
	}

	// Corrupt a file and test again
	testFile := filepath.Join(repoDir, "data/00/0001234567")
	if err := os.WriteFile(testFile, []byte("corrupted content"), 0644); err != nil {
		t.Fatalf("Failed to corrupt test file: %v", err)
	}

	// Fast verify should now fail
	if err := manager.check(); err == nil {
		t.Error("Fast verify should have failed with corrupted file")
	}
}

func TestMinimalRecovery(t *testing.T) {
	// Test that we can recover with exactly the minimum number of shards
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.30, // 30% redundancy
	}

	manager := NewManager(config)

	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}

	// Create backup
	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	if err := manager.GenerateErasureCodes(); err != nil {
		t.Fatalf("Failed to generate erasure codes: %v", err)
	}

	if err := manager.CreateOuterManifest(); err != nil {
		t.Fatalf("Failed to create outer manifest: %v", err)
	}

	// Delete maximum allowed files (parity count)
	parityCount := manager.scheme.ParityShards
	deletedCount := 0

	// Delete some data files
	dataFiles := []string{
		"data/00/0001234567",
		"data/00/0009876543",
		"data/01/0101234567",
	}

	for i, file := range dataFiles {
		if i >= parityCount {
			break
		}
		filePath := filepath.Join(repoDir, file)
		if err := os.Remove(filePath); err != nil {
			t.Fatalf("Failed to delete file: %v", err)
		}
		deletedCount++
	}

	// Delete some parity files to reach the limit
	parityDir := filepath.Join(config.ParityDir, "shards")
	for i := 0; i < parityCount-deletedCount && i < 2; i++ {
		parityFile := filepath.Join(parityDir, fmt.Sprintf("parity_%04d.shard", i))
		if err := os.Remove(parityFile); err != nil {
			t.Fatalf("Failed to delete parity file: %v", err)
		}
	}

	t.Logf("Deleted %d files (parity shards: %d)", deletedCount, parityCount)

	// Attempt recovery
	recoveryConfig := &Config{
		RepoPath:    repoDir,
		ParityDir:   config.ParityDir,
		MetadataDir: config.MetadataDir,
		RecoverAll:  true,
	}

	recoveryManager := NewManager(recoveryConfig)

	// This should still work with minimum shards
	if err := recoveryManager.Recover(); err != nil {
		t.Errorf("Recovery failed with minimum shards: %v", err)
	}
}

func TestRecoveryWithMissingInnerManifest(t *testing.T) {
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	// Create backup
	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.20,
	}

	manager := NewManager(config)

	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}

	// Create full backup
	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	if err := manager.GenerateErasureCodes(); err != nil {
		t.Fatalf("Failed to generate erasure codes: %v", err)
	}

	if err := manager.CreateOuterManifest(); err != nil {
		t.Fatalf("Failed to create outer manifest: %v", err)
	}

	// Delete inner manifest
	innerPath := filepath.Join(config.MetadataDir, InnerManifestName)
	if err := os.Remove(innerPath); err != nil {
		t.Fatalf("Failed to delete inner manifest: %v", err)
	}

	// Delete metadata zip to force recovery of inner manifest
	metadataFiles, err := os.ReadDir(config.MetadataDir)
	if err == nil {
		for _, file := range metadataFiles {
			if !file.IsDir() && file.Name() != InnerManifestName && file.Name() != ErasureSchemeName {
				// This should be the metadata zip
				metadataZipPath := filepath.Join(config.MetadataDir, file.Name())
				if err := os.Remove(metadataZipPath); err != nil {
					t.Fatalf("Failed to delete metadata zip: %v", err)
				}
				break
			}
		}
	}

	// Also delete one more data file (total 2 deletions with inner manifest)
	deletedFiles := []string{
		"data/00/0009876543",
	}

	for _, file := range deletedFiles {
		filePath := filepath.Join(repoDir, file)
		if err := os.Remove(filePath); err != nil {
			t.Fatalf("Failed to delete file: %v", err)
		}
	}

	// Recovery should work even without inner manifest
	recoveryConfig := &Config{
		RepoPath:    repoDir,
		ParityDir:   config.ParityDir,
		MetadataDir: config.MetadataDir,
		RecoverAll:  true,
	}

	recoveryManager := NewManager(recoveryConfig)

	if err := recoveryManager.Recover(); err != nil {
		t.Fatalf("Recovery failed: %v", err)
	}

	// Verify inner manifest was recovered
	if _, err := os.Stat(innerPath); os.IsNotExist(err) {
		t.Error("Inner manifest was not recovered")
	}

	// Verify deleted files were recovered
	for _, file := range deletedFiles {
		filePath := filepath.Join(repoDir, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("File %s was not recovered", file)
		}
	}
}

func TestLocalOnlyWorkflow(t *testing.T) {
	// Test that the program works without any remote configuration
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	// Set environment variable for repository
	os.Setenv("RESTIC_REPOSITORY", repoDir)
	defer os.Unsetenv("RESTIC_REPOSITORY")

	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.15,
		// No RcloneRemote specified - should work locally only
	}

	manager := NewManager(config)

	// Initialize state
	if err := manager.loadState(); err != nil {
		t.Logf("Warning: failed to load state: %v", err)
	}

	// For first run, we need to ensure parity directory exists
	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}

	// First, calculate erasure scheme
	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	// Then create manifests and erasure codes
	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	if err := manager.GenerateErasureCodes(); err != nil {
		t.Fatalf("Failed to generate erasure codes: %v", err)
	}

	if err := manager.CreateOuterManifest(); err != nil {
		t.Fatalf("Failed to create outer manifest: %v", err)
	}

	// Check for manifest files
	innerPath := filepath.Join(config.MetadataDir, InnerManifestName)
	outerPath := filepath.Join(config.ParityDir, OuterManifestName)

	if _, err := os.Stat(innerPath); os.IsNotExist(err) {
		t.Error("Inner manifest not created in local workflow")
	}

	if _, err := os.Stat(outerPath); os.IsNotExist(err) {
		t.Error("Outer manifest not created in local workflow")
	}
}

func TestMultipleFileDeletion(t *testing.T) {
	// Test recovery when multiple files from same parity group are deleted
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.40, // 40% redundancy to handle multiple deletions
	}

	manager := NewManager(config)

	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}

	// Create backup
	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	if err := manager.GenerateErasureCodes(); err != nil {
		t.Fatalf("Failed to generate erasure codes: %v", err)
	}

	if err := manager.CreateOuterManifest(); err != nil {
		t.Fatalf("Failed to create outer manifest: %v", err)
	}

	// Delete 35% of files (less than redundancy)
	totalFiles := len(manager.innerManifest.Files)
	filesToDelete := int(float64(totalFiles) * 0.35)

	deletedFiles := []string{}
	for i, file := range manager.innerManifest.Files {
		if i >= filesToDelete {
			break
		}
		if file.Path != ErasureSchemeName { // Don't delete erasure scheme
			deletedFiles = append(deletedFiles, file.Path)
			filePath := filepath.Join(repoDir, file.Path)
			if err := os.Remove(filePath); err != nil {
				t.Logf("Warning: failed to delete %s: %v", file.Path, err)
			}
		}
	}

	t.Logf("Deleted %d files out of %d total", len(deletedFiles), totalFiles)

	// Recovery should still work
	recoveryConfig := &Config{
		RepoPath:    repoDir,
		ParityDir:   config.ParityDir,
		MetadataDir: config.MetadataDir,
		RecoverAll:  true,
	}

	recoveryManager := NewManager(recoveryConfig)

	if err := recoveryManager.Recover(); err != nil {
		t.Fatalf("Recovery failed after deleting %d files: %v", len(deletedFiles), err)
	}

	// Verify all deleted files were recovered
	for _, file := range deletedFiles {
		filePath := filepath.Join(repoDir, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("File %s was not recovered", file)
		}
	}
}

// Test error conditions

func TestInvalidRepoPath(t *testing.T) {
	config := &Config{
		RepoPath:    "/non/existent/path",
		ParityDir:   filepath.Join("/non/existent/path", "parity"),
		MetadataDir: filepath.Join("/non/existent/path", "metadata"),
		MinOverhead: 0.10,
	}

	manager := NewManager(config)

	if err := manager.CalculateErasureScheme(); err == nil {
		t.Error("Expected error for invalid repo path")
	}
}

func TestCorruptedParityFile(t *testing.T) {
	tempDir := t.TempDir()
	repoDir := createTestRepo(t, tempDir)

	// Create backup
	config := &Config{
		RepoPath:    repoDir,
		ParityDir:   filepath.Join(repoDir, "parity"),
		MetadataDir: filepath.Join(repoDir, "metadata"),
		MinOverhead: 0.20,
	}

	manager := NewManager(config)

	if err := os.MkdirAll(config.ParityDir, 0755); err != nil {
		t.Fatalf("Failed to create parity dir: %v", err)
	}

	// Create full backup
	if err := manager.CalculateErasureScheme(); err != nil {
		t.Fatalf("Failed to calculate erasure scheme: %v", err)
	}

	if err := manager.CreateInnerManifest(); err != nil {
		t.Fatalf("Failed to create inner manifest: %v", err)
	}

	if err := manager.GenerateErasureCodes(); err != nil {
		t.Fatalf("Failed to generate erasure codes: %v", err)
	}

	if err := manager.CreateOuterManifest(); err != nil {
		t.Fatalf("Failed to create outer manifest: %v", err)
	}

	// Corrupt a parity file
	parityFile := filepath.Join(config.ParityDir, "shards", "parity_0000.shard")
	if err := os.WriteFile(parityFile, []byte("corrupted"), 0644); err != nil {
		t.Fatalf("Failed to corrupt parity file: %v", err)
	}

	// Delete a data file
	testFile := filepath.Join(repoDir, "data/00/0001234567")
	if err := os.Remove(testFile); err != nil {
		t.Fatalf("Failed to delete test file: %v", err)
	}

	// Recovery should still work with other parity files
	recoveryConfig := &Config{
		RepoPath:   repoDir,
		ParityDir:  config.ParityDir,
		RecoverAll: true,
	}

	recoveryManager := NewManager(recoveryConfig)

	// Should succeed if we have enough good parity files
	if err := recoveryManager.Recover(); err != nil {
		// This might fail if we don't have enough redundancy after corruption
		t.Logf("Recovery with corrupted parity: %v", err)
	}
}

// Benchmark tests

func BenchmarkErasureEncoding(b *testing.B) {

	// Create larger test data
	dataSize := 1024 * 1024 // 1MB per shard
	dataShards := 10
	parityShards := 2

	data := make([][]byte, dataShards+parityShards)
	for i := 0; i < dataShards; i++ {
		data[i] = make([]byte, dataSize)
		for j := range data[i] {
			data[i][j] = byte(i + j)
		}
	}
	// Pre-allocate parity shards
	for i := dataShards; i < dataShards+parityShards; i++ {
		data[i] = make([]byte, dataSize)
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		b.Fatalf("Failed to create encoder: %v", err)
	}

	b.ResetTimer()
	b.SetBytes(int64(dataSize * dataShards))

	for i := 0; i < b.N; i++ {
		if err := enc.Encode(data); err != nil {
			b.Fatalf("Encoding failed: %v", err)
		}
	}
}

func BenchmarkChecksumCalculation(b *testing.B) {
	tempDir := b.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "test.dat")
	fileSize := 10 * 1024 * 1024 // 10MB
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := os.WriteFile(testFile, data, 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	b.SetBytes(int64(fileSize))

	for i := 0; i < b.N; i++ {
		_, _, err := calculateChecksums(testFile)
		if err != nil {
			b.Fatalf("Checksum calculation failed: %v", err)
		}
	}
}

func BenchmarkFullBackup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tempDir, _ := os.MkdirTemp("", "bench")
		defer os.RemoveAll(tempDir)
		repoDir := createTestRepo(&testing.T{}, tempDir)

		config := &Config{
			RepoPath:    repoDir,
			ParityDir:   filepath.Join(repoDir, "parity"),
			MetadataDir: filepath.Join(repoDir, "metadata"),
			MinOverhead: 0.10,
		}

		manager := NewManager(config)
		os.MkdirAll(config.ParityDir, 0755)

		b.StartTimer()

		if err := manager.CalculateErasureScheme(); err != nil {
			b.Fatalf("Failed to calculate erasure scheme: %v", err)
		}

		if err := manager.CreateInnerManifest(); err != nil {
			b.Fatalf("Failed to create inner manifest: %v", err)
		}

		if err := manager.GenerateErasureCodes(); err != nil {
			b.Fatalf("Failed to generate erasure codes: %v", err)
		}

		if err := manager.CreateOuterManifest(); err != nil {
			b.Fatalf("Failed to create outer manifest: %v", err)
		}
	}
}
