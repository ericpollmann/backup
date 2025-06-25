package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	Version           = "1.0.0"
	InnerManifestName = "INNER_MANIFEST.json"
	OuterManifestName = "OUTER_MANIFEST.json"
	ErasureSchemeName = "erasure_scheme.json"
)

// FileEntry represents a file with checksums
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
	Type   string `json:"type"` // "data", "parity", "manifest", "metadata"
}

// InnerManifest contains repository files and erasure scheme
type InnerManifest struct {
	Version       string         `json:"version"`
	Created       time.Time      `json:"created"`
	RepoPath      string         `json:"repo_path"`
	TotalSize     int64          `json:"total_size"`
	Files         []FileEntry    `json:"files"`
	FileCount     int            `json:"file_count"`
	ErasureScheme *ErasureScheme `json:"erasure_scheme"`
}

// OuterManifest contains everything including erasure blocks
type OuterManifest struct {
	Version       string      `json:"version"`
	Created       time.Time   `json:"created"`
	InnerManifest FileEntry   `json:"inner_manifest"`
	DataFiles     []FileEntry `json:"data_files"`     // Repository files
	ParityFiles   []FileEntry `json:"parity_files"`   // Erasure code blocks
	MetadataFiles []FileEntry `json:"metadata_files"` // erasure_scheme.json, etc.
	TotalSize     int64       `json:"total_size"`
	FileCount     int         `json:"file_count"`
}

// ErasureScheme defines the erasure coding parameters
type ErasureScheme struct {
	DataShards   int     `json:"data_shards"`
	ParityShards int     `json:"parity_shards"`
	TotalShards  int     `json:"total_shards"`
	ShardSize    int64   `json:"shard_size"`
	FileOverhead float64 `json:"file_overhead_percent"`
	SizeOverhead float64 `json:"size_overhead_percent"`
	CanRecover   int     `json:"can_recover_up_to"`
}

// State tracks which files have been processed
type State struct {
	Version        string            `json:"version"`
	LastProcessed  time.Time         `json:"last_processed"`
	ProcessedFiles map[string]string `json:"processed_files"` // path -> checksum
	ParityShards   []string          `json:"parity_shards"`   // list of parity files
}

// Config holds application configuration
type Config struct {
	RepoPath        string
	ParityDir       string // Permanent parity directory (.restic/parity)
	RcloneRemote    string
	MinOverhead     float64
	BackupSources   []string
	ExcludePatterns []string
	WorkDir         string // Temporary directory for operations
	KeepTemp        bool   // Keep temporary files
	RemoteDir       string // Remote directory for recovery
	FastVerify      bool   // Fast verification mode
	FullVerify      bool   // Full verification mode
	Recover         string // Specific file to recover
	RecoverAll      bool   // Recover all missing files
}

// Manager handles the complete workflow
type Manager struct {
	config        *Config
	state         *State
	innerManifest *InnerManifest
	outerManifest *OuterManifest
	scheme        *ErasureScheme
}

func NewManager(config *Config) *Manager {
	return &Manager{
		config: config,
	}
}

// Run executes the main workflow
func (m *Manager) Run() error {
	// Create temporary working directory
	if m.config.WorkDir == "" {
		tempDir, err := os.MkdirTemp("/tmp", "restic-erasure-*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory: %w", err)
		}
		m.config.WorkDir = tempDir

		// Clean up temp directory when done (unless -keep-temp is set)
		if !m.config.KeepTemp {
			defer func() {
				log.Printf("Cleaning up temporary directory: %s", tempDir)
				os.RemoveAll(tempDir)
			}()
		} else {
			log.Printf("Temporary files will be kept in: %s", tempDir)
		}
	}

	log.Printf("Working directory: %s", m.config.WorkDir)

	switch {
	case m.config.FastVerify || m.config.FullVerify:
		// For verification, download manifests from remote if needed
		if err := m.downloadManifests(); err != nil {
			return fmt.Errorf("failed to download manifests: %w", err)
		}
		if m.config.FastVerify {
			return m.check()
		}
		return m.fsck()

	case m.config.Recover != "" || m.config.RecoverAll:
		// For recovery, download necessary files from remote
		if err := m.downloadForRecovery(); err != nil {
			return fmt.Errorf("failed to download recovery files: %w", err)
		}
		return m.Recover()

	default:
		// Full backup workflow
		if err := m.RunResticBackup(); err != nil {
			return fmt.Errorf("restic backup failed: %w", err)
		}

		// Calculate erasure scheme first
		if err := m.CalculateErasureScheme(); err != nil {
			return fmt.Errorf("erasure scheme calculation failed: %w", err)
		}

		// Create inner manifest (including erasure scheme)
		if err := m.CreateInnerManifest(); err != nil {
			return fmt.Errorf("inner manifest creation failed: %w", err)
		}

		// Generate erasure codes
		if err := m.GenerateErasureCodes(); err != nil {
			return fmt.Errorf("erasure code generation failed: %w", err)
		}

		// Create outer manifest
		if err := m.CreateOuterManifest(); err != nil {
			return fmt.Errorf("outer manifest creation failed: %w", err)
		}

		if m.config.RcloneRemote != "" {
			if err := m.UploadToRemote(); err != nil {
				return fmt.Errorf("remote upload failed: %w", err)
			}
		} else {
			log.Println("No remote specified, erasure files saved locally only")
		}

		m.PrintSummary()
		return nil
	}
}

// downloadManifests downloads manifests from remote for verification
func (m *Manager) downloadManifests() error {
	if m.config.RcloneRemote == "" {
		// If no remote, parity files should be local
		return nil
	}

	log.Println("Downloading manifests from remote...")

	// Ensure parity directory exists
	if err := os.MkdirAll(m.config.ParityDir, 0755); err != nil {
		return fmt.Errorf("failed to create parity directory: %w", err)
	}

	files := []string{OuterManifestName, InnerManifestName, ErasureSchemeName}
	for _, file := range files {
		src := fmt.Sprintf("%s/.restic/parity/%s", m.config.RcloneRemote, file)
		dst := m.config.ParityDir

		cmd := exec.Command("rclone", "copy", src, dst)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to download %s: %v", file, err)
		}
	}

	return nil
}

// downloadForRecovery downloads necessary files for recovery
func (m *Manager) downloadForRecovery() error {
	if m.config.RcloneRemote == "" {
		// If no remote, parity files should be local
		return nil
	}

	log.Println("Downloading recovery files from remote...")

	// Ensure parity directory exists
	if err := os.MkdirAll(m.config.ParityDir, 0755); err != nil {
		return fmt.Errorf("failed to create parity directory: %w", err)
	}

	// Download manifests and metadata
	files := []string{
		InnerManifestName,
		OuterManifestName,
		ErasureSchemeName,
	}

	for _, file := range files {
		src := fmt.Sprintf("%s/.restic/parity/%s", m.config.RcloneRemote, file)
		dst := m.config.ParityDir

		cmd := exec.Command("rclone", "copy", src, dst)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to download %s: %v", file, err)
		}
	}

	// Download parity shards
	paritySrc := fmt.Sprintf("%s/.restic/parity/shards/", m.config.RcloneRemote)
	parityDst := filepath.Join(m.config.ParityDir, "shards")

	cmd := exec.Command("rclone", "copy", paritySrc, parityDst, "--progress")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Printf("Warning: failed to download parity files: %v", err)
	}

	return nil
}

// RunResticBackup executes restic backup if sources are specified
func (m *Manager) RunResticBackup() error {
	if len(m.config.BackupSources) == 0 {
		log.Println("No backup sources specified, skipping restic backup")
		return nil
	}

	log.Println("Running restic backup...")

	// Build restic command
	args := []string{"backup"}
	args = append(args, m.config.BackupSources...)

	// Add exclude patterns
	for _, pattern := range m.config.ExcludePatterns {
		args = append(args, "--exclude", pattern)
	}

	// Set repository
	cmd := exec.Command("restic", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("RESTIC_REPOSITORY=%s", m.config.RepoPath))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restic backup failed: %w", err)
	}

	log.Println("Restic backup completed")
	return nil
}

// CalculateErasureScheme determines the erasure coding parameters
func (m *Manager) CalculateErasureScheme() error {
	log.Println("Calculating erasure scheme...")

	// Scan repository to count files
	fileCount := 0
	var maxFileSize int64

	err := filepath.Walk(m.config.RepoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileCount++
			if info.Size() > maxFileSize {
				maxFileSize = info.Size()
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error scanning repository: %w", err)
	}

	// Total files includes: repo files + inner manifest + erasure scheme
	totalFiles := fileCount + 2
	minParityShards := int(math.Ceil(float64(totalFiles) * m.config.MinOverhead))

	// Ensure minimum of 3 parity shards
	if minParityShards < 3 {
		minParityShards = 3
	}

	// Account for inner manifest and erasure scheme sizes (generous estimate)
	// The manifest can get quite large with many files
	estimatedManifestSize := int64(fileCount*300) + 5000 // ~300 bytes per file entry + overhead
	estimatedErasureSchemeSize := int64(2000)            // Estimate for erasure scheme JSON

	if estimatedManifestSize > maxFileSize {
		maxFileSize = estimatedManifestSize
	}
	if estimatedErasureSchemeSize > maxFileSize {
		maxFileSize = estimatedErasureSchemeSize
	}

	// Add some padding to ensure we have enough space
	maxFileSize = int64(float64(maxFileSize) * 1.1)

	m.scheme = &ErasureScheme{
		DataShards:   totalFiles,
		ParityShards: minParityShards,
		TotalShards:  totalFiles + minParityShards,
		ShardSize:    maxFileSize,
		FileOverhead: float64(minParityShards) / float64(totalFiles) * 100,
		SizeOverhead: m.config.MinOverhead * 100,
		CanRecover:   minParityShards,
	}

	log.Printf("Erasure scheme: %d data shards (including manifests), %d parity shards",
		m.scheme.DataShards, m.scheme.ParityShards)

	return nil
}

// CreateInnerManifest scans repository and creates inner manifest
func (m *Manager) CreateInnerManifest() error {
	log.Println("Creating inner manifest...")

	// First, save the erasure scheme file
	schemePath := filepath.Join(m.config.ParityDir, ErasureSchemeName)
	schemeData, err := json.MarshalIndent(m.scheme, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal erasure scheme: %w", err)
	}

	if err := os.WriteFile(schemePath, schemeData, 0644); err != nil {
		return fmt.Errorf("failed to write erasure scheme: %w", err)
	}

	// Calculate checksums for erasure scheme
	schemeMD5, schemeSHA256, err := calculateChecksums(schemePath)
	if err != nil {
		return fmt.Errorf("failed to calculate erasure scheme checksums: %w", err)
	}

	// Create inner manifest
	m.innerManifest = &InnerManifest{
		Version:       Version,
		Created:       time.Now(),
		RepoPath:      m.config.RepoPath,
		Files:         make([]FileEntry, 0),
		ErasureScheme: m.scheme,
	}

	// Add erasure scheme as first file
	m.innerManifest.Files = append(m.innerManifest.Files, FileEntry{
		Path:   ErasureSchemeName,
		Size:   int64(len(schemeData)),
		MD5:    schemeMD5,
		SHA256: schemeSHA256,
		Type:   "metadata",
	})
	m.innerManifest.TotalSize += int64(len(schemeData))

	// Scan repository
	err = filepath.Walk(m.config.RepoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the parity directory
		if info.IsDir() && path == m.config.ParityDir {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(m.config.RepoPath, path)
			if err != nil {
				return err
			}

			// Skip files in parity directory (in case ParityDir is inside RepoPath)
			if strings.HasPrefix(relPath, "parity/") {
				return nil
			}

			// Calculate checksums
			md5sum, sha256sum, err := calculateChecksums(path)
			if err != nil {
				log.Printf("Warning: couldn't calculate checksums for %s: %v", path, err)
				return nil // Continue with other files
			}

			entry := FileEntry{
				Path:   relPath,
				Size:   info.Size(),
				MD5:    md5sum,
				SHA256: sha256sum,
				Type:   "data",
			}

			m.innerManifest.Files = append(m.innerManifest.Files, entry)
			m.innerManifest.TotalSize += info.Size()
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error scanning repository: %w", err)
	}

	m.innerManifest.FileCount = len(m.innerManifest.Files)

	// Sort files by path for consistent ordering, but keep erasure_scheme.json first
	sort.Slice(m.innerManifest.Files, func(i, j int) bool {
		// erasure_scheme.json always comes first
		if m.innerManifest.Files[i].Path == ErasureSchemeName {
			return true
		}
		if m.innerManifest.Files[j].Path == ErasureSchemeName {
			return false
		}
		// Otherwise sort alphabetically
		return m.innerManifest.Files[i].Path < m.innerManifest.Files[j].Path
	})

	// Save inner manifest
	manifestPath := filepath.Join(m.config.ParityDir, InnerManifestName)
	manifestData, err := json.MarshalIndent(m.innerManifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal inner manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return fmt.Errorf("failed to write inner manifest: %w", err)
	}

	log.Printf("Inner manifest created: %d files (including metadata), %.2f GB total",
		m.innerManifest.FileCount,
		float64(m.innerManifest.TotalSize)/(1024*1024*1024))

	return nil
}

// GenerateErasureCodes creates parity shards
func (m *Manager) GenerateErasureCodes() error {
	log.Println("Generating erasure codes...")

	// Create Reed-Solomon encoder
	enc, err := reedsolomon.New(m.scheme.DataShards, m.scheme.ParityShards)
	if err != nil {
		return fmt.Errorf("failed to create encoder: %w", err)
	}

	// Prepare data shards (need to allocate space for parity shards too)
	dataShards := make([][]byte, m.scheme.DataShards+m.scheme.ParityShards)
	shardIndex := 0

	// First shard is the erasure scheme
	schemePath := filepath.Join(m.config.ParityDir, ErasureSchemeName)
	schemeData, err := os.ReadFile(schemePath)
	if err != nil {
		return fmt.Errorf("failed to read erasure scheme: %w", err)
	}
	dataShards[shardIndex] = make([]byte, m.scheme.ShardSize)
	copy(dataShards[shardIndex], schemeData)
	shardIndex++

	// Second shard is the inner manifest
	manifestPath := filepath.Join(m.config.ParityDir, InnerManifestName)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read inner manifest: %w", err)
	}
	dataShards[shardIndex] = make([]byte, m.scheme.ShardSize)
	copy(dataShards[shardIndex], manifestData)
	shardIndex++

	// Remaining shards are repository files (skip erasure_scheme.json from files list)
	for _, file := range m.innerManifest.Files {
		if file.Path == ErasureSchemeName {
			continue // Already added as first shard
		}

		// Determine the correct base path for the file
		var filePath string
		if file.Path == "state.json" {
			// state.json is in the parity directory
			filePath = filepath.Join(m.config.ParityDir, file.Path)
		} else {
			// Repository files
			filePath = filepath.Join(m.config.RepoPath, file.Path)
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Warning: couldn't read %s: %v", filePath, err)
			data = []byte{} // Use empty data for missing files
		}

		if shardIndex < m.scheme.DataShards {
			dataShards[shardIndex] = make([]byte, m.scheme.ShardSize)
			copy(dataShards[shardIndex], data)
			shardIndex++
		}
	}

	// Fill any remaining empty shards
	for shardIndex < m.scheme.DataShards {
		dataShards[shardIndex] = make([]byte, m.scheme.ShardSize)
		shardIndex++
	}

	// Pre-allocate parity shards (Reed-Solomon requires them to be pre-allocated)
	for i := 0; i < m.scheme.ParityShards; i++ {
		dataShards[m.scheme.DataShards+i] = make([]byte, m.scheme.ShardSize)
	}

	// Generate parity shards
	log.Printf("Creating %d parity shards...", m.scheme.ParityShards)

	if err := enc.Encode(dataShards); err != nil {
		return fmt.Errorf("failed to encode: %w", err)
	}

	// Save parity shards
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	if err := os.MkdirAll(parityDir, 0755); err != nil {
		return fmt.Errorf("failed to create parity directory: %w", err)
	}

	for i := 0; i < m.scheme.ParityShards; i++ {
		parityPath := filepath.Join(parityDir, fmt.Sprintf("parity_%04d.shard", i))
		parityData := dataShards[m.scheme.DataShards+i]

		if err := os.WriteFile(parityPath, parityData, 0644); err != nil {
			return fmt.Errorf("failed to write parity shard %d: %w", i, err)
		}

		log.Printf("Created parity shard %d/%d", i+1, m.scheme.ParityShards)
	}

	return nil
}

// CreateOuterManifest creates the outer manifest including parity files
func (m *Manager) CreateOuterManifest() error {
	log.Println("Creating outer manifest...")

	m.outerManifest = &OuterManifest{
		Version:       Version,
		Created:       time.Now(),
		DataFiles:     make([]FileEntry, 0),
		ParityFiles:   make([]FileEntry, 0),
		MetadataFiles: make([]FileEntry, 0),
	}

	// Separate data files and metadata files from inner manifest
	for _, file := range m.innerManifest.Files {
		if file.Type == "metadata" {
			m.outerManifest.MetadataFiles = append(m.outerManifest.MetadataFiles, file)
		} else {
			m.outerManifest.DataFiles = append(m.outerManifest.DataFiles, file)
		}
	}

	// Add inner manifest entry
	manifestPath := filepath.Join(m.config.ParityDir, InnerManifestName)
	md5sum, sha256sum, err := calculateChecksums(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to calculate inner manifest checksums: %w", err)
	}

	manifestInfo, _ := os.Stat(manifestPath)
	m.outerManifest.InnerManifest = FileEntry{
		Path:   InnerManifestName,
		Size:   manifestInfo.Size(),
		MD5:    md5sum,
		SHA256: sha256sum,
		Type:   "manifest",
	}

	// Add parity files
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	for i := 0; i < m.scheme.ParityShards; i++ {
		parityPath := filepath.Join(parityDir, fmt.Sprintf("parity_%04d.shard", i))

		md5sum, sha256sum, err := calculateChecksums(parityPath)
		if err != nil {
			log.Printf("Warning: couldn't calculate checksums for parity shard %d: %v", i, err)
			continue
		}

		info, _ := os.Stat(parityPath)
		entry := FileEntry{
			Path:   fmt.Sprintf("shards/parity_%04d.shard", i),
			Size:   info.Size(),
			MD5:    md5sum,
			SHA256: sha256sum,
			Type:   "parity",
		}

		m.outerManifest.ParityFiles = append(m.outerManifest.ParityFiles, entry)
		m.outerManifest.TotalSize += info.Size()
	}

	// Calculate totals
	m.outerManifest.TotalSize += m.innerManifest.TotalSize + m.outerManifest.InnerManifest.Size
	m.outerManifest.FileCount = len(m.outerManifest.DataFiles) + len(m.outerManifest.MetadataFiles) +
		len(m.outerManifest.ParityFiles) + 1 // +1 for inner manifest

	// Save outer manifest
	outerPath := filepath.Join(m.config.ParityDir, OuterManifestName)
	outerData, err := json.MarshalIndent(m.outerManifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal outer manifest: %w", err)
	}

	if err := os.WriteFile(outerPath, outerData, 0644); err != nil {
		return fmt.Errorf("failed to write outer manifest: %w", err)
	}

	log.Println("Outer manifest created")
	return nil
}

// Incremental versions of the methods

// CalculateErasureSchemeIncremental updates erasure scheme for new files
func (m *Manager) CalculateErasureSchemeIncremental() error {
	log.Println("Calculating erasure scheme (incremental)...")

	// If we have an existing scheme, load it
	schemePath := filepath.Join(m.config.ParityDir, ErasureSchemeName)
	if _, err := os.Stat(schemePath); err == nil {
		data, err := os.ReadFile(schemePath)
		if err != nil {
			return fmt.Errorf("failed to read existing scheme: %w", err)
		}

		scheme := &ErasureScheme{}
		if err := json.Unmarshal(data, scheme); err != nil {
			return fmt.Errorf("failed to parse existing scheme: %w", err)
		}

		m.scheme = scheme
		log.Printf("Using existing erasure scheme: %d data + %d parity shards",
			scheme.DataShards, scheme.ParityShards)
		return nil
	}

	// Otherwise calculate new scheme
	return m.CalculateErasureScheme()
}

// CreateInnerManifestIncremental creates manifest for new/changed files
func (m *Manager) CreateInnerManifestIncremental() error {
	log.Println("Creating inner manifest (incremental)...")

	// Load existing manifest if available
	manifestPath := filepath.Join(m.config.ParityDir, InnerManifestName)
	existingFiles := make(map[string]FileEntry)

	if data, err := os.ReadFile(manifestPath); err == nil {
		existing := &InnerManifest{}
		if err := json.Unmarshal(data, existing); err == nil {
			// Build map of existing files
			for _, file := range existing.Files {
				existingFiles[file.Path] = file
			}
		}
	}

	// Scan repository and check for changes
	var files []FileEntry
	var totalSize int64
	changedFiles := 0

	err := filepath.Walk(m.config.RepoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the parity directory
		if info.IsDir() && path == m.config.ParityDir {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(m.config.RepoPath, path)
			if err != nil {
				return err
			}

			// Skip files in parity directory (in case ParityDir is inside RepoPath)
			if strings.HasPrefix(relPath, "parity/") {
				return nil
			}

			// Check if file has changed
			needsUpdate := false
			if existing, ok := existingFiles[relPath]; ok {
				// Quick size check first
				if existing.Size != info.Size() {
					needsUpdate = true
				} else {
					// Check MD5 for same-sized files
					md5sum, err := calculateMD5(path)
					if err != nil {
						return err
					}
					if md5sum != existing.MD5 {
						needsUpdate = true
					}
				}

				if !needsUpdate {
					// File hasn't changed, reuse existing entry
					files = append(files, existing)
					totalSize += existing.Size
					m.state.ProcessedFiles[relPath] = existing.SHA256
					return nil
				}
			} else {
				needsUpdate = true
			}

			if needsUpdate {
				changedFiles++
				// Calculate checksums for new/changed file
				md5sum, sha256sum, err := calculateChecksums(path)
				if err != nil {
					return fmt.Errorf("failed to checksum %s: %w", path, err)
				}

				entry := FileEntry{
					Path:   relPath,
					Size:   info.Size(),
					MD5:    md5sum,
					SHA256: sha256sum,
					Type:   "data",
				}

				files = append(files, entry)
				totalSize += info.Size()

				// Update state
				m.state.ProcessedFiles[relPath] = sha256sum
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error scanning repository: %w", err)
	}

	log.Printf("Found %d changed files", changedFiles)

	// Create manifest
	m.innerManifest = &InnerManifest{
		Version:       Version,
		Created:       time.Now(),
		RepoPath:      m.config.RepoPath,
		TotalSize:     totalSize,
		Files:         files,
		FileCount:     len(files),
		ErasureScheme: m.scheme,
	}

	// Save manifest to parity directory
	manifestData, err := json.MarshalIndent(m.innerManifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal inner manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return fmt.Errorf("failed to write inner manifest: %w", err)
	}

	log.Printf("Inner manifest created with %d files", len(files))
	return nil
}

// GenerateErasureCodesIncremental generates codes only for new/changed files
func (m *Manager) GenerateErasureCodesIncremental() error {
	log.Println("Generating erasure codes (incremental)...")

	// For now, regenerate all parity files
	// TODO: Implement true incremental parity generation
	return m.GenerateErasureCodes()
}

// CreateOuterManifestIncremental creates outer manifest with all files
func (m *Manager) CreateOuterManifestIncremental() error {
	log.Println("Creating outer manifest...")

	// Read inner manifest checksum
	manifestPath := filepath.Join(m.config.ParityDir, InnerManifestName)
	innerMD5, innerSHA256, err := calculateChecksums(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to checksum inner manifest: %w", err)
	}

	innerInfo, err := os.Stat(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to stat inner manifest: %w", err)
	}

	m.outerManifest = &OuterManifest{
		Version: Version,
		Created: time.Now(),
		InnerManifest: FileEntry{
			Path:   InnerManifestName,
			Size:   innerInfo.Size(),
			MD5:    innerMD5,
			SHA256: innerSHA256,
			Type:   "manifest",
		},
		DataFiles:     m.innerManifest.Files,
		MetadataFiles: []FileEntry{},
		ParityFiles:   []FileEntry{},
	}

	// Add erasure scheme
	schemePath := filepath.Join(m.config.ParityDir, ErasureSchemeName)
	if info, err := os.Stat(schemePath); err == nil {
		md5sum, sha256sum, err := calculateChecksums(schemePath)
		if err != nil {
			return fmt.Errorf("failed to checksum erasure scheme: %w", err)
		}

		m.outerManifest.MetadataFiles = append(m.outerManifest.MetadataFiles, FileEntry{
			Path:   ErasureSchemeName,
			Size:   info.Size(),
			MD5:    md5sum,
			SHA256: sha256sum,
			Type:   "metadata",
		})
		m.outerManifest.TotalSize += info.Size()
	}

	// Add parity files
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	if files, err := os.ReadDir(parityDir); err == nil {
		for _, file := range files {
			if !file.IsDir() && strings.HasPrefix(file.Name(), "parity_") {
				info, err := file.Info()
				if err != nil {
					continue
				}

				filePath := filepath.Join(parityDir, file.Name())
				md5sum, err := calculateMD5(filePath)
				if err != nil {
					continue
				}

				m.outerManifest.ParityFiles = append(m.outerManifest.ParityFiles, FileEntry{
					Path:   filepath.Join("shards", file.Name()),
					Size:   info.Size(),
					MD5:    md5sum,
					SHA256: "", // Skip SHA256 for parity files (large)
					Type:   "parity",
				})
				m.outerManifest.TotalSize += info.Size()
			}
		}
	}

	// Update totals
	m.outerManifest.TotalSize += m.innerManifest.TotalSize + m.outerManifest.InnerManifest.Size
	m.outerManifest.FileCount = len(m.outerManifest.DataFiles) + len(m.outerManifest.MetadataFiles) +
		len(m.outerManifest.ParityFiles) + 1 // +1 for inner manifest

	// Save outer manifest
	outerPath := filepath.Join(m.config.ParityDir, OuterManifestName)
	outerData, err := json.MarshalIndent(m.outerManifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal outer manifest: %w", err)
	}

	if err := os.WriteFile(outerPath, outerData, 0644); err != nil {
		return fmt.Errorf("failed to write outer manifest: %w", err)
	}

	log.Println("Outer manifest created")
	return nil
}

// check performs quick verification using MD5 sums
func (m *Manager) check() error {
	fmt.Println("Running quick integrity check...")

	// Load outer manifest
	outerPath := filepath.Join(m.config.ParityDir, OuterManifestName)
	outerData, err := os.ReadFile(outerPath)
	if err != nil {
		return fmt.Errorf("failed to read outer manifest: %w", err)
	}

	var manifest OuterManifest
	if err := json.Unmarshal(outerData, &manifest); err != nil {
		return fmt.Errorf("failed to parse outer manifest: %w", err)
	}

	errors := 0
	verified := 0
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Verify function
	verifyFile := func(entry FileEntry, basePath string) {
		defer wg.Done()

		filePath := filepath.Join(basePath, entry.Path)
		md5sum, err := calculateMD5(filePath)
		if err != nil {
			mu.Lock()
			log.Printf("Error reading %s: %v", entry.Path, err)
			errors++
			mu.Unlock()
			return
		}

		if md5sum != entry.MD5 {
			mu.Lock()
			log.Printf("MD5 mismatch: %s", entry.Path)
			errors++
			mu.Unlock()
			return
		}

		mu.Lock()
		verified++
		mu.Unlock()
	}

	// Verify inner manifest
	wg.Add(1)
	go verifyFile(manifest.InnerManifest, m.config.ParityDir)

	// Verify metadata files
	for _, file := range manifest.MetadataFiles {
		wg.Add(1)
		go verifyFile(file, m.config.ParityDir)
	}

	// Verify data files
	for _, file := range manifest.DataFiles {
		wg.Add(1)
		go verifyFile(file, m.config.RepoPath)
	}

	// Verify parity files (download from remote if needed)
	if m.config.RcloneRemote != "" && errors == 0 {
		// Download parity files for verification
		log.Println("Downloading parity files for verification...")
		paritySrc := fmt.Sprintf("%s/.restic/parity/shards/", m.config.RcloneRemote)
		parityDst := filepath.Join(m.config.ParityDir, "shards")

		cmd := exec.Command("rclone", "copy", paritySrc, parityDst)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to download parity files: %v", err)
		}
	}

	for _, file := range manifest.ParityFiles {
		wg.Add(1)
		go verifyFile(file, m.config.ParityDir)
	}

	wg.Wait()

	// Summary for local verification
	fmt.Println("\nLocal verification:")
	if errors == 0 {
		fmt.Printf("  ✓ All %d local files OK\n", verified)
	} else {
		fmt.Printf("  ✗ Found %d local errors\n", errors)
	}

	// Check cloud files
	if m.config.RcloneRemote != "" {
		fmt.Println("\nChecking cloud files...")
		cloudErrors := 0

		// Get file list with checksums from rclone
		cmd := exec.Command("rclone", "lsjson", m.config.RcloneRemote, "--hash", "--recursive")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to list remote files: %w", err)
		}

		var remoteFiles []struct {
			Path   string            `json:"Path"`
			Size   int64             `json:"Size"`
			Hashes map[string]string `json:"Hashes"`
		}

		if err := json.Unmarshal(output, &remoteFiles); err != nil {
			return fmt.Errorf("failed to parse remote file list: %w", err)
		}

		// Build map of remote files
		remoteMap := make(map[string]string)
		for _, f := range remoteFiles {
			if md5, ok := f.Hashes["MD5"]; ok {
				remoteMap[f.Path] = md5
			}
		}

		// Check manifests and parity files
		checkFiles := []FileEntry{manifest.InnerManifest}
		checkFiles = append(checkFiles, manifest.MetadataFiles...)
		checkFiles = append(checkFiles, manifest.ParityFiles...)

		for _, file := range checkFiles {
			remotePath := file.Path
			// Adjust path for files in .restic/parity/
			if !strings.HasPrefix(remotePath, ".restic/") {
				if strings.HasPrefix(remotePath, "shards/") {
					remotePath = ".restic/parity/" + remotePath
				} else {
					remotePath = ".restic/parity/" + remotePath
				}
			}

			if remoteMD5, exists := remoteMap[remotePath]; exists {
				if remoteMD5 != file.MD5 {
					fmt.Printf("  ✗ Cloud MD5 mismatch: %s\n", remotePath)
					cloudErrors++
				}
			} else {
				fmt.Printf("  ✗ Missing in cloud: %s\n", remotePath)
				cloudErrors++
			}
		}

		if cloudErrors == 0 {
			fmt.Println("  ✓ All cloud files OK")
		} else {
			fmt.Printf("  ✗ Found %d cloud errors\n", cloudErrors)
			errors += cloudErrors
		}
	}

	fmt.Println("\nQuick check complete")
	if errors > 0 {
		return fmt.Errorf("verification failed with %d errors", errors)
	}

	return nil
}

// fsck performs deep verification using both MD5 and SHA256
func (m *Manager) fsck() error {
	fmt.Println("Running deep integrity check with SHA256...")

	// Load outer manifest
	outerPath := filepath.Join(m.config.ParityDir, OuterManifestName)
	outerData, err := os.ReadFile(outerPath)
	if err != nil {
		return fmt.Errorf("failed to read outer manifest: %w", err)
	}

	var manifest OuterManifest
	if err := json.Unmarshal(outerData, &manifest); err != nil {
		return fmt.Errorf("failed to parse outer manifest: %w", err)
	}

	errors := 0
	verified := 0

	// Verify function
	verifyFile := func(entry FileEntry, basePath string) error {
		filePath := filepath.Join(basePath, entry.Path)

		log.Printf("Verifying %s...", entry.Path)

		md5sum, sha256sum, err := calculateChecksums(filePath)
		if err != nil {
			return fmt.Errorf("error reading file: %w", err)
		}

		if md5sum != entry.MD5 {
			return fmt.Errorf("MD5 mismatch")
		}

		if sha256sum != entry.SHA256 {
			return fmt.Errorf("SHA256 mismatch")
		}

		return nil
	}

	// Verify inner manifest
	if err := verifyFile(manifest.InnerManifest, m.config.ParityDir); err != nil {
		fmt.Printf("  ✗ Inner manifest verification failed: %v\n", err)
		errors++
	} else {
		verified++
	}

	// Verify metadata files
	for _, file := range manifest.MetadataFiles {
		if err := verifyFile(file, m.config.ParityDir); err != nil {
			fmt.Printf("  ✗ Metadata file %s verification failed: %v\n", file.Path, err)
			errors++
		} else {
			verified++
		}
	}

	// Verify data files
	totalFiles := len(manifest.DataFiles)
	for i, file := range manifest.DataFiles {
		if err := verifyFile(file, m.config.RepoPath); err != nil {
			fmt.Printf("  ✗ %s: %v\n", file.Path, err)
			errors++
		} else {
			verified++
		}

		// Show progress every 100 files
		if (i+1)%100 == 0 || i+1 == totalFiles {
			fmt.Printf("  Checked %d/%d files...\n", i+1, totalFiles)
		}
	}

	// Download and verify parity files if using remote
	if m.config.RcloneRemote != "" {
		fmt.Println("\nDownloading parity files for full verification...")
		paritySrc := fmt.Sprintf("%s/.restic/parity/shards/", m.config.RcloneRemote)
		parityDst := filepath.Join(m.config.ParityDir, "shards")

		cmd := exec.Command("rclone", "copy", paritySrc, parityDst, "--progress")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("  Warning: failed to download parity files: %v\n", err)
		}
	}

	// Verify parity files
	fmt.Println("\nVerifying parity files...")
	for _, file := range manifest.ParityFiles {
		if err := verifyFile(file, m.config.ParityDir); err != nil {
			fmt.Printf("  ✗ Parity file %s verification failed: %v\n", file.Path, err)
			errors++
		} else {
			verified++
		}
	}

	if errors == 0 {
		fmt.Printf("\n✓ All %d files verified successfully\n", verified)
	} else {
		fmt.Printf("\n✗ Found %d errors in %d files\n", errors, verified)
		return fmt.Errorf("verification failed with %d errors", errors)
	}

	return nil
}

// Recover handles file recovery
func (m *Manager) Recover() error {
	log.Println("Starting recovery process...")

	// Try to load inner manifest
	innerPath := filepath.Join(m.config.ParityDir, InnerManifestName)
	innerData, err := os.ReadFile(innerPath)

	if err != nil {
		log.Println("Inner manifest missing, will recover it from parity...")
		if err := m.recoverFromParity(); err != nil {
			return fmt.Errorf("failed to recover from parity: %w", err)
		}

		// Reload inner manifest
		innerData, err = os.ReadFile(innerPath)
		if err != nil {
			return fmt.Errorf("failed to read recovered inner manifest: %w", err)
		}
	}

	if err := json.Unmarshal(innerData, &m.innerManifest); err != nil {
		return fmt.Errorf("failed to parse inner manifest: %w", err)
	}

	// Extract erasure scheme from inner manifest
	m.scheme = m.innerManifest.ErasureScheme

	// Continue with normal recovery
	if m.config.Recover != "" {
		return m.recoverSpecificFile(m.config.Recover)
	} else if m.config.RecoverAll {
		return m.recoverAllMissingFiles()
	}

	return nil
}

// recoverFromParity recovers missing files including manifests from parity
func (m *Manager) recoverFromParity() error {
	log.Println("Recovering from parity shards...")

	// We need the outer manifest to know the structure
	outerPath := filepath.Join(m.config.ParityDir, OuterManifestName)
	outerData, err := os.ReadFile(outerPath)
	if err != nil {
		return fmt.Errorf("outer manifest required for recovery: %w", err)
	}

	var outerManifest OuterManifest
	if err := json.Unmarshal(outerData, &outerManifest); err != nil {
		return fmt.Errorf("failed to parse outer manifest: %w", err)
	}

	// Load inner manifest to get erasure scheme
	innerPath := filepath.Join(m.config.ParityDir, InnerManifestName)
	innerData, _ := os.ReadFile(innerPath)

	var tempScheme *ErasureScheme
	if innerData != nil {
		var innerManifest InnerManifest
		if err := json.Unmarshal(innerData, &innerManifest); err == nil {
			tempScheme = innerManifest.ErasureScheme
		}
	}

	if tempScheme == nil {
		// Try to infer from outer manifest
		dataCount := len(outerManifest.DataFiles) + len(outerManifest.MetadataFiles) + 1 // +1 for inner manifest
		parityCount := len(outerManifest.ParityFiles)

		tempScheme = &ErasureScheme{
			DataShards:   dataCount,
			ParityShards: parityCount,
			TotalShards:  dataCount + parityCount,
		}

		// Estimate shard size from parity files
		if len(outerManifest.ParityFiles) > 0 {
			tempScheme.ShardSize = outerManifest.ParityFiles[0].Size
		}
	}

	// Create Reed-Solomon decoder
	dec, err := reedsolomon.New(tempScheme.DataShards, tempScheme.ParityShards)
	if err != nil {
		return fmt.Errorf("failed to create decoder: %w", err)
	}

	// Load all available shards
	shards := make([][]byte, tempScheme.TotalShards)
	shardIndex := 0

	// First shard should be erasure_scheme.json
	schemePath := filepath.Join(m.config.ParityDir, ErasureSchemeName)
	if data, err := os.ReadFile(schemePath); err == nil {
		shards[shardIndex] = make([]byte, tempScheme.ShardSize)
		copy(shards[shardIndex], data)
		log.Printf("Loaded erasure_scheme.json as shard %d", shardIndex)
	} else {
		log.Printf("erasure_scheme.json missing (shard %d): %v", shardIndex, err)
	}
	shardIndex++

	// Second shard should be inner manifest
	if innerData != nil {
		shards[shardIndex] = make([]byte, tempScheme.ShardSize)
		copy(shards[shardIndex], innerData)
	}
	shardIndex++

	// Load repository files in order
	allFiles := append(outerManifest.MetadataFiles, outerManifest.DataFiles...)
	for _, file := range allFiles {
		if file.Path == ErasureSchemeName {
			continue // Already loaded
		}

		// Determine the correct base path for the file
		var filePath string
		if file.Path == "state.json" {
			// state.json is directly in parity directory
			filePath = filepath.Join(m.config.ParityDir, file.Path)
		} else if strings.HasPrefix(file.Path, "parity/") {
			// For files with parity/ prefix, they're actually in the repo
			// This happens when erasure_scheme.json gets listed as parity/erasure_scheme.json
			filePath = filepath.Join(m.config.RepoPath, file.Path)
		} else {
			// Repository files
			filePath = filepath.Join(m.config.RepoPath, file.Path)
		}

		if data, err := os.ReadFile(filePath); err == nil {
			shards[shardIndex] = make([]byte, tempScheme.ShardSize)
			copy(shards[shardIndex], data)
			log.Printf("Loaded file %s as shard %d", file.Path, shardIndex)
		} else {
			log.Printf("File %s missing (shard %d): %v", file.Path, shardIndex, err)
		}
		shardIndex++
	}

	// Load parity shards
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	for i := 0; i < tempScheme.ParityShards; i++ {
		parityPath := filepath.Join(parityDir, fmt.Sprintf("parity_%04d.shard", i))
		if data, err := os.ReadFile(parityPath); err == nil {
			shards[tempScheme.DataShards+i] = data
		}
	}

	// Count available shards for debugging
	availableShards := 0
	for i, shard := range shards {
		if shard != nil {
			availableShards++
		} else {
			log.Printf("Shard %d is missing", i)
		}
	}
	log.Printf("Available shards: %d/%d", availableShards, len(shards))

	// Reconstruct missing shards
	ok, err := dec.Verify(shards)
	if !ok {
		log.Println("Verification failed, attempting reconstruction...")
		if err := dec.Reconstruct(shards); err != nil {
			return fmt.Errorf("failed to reconstruct: %w", err)
		}
		log.Println("Reconstruction successful!")
	}

	// Recover erasure_scheme.json if missing
	if _, err := os.Stat(schemePath); os.IsNotExist(err) {
		log.Println("Recovering erasure_scheme.json...")
		// Find size from outer manifest
		var schemeSize int64
		for _, f := range outerManifest.MetadataFiles {
			if f.Path == ErasureSchemeName {
				schemeSize = f.Size
				break
			}
		}
		if schemeSize > 0 {
			recoveredData := shards[0][:schemeSize]
			if err := os.WriteFile(schemePath, recoveredData, 0644); err != nil {
				return fmt.Errorf("failed to write recovered erasure scheme: %w", err)
			}
		}
	}

	// Recover inner manifest if missing
	if _, err := os.Stat(innerPath); os.IsNotExist(err) {
		log.Println("Recovering inner manifest...")
		innerSize := outerManifest.InnerManifest.Size
		if shards[1] != nil && int64(len(shards[1])) >= innerSize {
			recoveredData := shards[1][:innerSize]
			if err := os.WriteFile(innerPath, recoveredData, 0644); err != nil {
				return fmt.Errorf("failed to write recovered inner manifest: %w", err)
			}
		} else {
			return fmt.Errorf("inner manifest shard is missing or corrupted")
		}
	}

	// Recover missing repository files
	shardIndex = 2 // Start after erasure_scheme and inner manifest

	for _, file := range allFiles {
		if file.Path == ErasureSchemeName {
			continue // Already handled
		}

		// Determine the correct base path for the file
		var filePath string
		if file.Path == "state.json" {
			// state.json is directly in parity directory
			filePath = filepath.Join(m.config.ParityDir, file.Path)
		} else if strings.HasPrefix(file.Path, "parity/") {
			// For files with parity/ prefix, they're actually in the repo
			// This happens when erasure_scheme.json gets listed as parity/erasure_scheme.json
			filePath = filepath.Join(m.config.RepoPath, file.Path)
		} else {
			// Repository files
			filePath = filepath.Join(m.config.RepoPath, file.Path)
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			log.Printf("Recovering file: %s", file.Path)

			// Get recovered data from shard
			if shardIndex < tempScheme.DataShards && shards[shardIndex] != nil {
				recoveredData := shards[shardIndex][:file.Size]

				// Create directory if needed
				dir := filepath.Dir(filePath)
				if err := os.MkdirAll(dir, 0755); err != nil {
					return fmt.Errorf("failed to create directory %s: %w", dir, err)
				}

				// Write recovered file
				if err := os.WriteFile(filePath, recoveredData, 0644); err != nil {
					return fmt.Errorf("failed to write recovered file %s: %w", file.Path, err)
				}
			}
		}
		shardIndex++
	}

	return nil
}

// recoverSpecificFile recovers a specific file
func (m *Manager) recoverSpecificFile(targetFile string) error {
	// Implementation would be similar to before but using the proper shard ordering
	log.Printf("Recovering specific file: %s", targetFile)

	// Create decoder
	_, err := reedsolomon.New(m.scheme.DataShards, m.scheme.ParityShards)
	if err != nil {
		return fmt.Errorf("failed to create decoder: %w", err)
	}

	// Load shards and recover as before...
	// (Similar implementation to recoverFromParity but for specific file)

	return fmt.Errorf("specific file recovery not yet fully implemented")
}

// recoverAllMissingFiles recovers all missing files
func (m *Manager) recoverAllMissingFiles() error {
	log.Println("Recovering all missing files...")

	// Use recoverFromParity which handles all files
	return m.recoverFromParity()
}

// UploadToRemote uploads backup to rclone remote
func (m *Manager) UploadToRemote() error {
	log.Printf("Uploading to remote: %s", m.config.RcloneRemote)

	// Upload all files
	files := []string{
		InnerManifestName,
		OuterManifestName,
		ErasureSchemeName,
	}

	for _, file := range files {
		src := filepath.Join(m.config.ParityDir, file)
		dst := fmt.Sprintf("%s/.restic/parity/", m.config.RcloneRemote)

		cmd := exec.Command("rclone", "copy", src, dst)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to upload %s: %v", file, err)
		}
	}

	// Upload parity directory
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	parityDst := fmt.Sprintf("%s/.restic/parity/shards/", m.config.RcloneRemote)

	cmd := exec.Command("rclone", "copy", parityDir, parityDst, "--progress")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to upload parity files: %w", err)
	}

	log.Println("Remote upload completed")
	return nil
}

// PrintSummary prints operation summary
func (m *Manager) PrintSummary() {
	fmt.Println("\n=== Erasure Coding Summary ===")
	fmt.Printf("Repository: %s\n", m.config.RepoPath)

	if m.innerManifest != nil {
		fmt.Printf("Files protected: %d\n", m.innerManifest.FileCount)
		fmt.Printf("Total data size: %.2f GB\n", float64(m.innerManifest.TotalSize)/(1024*1024*1024))
	}

	if m.scheme != nil {
		fmt.Printf("Parity shards: %d\n", m.scheme.ParityShards)
		fmt.Printf("Can recover from: up to %d missing files\n", m.scheme.CanRecover)
		fmt.Printf("File overhead: %.1f%%\n", m.scheme.FileOverhead)
		fmt.Printf("Size overhead: ~%.1f%%\n", m.scheme.SizeOverhead)
	}

	if m.config.RcloneRemote != "" {
		fmt.Printf("Remote: %s\n", m.config.RcloneRemote)
	}

	if m.config.KeepTemp {
		fmt.Printf("Temporary files kept in: %s\n", m.config.WorkDir)
	}

	fmt.Println("\nFiles created:")
	fmt.Printf("  - %s: Erasure coding parameters (protected)\n", ErasureSchemeName)
	fmt.Printf("  - %s: Repository files with checksums\n", InnerManifestName)
	fmt.Printf("  - %s: Complete backup including parity\n", OuterManifestName)
	fmt.Println("  - parity/: Directory with erasure code blocks")
}

// Helper functions

func calculateChecksums(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()

	// Use io.MultiWriter to calculate both hashes in one pass
	multiWriter := io.MultiWriter(md5Hash, sha256Hash)

	if _, err := io.Copy(multiWriter, file); err != nil {
		return "", "", err
	}

	return hex.EncodeToString(md5Hash.Sum(nil)),
		hex.EncodeToString(sha256Hash.Sum(nil)), nil
}

func calculateMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func printHelp() {
	fmt.Printf(`backup v%s - Restic Backup Manager with Erasure Coding

Usage:
  backup [command] [options]

Commands:
  (no command)    Run full pipeline: snapshot → parity → sync → check
  snapshot        Create restic snapshot
  parity          Generate/update erasure codes (incremental)
  sync            Sync parity files to cloud storage
  check           Quick check: file presence + MD5 (local & cloud)
  fsck            Deep verification with SHA256 checksums
  restore <path>  Restore backup to specified path

Global Options:
  -repo <path>     Override $RESTIC_REPOSITORY
  -remote <remote> Rclone remote (default: "gdrive:backup")
  -overhead <pct>  Erasure coding overhead (default: 10%%)

Examples:
  # Full backup with verification
  backup

  # Just create restic snapshot
  backup snapshot

  # Update erasure codes (incremental)
  backup parity

  # Sync to Google Drive
  backup sync

  # Quick health check
  backup check

  # Deep integrity check
  backup fsck

  # Restore to new location
  backup restore /tmp/restored-backup

Storage Layout:
  .restic/
  └── parity/               # Erasure coding data
      ├── state.json        # Tracks processed files
      ├── erasure_scheme.json
      ├── INNER_MANIFEST.json
      ├── OUTER_MANIFEST.json
      └── shards/           # Parity files

The tool provides automatic protection against data loss through
incremental erasure coding that integrates with your restic repository.

`, Version)
}

func main() {
	// Define flags
	config := &Config{
		RcloneRemote: "gdrive:backup", // Default remote
	}

	flag.StringVar(&config.RepoPath, "repo", "", "Override RESTIC_REPOSITORY path")
	flag.StringVar(&config.RcloneRemote, "remote", "gdrive:backup", "Rclone remote destination")
	flag.Float64Var(&config.MinOverhead, "overhead", 0.10, "Minimum overhead percentage")
	flag.BoolVar(&config.KeepTemp, "keep-temp", false, "Keep temporary files")

	// Custom usage
	flag.Usage = printHelp

	flag.Parse()

	// Get repository path from environment or flag
	if config.RepoPath == "" {
		config.RepoPath = os.Getenv("RESTIC_REPOSITORY")
		if config.RepoPath == "" {
			fmt.Println("Error: No repository specified. Set RESTIC_REPOSITORY or use -repo")
			os.Exit(1)
		}
	}

	// Get command
	args := flag.Args()
	command := ""
	if len(args) > 0 {
		command = args[0]
	}

	// Create manager
	manager := NewManager(config)

	// Set up parity directory
	config.ParityDir = filepath.Join(config.RepoPath, "parity")
	if err := manager.loadState(); err != nil {
		log.Printf("Warning: failed to load state: %v", err)
	}

	// Handle commands
	switch command {
	case "", "all": // Default: full pipeline
		// 1. Create snapshot
		if err := runSnapshot(config.RepoPath); err != nil {
			log.Fatal(err)
		}
		// 2. Generate parity (incremental)
		if err := manager.generateParity(); err != nil {
			log.Fatal(err)
		}
		// 3. Sync to remote
		if err := manager.syncToRemote(); err != nil {
			log.Fatal(err)
		}
		// 4. Run check
		if err := manager.check(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("\nBackup complete!")

	case "snapshot":
		if err := runSnapshot(config.RepoPath); err != nil {
			log.Fatal(err)
		}

	case "parity":
		if err := manager.generateParity(); err != nil {
			log.Fatal(err)
		}

	case "sync":
		if err := manager.syncToRemote(); err != nil {
			log.Fatal(err)
		}

	case "check":
		if err := manager.check(); err != nil {
			log.Fatal(err)
		}

	case "fsck":
		if err := manager.fsck(); err != nil {
			log.Fatal(err)
		}

	case "restore":
		if len(args) < 2 {
			fmt.Println("Error: restore requires a destination path")
			fmt.Println("Usage: backup restore <path>")
			os.Exit(1)
		}
		restorePath := args[1]
		if err := manager.restoreToPath(restorePath); err != nil {
			log.Fatal(err)
		}

	case "help", "-h", "--help":
		printHelp()
		os.Exit(0)

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printHelp()
		os.Exit(1)
	}
}

// Helper functions for subcommands

func runSnapshot(repoPath string) error {
	fmt.Println("Creating restic snapshot...")

	// Default to backing up home directory with exclusions
	backupPath := os.Getenv("HOME")
	excludeFile := filepath.Join(os.Getenv("HOME"), ".resticignore")

	args := []string{"backup", backupPath}
	if _, err := os.Stat(excludeFile); err == nil {
		args = append(args, "--exclude-file", excludeFile)
	}

	cmd := exec.Command("restic", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("RESTIC_REPOSITORY=%s", repoPath))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restic snapshot failed: %w", err)
	}

	fmt.Println("Snapshot created successfully")
	return nil
}

func (m *Manager) generateParity() error {
	fmt.Println("Generating erasure codes (incremental)...")

	// Ensure parity directory exists
	if err := os.MkdirAll(m.config.ParityDir, 0755); err != nil {
		return fmt.Errorf("failed to create parity directory: %w", err)
	}

	// Calculate erasure scheme
	if err := m.CalculateErasureSchemeIncremental(); err != nil {
		return fmt.Errorf("erasure scheme calculation failed: %w", err)
	}

	// Create inner manifest
	if err := m.CreateInnerManifestIncremental(); err != nil {
		return fmt.Errorf("inner manifest creation failed: %w", err)
	}

	// Generate erasure codes (only for new/changed files)
	if err := m.GenerateErasureCodesIncremental(); err != nil {
		return fmt.Errorf("erasure code generation failed: %w", err)
	}

	// Create outer manifest
	if err := m.CreateOuterManifestIncremental(); err != nil {
		return fmt.Errorf("outer manifest creation failed: %w", err)
	}

	// Save state
	if err := m.saveState(); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	m.PrintSummary()
	return nil
}

func (m *Manager) loadState() error {
	statePath := filepath.Join(m.config.ParityDir, "state.json")

	// Initialize empty state if file doesn't exist
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		m.state = &State{
			Version:        Version,
			LastProcessed:  time.Time{},
			ProcessedFiles: make(map[string]string),
			ParityShards:   []string{},
		}
		return nil
	}

	// Load existing state
	data, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("failed to read state: %w", err)
	}

	state := &State{}
	if err := json.Unmarshal(data, state); err != nil {
		return fmt.Errorf("failed to parse state: %w", err)
	}

	m.state = state
	return nil
}

func (m *Manager) saveState() error {
	// Ensure parity directory exists
	if err := os.MkdirAll(m.config.ParityDir, 0755); err != nil {
		return fmt.Errorf("failed to create parity directory: %w", err)
	}

	// Update timestamp
	m.state.LastProcessed = time.Now()

	// Marshal state
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Write to file
	statePath := filepath.Join(m.config.ParityDir, "state.json")
	if err := os.WriteFile(statePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write state: %w", err)
	}

	return nil
}

func (m *Manager) syncToRemote() error {
	fmt.Println("Syncing parity files to remote...")

	// Sync entire parity directory
	src := m.config.ParityDir
	dst := fmt.Sprintf("%s/.restic/parity/", m.config.RcloneRemote)

	cmd := exec.Command("rclone", "sync", src, dst, "--progress")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to sync parity files: %w", err)
	}

	fmt.Println("Sync completed successfully")
	return nil
}

func (m *Manager) restoreToPath(restorePath string) error {
	fmt.Printf("Restoring backup to %s...\n", restorePath)

	// Download necessary files
	if err := m.downloadForRecovery(); err != nil {
		return fmt.Errorf("failed to download recovery files: %w", err)
	}

	// Set up recovery
	m.config.RecoverAll = true

	// Create restore directory
	if err := os.MkdirAll(restorePath, 0755); err != nil {
		return fmt.Errorf("failed to create restore directory: %w", err)
	}

	// Load manifests and recover
	if err := m.Recover(); err != nil {
		return fmt.Errorf("recovery failed: %w", err)
	}

	// Restore restic repository
	fmt.Println("Restoring restic repository...")
	resticRestorePath := filepath.Join(restorePath, ".restic")

	cmd := exec.Command("rsync", "-av", m.config.RepoPath+"/", resticRestorePath+"/")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restore restic repository: %w", err)
	}

	fmt.Printf("\nRestore complete! Repository available at: %s\n", resticRestorePath)
	return nil
}

// init ensures required packages are available
func init() {
	// This would normally be in go.mod but for single file usage:
	// go get github.com/klauspost/reedsolomon
}
