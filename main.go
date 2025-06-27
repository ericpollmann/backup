package main

import (
	"archive/zip"
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
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
	"golang.org/x/term"
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
	SHA256 string `json:"sha256,omitempty"` // Only for non-restic files
	Type   string `json:"type"`             // "data", "parity", "manifest", "metadata"
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
	MetadataDir     string // Metadata directory (.restic/metadata)
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
	Quiet           bool   // Force simple progress mode
	NoProgress      bool   // Disable all progress output
}

// ProgressTracker handles progress display
type ProgressTracker struct {
	isTerminal  bool
	useAdvanced bool
	currentTask string
	totalItems  int
	currentItem int
	startTime   time.Time
	mu          sync.Mutex
	quiet       bool
	noProgress  bool
}

// Manager handles the complete workflow
type Manager struct {
	config        *Config
	state         *State
	innerManifest *InnerManifest
	outerManifest *OuterManifest
	scheme        *ErasureScheme
	progress      *ProgressTracker
}

func NewManager(config *Config) *Manager {
	// Check if we're in a terminal
	isTerminal := term.IsTerminal(int(os.Stdout.Fd()))
	useAdvanced := isTerminal && !config.Quiet

	progress := &ProgressTracker{
		isTerminal:  isTerminal,
		useAdvanced: useAdvanced,
		quiet:       config.Quiet,
		noProgress:  config.NoProgress,
		startTime:   time.Now(),
	}

	return &Manager{
		config:   config,
		progress: progress,
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

	// Ensure metadata directory exists
	if err := os.MkdirAll(m.config.MetadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}

	files := []string{OuterManifestName, InnerManifestName, ErasureSchemeName}
	for _, file := range files {
		src := fmt.Sprintf("%s/.restic/parity/%s", m.config.RcloneRemote, file)
		dst := m.config.ParityDir

		cmd := exec.Command(getRclonePath(), "copy", src, dst)
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

	// Ensure metadata directory exists
	if err := os.MkdirAll(m.config.MetadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
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

		cmd := exec.Command(getRclonePath(), "copy", src, dst)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to download %s: %v", file, err)
		}
	}

	// Download parity shards
	paritySrc := fmt.Sprintf("%s/.restic/parity/shards/", m.config.RcloneRemote)
	parityDst := filepath.Join(m.config.ParityDir, "shards")

	cmd := exec.Command(getRclonePath(), "copy", paritySrc, parityDst, "--progress")
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

	if err := runResticCommand(m.config.RepoPath, args...); err != nil {
		return fmt.Errorf("restic backup failed: %w", err)
	}

	log.Println("Restic backup completed")
	return nil
}

// CalculateErasureScheme determines the erasure coding parameters
func (m *Manager) CalculateErasureScheme() error {
	m.progress.StartTask("Calculating erasure scheme", 0)

	// Scan only data directory to count pack files
	dataFileCount := 0
	var maxDataFileSize int64

	dataDir := filepath.Join(m.config.RepoPath, "data")
	err := filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			dataFileCount++
			if info.Size() > maxDataFileSize {
				maxDataFileSize = info.Size()
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error scanning data directory: %w", err)
	}

	// Estimate metadata zip size (all non-data files compressed)
	var metadataSize int64
	metadataDirs := []string{"config", "index", "keys", "locks", "snapshots"}
	for _, dir := range metadataDirs {
		dirPath := filepath.Join(m.config.RepoPath, dir)
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				metadataSize += info.Size()
			}
			return nil
		})
	}
	// Estimate compressed size as ~50% of original + manifest overhead
	estimatedMetadataZipSize := metadataSize/2 + int64(dataFileCount*300) + 10000

	// Total shards = data files + 1 metadata zip
	totalFiles := dataFileCount + 1
	minParityShards := int(math.Ceil(float64(totalFiles) * m.config.MinOverhead))

	// Ensure minimum of 3 parity shards
	if minParityShards < 3 {
		minParityShards = 3
	}

	// Use the larger of max data file or estimated metadata zip
	maxFileSize := maxDataFileSize
	if estimatedMetadataZipSize > maxFileSize {
		maxFileSize = estimatedMetadataZipSize
	}

	// Add some padding to ensure we have enough space
	maxFileSize = int64(float64(maxFileSize) * 1.2)

	m.scheme = &ErasureScheme{
		DataShards:   totalFiles,
		ParityShards: minParityShards,
		TotalShards:  totalFiles + minParityShards,
		ShardSize:    maxFileSize,
		FileOverhead: float64(minParityShards) / float64(totalFiles) * 100,
		SizeOverhead: m.config.MinOverhead * 100,
		CanRecover:   minParityShards,
	}

	m.progress.CompleteTask(fmt.Sprintf("Erasure scheme: %d data + %d parity shards, shard size: %d bytes",
		m.scheme.DataShards, m.scheme.ParityShards, m.scheme.ShardSize))

	return nil
}

// createMetadataZip creates a zip of all non-data files and returns its path and SHA256
func (m *Manager) createMetadataZip() (string, string, error) {
	// Create temp file for the zip
	tempFile, err := os.CreateTemp(m.config.WorkDir, "metadata-*.zip")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()
	tempPath := tempFile.Name()

	// Create zip writer
	zipWriter := zip.NewWriter(tempFile)

	// Add restic metadata directories (everything except data and our metadata/parity dirs)
	dirs := []string{"config", "index", "keys", "locks", "snapshots"}
	for _, dir := range dirs {
		dirPath := filepath.Join(m.config.RepoPath, dir)
		if _, err := os.Stat(dirPath); err != nil {
			continue // Skip if directory doesn't exist
		}

		// Walk directory and add all files
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}

			// Get relative path for zip entry
			relPath, err := filepath.Rel(m.config.RepoPath, path)
			if err != nil {
				return err
			}

			// Create zip entry
			writer, err := zipWriter.Create(relPath)
			if err != nil {
				return err
			}

			// Copy file contents
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(writer, file)
			return err
		})

		if err != nil {
			zipWriter.Close()
			os.Remove(tempPath)
			return "", "", fmt.Errorf("failed to add %s to zip: %w", dir, err)
		}
	}

	// Add the manifest and erasure scheme from metadata dir
	metadataFiles := []struct {
		path string
		name string
	}{
		{filepath.Join(m.config.MetadataDir, InnerManifestName), "metadata/" + InnerManifestName},
		{filepath.Join(m.config.MetadataDir, ErasureSchemeName), "metadata/" + ErasureSchemeName},
	}

	for _, mf := range metadataFiles {
		writer, err := zipWriter.Create(mf.name)
		if err != nil {
			zipWriter.Close()
			os.Remove(tempPath)
			return "", "", fmt.Errorf("failed to create zip entry for %s: %w", mf.name, err)
		}

		file, err := os.Open(mf.path)
		if err != nil {
			zipWriter.Close()
			os.Remove(tempPath)
			return "", "", fmt.Errorf("failed to open %s: %w", mf.path, err)
		}

		_, err = io.Copy(writer, file)
		file.Close()
		if err != nil {
			zipWriter.Close()
			os.Remove(tempPath)
			return "", "", fmt.Errorf("failed to write %s to zip: %w", mf.name, err)
		}
	}

	// Close zip writer
	if err := zipWriter.Close(); err != nil {
		os.Remove(tempPath)
		return "", "", fmt.Errorf("failed to close zip: %w", err)
	}

	// Calculate SHA256 of the zip
	tempFile.Seek(0, 0)
	hash := sha256.New()
	if _, err := io.Copy(hash, tempFile); err != nil {
		os.Remove(tempPath)
		return "", "", fmt.Errorf("failed to calculate SHA256: %w", err)
	}
	sha256sum := hex.EncodeToString(hash.Sum(nil))

	// Close temp file before rename
	tempFile.Close()

	// Move to final location with SHA256 name
	finalPath := filepath.Join(m.config.MetadataDir, sha256sum)

	// Copy file instead of rename to handle cross-device moves
	if err := copyFile(tempPath, finalPath); err != nil {
		os.Remove(tempPath)
		return "", "", fmt.Errorf("failed to move zip to final location: %w", err)
	}

	// Remove temp file after successful copy
	os.Remove(tempPath)

	return finalPath, sha256sum, nil
}

// CreateInnerManifest scans repository and creates inner manifest with parallel processing
func (m *Manager) CreateInnerManifest() error {
	log.Println("Creating inner manifest...")

	// Ensure metadata directory exists
	if err := os.MkdirAll(m.config.MetadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}

	// First, save the erasure scheme file
	schemePath := filepath.Join(m.config.MetadataDir, ErasureSchemeName)
	schemeData, err := json.MarshalIndent(m.scheme, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal erasure scheme: %w", err)
	}

	if err := os.WriteFile(schemePath, schemeData, 0644); err != nil {
		return fmt.Errorf("failed to write erasure scheme: %w", err)
	}

	// Create inner manifest
	m.innerManifest = &InnerManifest{
		Version:       Version,
		Created:       time.Now(),
		RepoPath:      m.config.RepoPath,
		Files:         make([]FileEntry, 0),
		ErasureScheme: m.scheme,
	}

	// Collect only data files from the data directory
	var filesToProcess []fileWorkUnit

	dataDir := filepath.Join(m.config.RepoPath, "data")
	err = filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(m.config.RepoPath, path)
			if err != nil {
				return err
			}

			filesToProcess = append(filesToProcess, fileWorkUnit{
				path:    path,
				info:    info,
				relPath: relPath,
			})
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error scanning repository: %w", err)
	}

	// Process files in parallel
	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8 // Cap at 8 workers to avoid too many open files
	}

	workChan := make(chan fileWorkUnit, numWorkers*2)
	resultChan := make(chan fileResultUnit, numWorkers*2)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go m.manifestWorker(&wg, workChan, resultChan)
	}

	// Start result collector
	collectorDone := make(chan bool)
	go func() {
		for result := range resultChan {
			if result.err != nil {
				log.Printf("Warning: couldn't process %s: %v", result.entry.Path, result.err)
				continue
			}
			m.innerManifest.Files = append(m.innerManifest.Files, result.entry)
			m.innerManifest.TotalSize += result.entry.Size
		}
		collectorDone <- true
	}()

	// Send work
	m.progress.StartTask("Processing repository files", len(filesToProcess))
	for i, work := range filesToProcess {
		workChan <- work
		if i%100 == 0 {
			m.progress.UpdateProgress(i, fmt.Sprintf("Processing %s", filepath.Base(work.relPath)))
		}
	}
	close(workChan)

	// Wait for workers to finish
	wg.Wait()
	close(resultChan)
	<-collectorDone

	m.progress.CompleteTask(fmt.Sprintf("Processed %d files", len(filesToProcess)))

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
	manifestPath := filepath.Join(m.config.MetadataDir, InnerManifestName)
	manifestData, err := json.MarshalIndent(m.innerManifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal inner manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return fmt.Errorf("failed to write inner manifest: %w", err)
	}

	log.Printf("Inner manifest created: %d data files, %.2f GB total",
		m.innerManifest.FileCount,
		float64(m.innerManifest.TotalSize)/(1024*1024*1024))

	return nil
}

// manifestWorker processes files for manifest creation
func (m *Manager) manifestWorker(wg *sync.WaitGroup, work <-chan fileWorkUnit, results chan<- fileResultUnit) {
	defer wg.Done()

	for unit := range work {
		// Check if this is a restic data file (in data/ directory with hex name)
		isResticData := strings.HasPrefix(unit.relPath, "data/") &&
			len(filepath.Base(unit.relPath)) >= 10 // Restic uses long hex names

		var md5sum string
		var err error

		if isResticData {
			// For restic data files, only calculate MD5
			md5sum, err = calculateMD5Only(unit.path)
			if err != nil {
				results <- fileResultUnit{
					entry: FileEntry{Path: unit.relPath},
					err:   fmt.Errorf("failed to calculate MD5: %w", err),
				}
				continue
			}
		} else {
			// For other files (config, index, keys, etc), calculate both
			var sha256sum string
			md5sum, sha256sum, err = calculateChecksums(unit.path)
			if err != nil {
				results <- fileResultUnit{
					entry: FileEntry{Path: unit.relPath},
					err:   fmt.Errorf("failed to calculate checksums: %w", err),
				}
				continue
			}

			results <- fileResultUnit{
				entry: FileEntry{
					Path:   unit.relPath,
					Size:   unit.info.Size(),
					MD5:    md5sum,
					SHA256: sha256sum,
					Type:   "data",
				},
			}
			continue
		}

		// For restic data files
		results <- fileResultUnit{
			entry: FileEntry{
				Path: unit.relPath,
				Size: unit.info.Size(),
				MD5:  md5sum,
				Type: "data",
			},
		}
	}
}

// fileWorkUnit represents a file to process for manifest creation
type fileWorkUnit struct {
	path    string
	info    os.FileInfo
	relPath string
}

// fileResultUnit contains the processed file entry
type fileResultUnit struct {
	entry FileEntry
	err   error
}

// Work unit for parallel erasure encoding
type encodeWorkUnit struct {
	index  int      // Chunk index (0, 1, 2, ...)
	offset int64    // File offset for this chunk
	data   [][]byte // Data shards for this chunk
}

// Result unit with encoded parity
type encodeResultUnit struct {
	index  int      // Chunk index to maintain order
	parity [][]byte // Parity shards for this chunk
}

// GenerateErasureCodesChunked creates parity shards using parallel chunk processing
func (m *Manager) GenerateErasureCodesChunked() error {
	const chunkSize = 64 * 1024 // 64KB chunks
	numCPU := runtime.NumCPU()

	m.progress.StartTask("Preparing erasure coding", 0)

	// Create metadata zip first
	log.Println("Creating metadata archive...")
	metadataZipPath, metadataZipSHA256, err := m.createMetadataZip()
	if err != nil {
		return fmt.Errorf("failed to create metadata zip: %w", err)
	}
	log.Printf("Created metadata archive: %s", metadataZipSHA256)

	// Collect all files to process
	var filePaths []string

	// Add all data files from the manifest
	for _, file := range m.innerManifest.Files {
		filePath := filepath.Join(m.config.RepoPath, file.Path)
		filePaths = append(filePaths, filePath)
	}

	// Add the metadata zip as the last shard
	filePaths = append(filePaths, metadataZipPath)

	// Pad to match data shards count
	for len(filePaths) < m.scheme.DataShards {
		filePaths = append(filePaths, "") // Empty files for padding
	}

	// Ensure we don't exceed data shards count
	if len(filePaths) > m.scheme.DataShards {
		log.Printf("Warning: filePaths (%d) exceeds DataShards (%d), truncating", len(filePaths), m.scheme.DataShards)
		filePaths = filePaths[:m.scheme.DataShards]
	}

	// Determine maximum file size for total chunks
	var maxSize int64
	for _, path := range filePaths {
		if path != "" {
			if info, err := os.Stat(path); err == nil && info.Size() > maxSize {
				maxSize = info.Size()
			}
		}
	}
	totalChunks := int((maxSize + chunkSize - 1) / chunkSize)

	// Create channels for pipeline
	workChan := make(chan encodeWorkUnit, numCPU*2)
	resultChan := make(chan encodeResultUnit, numCPU*2)

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go m.erasureWorker(chunkSize, &wg, workChan, resultChan)
	}

	// Start result writer
	writerDone := make(chan error, 1)
	go m.parityWriter(totalChunks, chunkSize, resultChan, writerDone)

	// Start task producer
	m.progress.StartTask("Processing chunks", totalChunks)
	go func() {
		for chunkIdx := 0; chunkIdx < totalChunks; chunkIdx++ {
			offset := int64(chunkIdx) * chunkSize

			// Read chunk from each file
			dataChunks := make([][]byte, m.scheme.DataShards)
			for i := 0; i < m.scheme.DataShards && i < len(filePaths); i++ {
				if i >= len(filePaths) || filePaths[i] == "" {
					dataChunks[i] = make([]byte, chunkSize)
				} else {
					dataChunks[i] = m.readChunk(filePaths[i], offset, chunkSize)
				}
			}

			workChan <- encodeWorkUnit{
				index:  chunkIdx,
				offset: offset,
				data:   dataChunks,
			}

			m.progress.UpdateProgress(chunkIdx+1, fmt.Sprintf("Chunk %d/%d", chunkIdx+1, totalChunks))
		}
		close(workChan)
	}()

	// Wait for workers to finish
	wg.Wait()
	close(resultChan)

	// Wait for writer to finish
	if err := <-writerDone; err != nil {
		return err
	}

	m.progress.CompleteTask(fmt.Sprintf("Processed %d chunks", totalChunks))
	return nil
}

// erasureWorker processes chunks in parallel
func (m *Manager) erasureWorker(chunkSize int64, wg *sync.WaitGroup, work <-chan encodeWorkUnit, results chan<- encodeResultUnit) {
	defer wg.Done()

	// Create encoder - klauspost library automatically uses NEON on M1
	enc, err := reedsolomon.New(m.scheme.DataShards, m.scheme.ParityShards)
	if err != nil {
		m.progress.Error("Failed to create encoder: %v", err)
		return
	}

	for unit := range work {
		// Prepare shards array with data and space for parity
		shards := make([][]byte, m.scheme.DataShards+m.scheme.ParityShards)
		copy(shards, unit.data)

		// Allocate parity shards
		for i := m.scheme.DataShards; i < len(shards); i++ {
			shards[i] = make([]byte, chunkSize)
		}

		// Encode - this uses SIMD optimizations automatically
		if err := enc.Encode(shards); err != nil {
			m.progress.Error("Encoding failed for chunk %d: %v", unit.index, err)
			continue
		}

		// Send only parity shards as result
		results <- encodeResultUnit{
			index:  unit.index,
			parity: shards[m.scheme.DataShards:],
		}
	}
}

// parityWriter writes parity chunks in order
func (m *Manager) parityWriter(totalChunks int, chunkSize int64, results <-chan encodeResultUnit, done chan<- error) {
	// Create parity directory
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	if err := os.MkdirAll(parityDir, 0755); err != nil {
		done <- fmt.Errorf("failed to create parity directory: %w", err)
		return
	}

	// Open all parity files
	parityFiles := make([]*os.File, m.scheme.ParityShards)
	for i := 0; i < m.scheme.ParityShards; i++ {
		path := filepath.Join(parityDir, fmt.Sprintf("parity_%04d.shard", i))
		f, err := os.Create(path)
		if err != nil {
			done <- fmt.Errorf("failed to create parity file %d: %w", i, err)
			return
		}
		defer f.Close()
		parityFiles[i] = f
	}

	// Buffer for out-of-order results
	resultBuffer := make(map[int]encodeResultUnit)
	nextIndex := 0

	m.progress.StartTask("Writing parity shards", totalChunks)

	for result := range results {
		resultBuffer[result.index] = result

		// Write all consecutive chunks we can
		for {
			if chunk, ok := resultBuffer[nextIndex]; ok {
				// Write this chunk's parity data
				for i, parityData := range chunk.parity {
					if _, err := parityFiles[i].Write(parityData); err != nil {
						done <- fmt.Errorf("failed to write parity chunk: %w", err)
						return
					}
				}

				delete(resultBuffer, nextIndex)
				nextIndex++

				m.progress.UpdateProgress(nextIndex, fmt.Sprintf("Written chunk %d/%d", nextIndex, totalChunks))
			} else {
				break
			}
		}
	}

	m.progress.CompleteTask(fmt.Sprintf("Created %d parity files", m.scheme.ParityShards))
	done <- nil
}

// readChunk reads a chunk from a file
func (m *Manager) readChunk(path string, offset, size int64) []byte {
	data := make([]byte, size)

	if path == "" {
		return data // Return zeros for padding
	}

	file, err := os.Open(path)
	if err != nil {
		m.progress.Log("Warning: couldn't open %s: %v", path, err)
		return data
	}
	defer file.Close()

	n, err := file.ReadAt(data, offset)
	if err != nil && err != io.EOF {
		m.progress.Log("Warning: couldn't read from %s at offset %d: %v", path, offset, err)
	}

	// Zero-pad if we read less than chunk size
	if n < int(size) {
		for i := n; i < int(size); i++ {
			data[i] = 0
		}
	}

	return data
}

// GenerateErasureCodes creates parity shards using parallel chunk processing
func (m *Manager) GenerateErasureCodes() error {
	// Use the new chunked implementation
	return m.GenerateErasureCodesChunked()
}

// GenerateErasureCodesOld is the old implementation for reference
func (m *Manager) GenerateErasureCodesOld() error {
	m.progress.StartTask("Generating erasure codes", m.scheme.DataShards)

	// Create Reed-Solomon encoder with NEON optimization for M1
	enc, err := reedsolomon.New(m.scheme.DataShards, m.scheme.ParityShards,
		reedsolomon.WithAutoGoroutines(64*1024)) // Auto-optimize for 64KB chunks
	if err != nil {
		return fmt.Errorf("failed to create encoder: %w", err)
	}

	// Prepare data shards (need to allocate space for parity shards too)
	dataShards := make([][]byte, m.scheme.DataShards+m.scheme.ParityShards)
	shardIndex := 0

	// First shard is the erasure scheme
	schemePath := filepath.Join(m.config.MetadataDir, ErasureSchemeName)
	schemeData, err := os.ReadFile(schemePath)
	if err != nil {
		return fmt.Errorf("failed to read erasure scheme: %w", err)
	}
	dataShards[shardIndex] = make([]byte, m.scheme.ShardSize)
	copy(dataShards[shardIndex], schemeData)
	shardIndex++

	// Second shard is the inner manifest
	manifestPath := filepath.Join(m.config.MetadataDir, InnerManifestName)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read inner manifest: %w", err)
	}
	dataShards[shardIndex] = make([]byte, m.scheme.ShardSize)
	copy(dataShards[shardIndex], manifestData)
	shardIndex++

	// Remaining shards are repository files (skip erasure_scheme.json from files list)
	filesProcessed := 2 // Already processed erasure scheme and manifest
	for _, file := range m.innerManifest.Files {
		if file.Path == ErasureSchemeName {
			continue // Already added as first shard
		}

		m.progress.UpdateProgress(filesProcessed, fmt.Sprintf("Loading %s", filepath.Base(file.Path)))
		filesProcessed++

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
			m.progress.Log("Warning: couldn't read %s: %v", filePath, err)
			data = []byte{} // Use empty data for missing files
		}

		if int64(len(data)) > m.scheme.ShardSize {
			return fmt.Errorf("file %s is too large (%d bytes) for shard size %d", file.Path, len(data), m.scheme.ShardSize)
		}

		if shardIndex < m.scheme.DataShards {
			dataShards[shardIndex] = make([]byte, m.scheme.ShardSize)
			copy(dataShards[shardIndex], data)
			shardIndex++
		} else {
			return fmt.Errorf("too many files (%d) for data shards (%d) - scheme needs recalculation", shardIndex+1, m.scheme.DataShards)
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
	m.progress.CompleteTask(fmt.Sprintf("Loaded %d data files", filesProcessed))
	m.progress.StartTask("Encoding parity shards", 1)

	if err := enc.Encode(dataShards); err != nil {
		return fmt.Errorf("failed to encode: %w", err)
	}

	m.progress.CompleteTask("Encoding complete")

	// Save parity shards
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	if err := os.MkdirAll(parityDir, 0755); err != nil {
		return fmt.Errorf("failed to create parity directory: %w", err)
	}

	m.progress.StartTask("Writing parity shards", m.scheme.ParityShards)

	for i := 0; i < m.scheme.ParityShards; i++ {
		m.progress.UpdateProgress(i+1, fmt.Sprintf("parity_%04d.shard", i))

		parityPath := filepath.Join(parityDir, fmt.Sprintf("parity_%04d.shard", i))
		parityData := dataShards[m.scheme.DataShards+i]

		if err := os.WriteFile(parityPath, parityData, 0644); err != nil {
			return fmt.Errorf("failed to write parity shard %d: %w", i, err)
		}
	}

	m.progress.CompleteTask(fmt.Sprintf("Created %d parity shards", m.scheme.ParityShards))
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

	// Add all data files from inner manifest
	m.outerManifest.DataFiles = m.innerManifest.Files

	// Add metadata files (erasure scheme and metadata zip)

	// Add erasure scheme
	schemePath := filepath.Join(m.config.MetadataDir, ErasureSchemeName)
	if info, err := os.Stat(schemePath); err == nil {
		md5sum, sha256sum, err := calculateChecksums(schemePath)
		if err == nil {
			m.outerManifest.MetadataFiles = append(m.outerManifest.MetadataFiles, FileEntry{
				Path:   "metadata/" + ErasureSchemeName,
				Size:   info.Size(),
				MD5:    md5sum,
				SHA256: sha256sum,
				Type:   "metadata",
			})
		}
	}

	// Add metadata zip - find it in metadata directory
	files, err := os.ReadDir(m.config.MetadataDir)
	if err == nil {
		for _, file := range files {
			name := file.Name()
			// Skip manifest and erasure scheme - look for SHA256 named file
			if name != InnerManifestName && name != ErasureSchemeName && len(name) == 64 {
				info, err := file.Info()
				if err == nil {
					zipPath := filepath.Join(m.config.MetadataDir, name)
					md5sum, err := calculateMD5Only(zipPath)
					if err == nil {
						m.outerManifest.MetadataFiles = append(m.outerManifest.MetadataFiles, FileEntry{
							Path:   "metadata/" + name,
							Size:   info.Size(),
							MD5:    md5sum,
							SHA256: name, // The filename IS the SHA256
							Type:   "metadata",
						})
					}
				}
			}
		}
	}

	// Add inner manifest entry
	manifestPath := filepath.Join(m.config.MetadataDir, InnerManifestName)
	md5sum, sha256sum, err := calculateChecksums(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to calculate inner manifest checksums: %w", err)
	}

	manifestInfo, _ := os.Stat(manifestPath)
	m.outerManifest.InnerManifest = FileEntry{
		Path:   "metadata/" + InnerManifestName,
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

	// Ensure parity directory exists
	if err := os.MkdirAll(m.config.ParityDir, 0755); err != nil {
		return fmt.Errorf("failed to create parity directory: %w", err)
	}

	// Ensure metadata directory exists
	if err := os.MkdirAll(m.config.MetadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}

	// Count current files first
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

	// If we have an existing scheme, check if it's still valid
	schemePath := filepath.Join(m.config.MetadataDir, ErasureSchemeName)
	if _, err := os.Stat(schemePath); err == nil {
		data, err := os.ReadFile(schemePath)
		if err != nil {
			return fmt.Errorf("failed to read existing scheme: %w", err)
		}

		scheme := &ErasureScheme{}
		if err := json.Unmarshal(data, scheme); err != nil {
			return fmt.Errorf("failed to parse existing scheme: %w", err)
		}

		// Check if the scheme is still valid for current files
		totalFiles := fileCount + 2 // +2 for inner manifest and erasure scheme
		if scheme.DataShards == totalFiles && scheme.ShardSize >= maxFileSize*2 {
			m.scheme = scheme
			log.Printf("Using existing erasure scheme: %d data + %d parity shards (shard size: %d bytes)",
				scheme.DataShards, scheme.ParityShards, scheme.ShardSize)
			return nil
		}

		log.Printf("Existing scheme outdated (files: %d->%d, max size: %d->%d), recalculating...",
			scheme.DataShards-2, fileCount, scheme.ShardSize/2, maxFileSize)
	}

	// Otherwise calculate new scheme
	return m.CalculateErasureScheme()
}

// CreateInnerManifestIncremental creates manifest for new/changed files
func (m *Manager) CreateInnerManifestIncremental() error {
	m.progress.StartTask("Creating inner manifest (incremental)", 0)

	// Load existing manifest if available
	manifestPath := filepath.Join(m.config.MetadataDir, InnerManifestName)
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

	// First count total files for progress (only in data directory)
	totalFiles := 0
	dataDir := filepath.Join(m.config.RepoPath, "data")
	filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalFiles++
		}
		return nil
	})

	m.progress.StartTask("Scanning data files", totalFiles)

	// Scan only data directory for changes
	var files []FileEntry
	var totalSize int64
	changedFiles := 0
	processedCount := 0

	err := filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			processedCount++

			relPath, err := filepath.Rel(m.config.RepoPath, path)
			if err != nil {
				return err
			}

			// Update progress
			m.progress.UpdateProgress(processedCount, filepath.Base(relPath))

			// Check if file has changed
			needsUpdate := false
			if existing, ok := existingFiles[relPath]; ok {
				// Quick size check first
				if existing.Size != info.Size() {
					needsUpdate = true
				} else {
					// Check MD5 for same-sized files
					md5sum, err := calculateMD5Only(path)
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

				// Check if this is a restic data file
				isResticData := strings.HasPrefix(relPath, "data/") &&
					len(filepath.Base(relPath)) >= 10

				var entry FileEntry
				if isResticData {
					// For restic data files, only calculate MD5
					md5sum, err := calculateMD5Only(path)
					if err != nil {
						return fmt.Errorf("failed to calculate MD5 for %s: %w", path, err)
					}
					entry = FileEntry{
						Path: relPath,
						Size: info.Size(),
						MD5:  md5sum,
						Type: "data",
					}
					// For state tracking, use MD5 instead of SHA256
					m.state.ProcessedFiles[relPath] = md5sum
				} else {
					// For other files, calculate both checksums
					md5sum, sha256sum, err := calculateChecksums(path)
					if err != nil {
						return fmt.Errorf("failed to checksum %s: %w", path, err)
					}
					entry = FileEntry{
						Path:   relPath,
						Size:   info.Size(),
						MD5:    md5sum,
						SHA256: sha256sum,
						Type:   "data",
					}
					m.state.ProcessedFiles[relPath] = sha256sum
				}

				files = append(files, entry)
				totalSize += info.Size()
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error scanning repository: %w", err)
	}

	m.progress.CompleteTask(fmt.Sprintf("Found %d changed files", changedFiles))

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
	manifestPath := filepath.Join(m.config.MetadataDir, InnerManifestName)
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
			Path:   "metadata/" + InnerManifestName,
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
	schemePath := filepath.Join(m.config.MetadataDir, ErasureSchemeName)
	if info, err := os.Stat(schemePath); err == nil {
		md5sum, sha256sum, err := calculateChecksums(schemePath)
		if err != nil {
			return fmt.Errorf("failed to checksum erasure scheme: %w", err)
		}

		m.outerManifest.MetadataFiles = append(m.outerManifest.MetadataFiles, FileEntry{
			Path:   "metadata/" + ErasureSchemeName,
			Size:   info.Size(),
			MD5:    md5sum,
			SHA256: sha256sum,
			Type:   "metadata",
		})
		m.outerManifest.TotalSize += info.Size()
	}

	// Add metadata zip file
	metadataFiles, err := os.ReadDir(m.config.MetadataDir)
	if err == nil {
		for _, file := range metadataFiles {
			if !file.IsDir() && file.Name() != InnerManifestName && file.Name() != ErasureSchemeName {
				// This should be the metadata zip (named by SHA256)
				info, err := file.Info()
				if err != nil {
					continue
				}

				filePath := filepath.Join(m.config.MetadataDir, file.Name())
				md5sum, sha256sum, err := calculateChecksums(filePath)
				if err != nil {
					continue
				}

				m.outerManifest.MetadataFiles = append(m.outerManifest.MetadataFiles, FileEntry{
					Path:   "metadata/" + file.Name(),
					Size:   info.Size(),
					MD5:    md5sum,
					SHA256: sha256sum,
					Type:   "metadata",
				})
				m.outerManifest.TotalSize += info.Size()
			}
		}
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

	// Track errors by category
	type verifyStats struct {
		total   int
		errors  int
		missing int
	}

	dataStats := verifyStats{}
	metadataStats := verifyStats{}
	parityStats := verifyStats{}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Verify function
	verifyFile := func(entry FileEntry, basePath string, stats *verifyStats) {
		defer wg.Done()

		mu.Lock()
		stats.total++
		mu.Unlock()

		// Special handling for metadata files in metadata directory
		actualPath := entry.Path
		if entry.Type == "metadata" && strings.HasPrefix(entry.Path, "metadata/") {
			actualPath = strings.TrimPrefix(entry.Path, "metadata/")
			basePath = m.config.MetadataDir
		}

		filePath := filepath.Join(basePath, actualPath)
		md5sum, err := calculateMD5Only(filePath)
		if err != nil {
			mu.Lock()
			if os.IsNotExist(err) {
				stats.missing++
				log.Printf("Missing: %s", entry.Path)
			} else {
				stats.errors++
				log.Printf("Error reading %s: %v", entry.Path, err)
			}
			mu.Unlock()
			return
		}

		if md5sum != entry.MD5 {
			mu.Lock()
			stats.errors++
			log.Printf("MD5 mismatch: %s", entry.Path)
			mu.Unlock()
			return
		}
	}

	// Verify data files
	fmt.Println("\nVerifying data files...")
	for _, file := range manifest.DataFiles {
		wg.Add(1)
		go verifyFile(file, m.config.RepoPath, &dataStats)
	}
	wg.Wait()

	// Verify metadata files
	fmt.Println("\nVerifying metadata files...")
	// Inner manifest
	wg.Add(1)
	go verifyFile(manifest.InnerManifest, m.config.RepoPath, &metadataStats)

	// Other metadata files
	for _, file := range manifest.MetadataFiles {
		wg.Add(1)
		go verifyFile(file, m.config.RepoPath, &metadataStats)
	}
	wg.Wait()

	// Download parity files if using remote
	if m.config.RcloneRemote != "" {
		fmt.Println("\nDownloading parity files for verification...")
		paritySrc := fmt.Sprintf("%s/.restic/parity/shards/", m.config.RcloneRemote)
		parityDst := filepath.Join(m.config.ParityDir, "shards")

		cmd := exec.Command(getRclonePath(), "copy", paritySrc, parityDst, "--update")
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to download parity files: %v", err)
		}
	}

	// Verify parity files
	fmt.Println("\nVerifying parity files...")
	for _, file := range manifest.ParityFiles {
		wg.Add(1)
		go verifyFile(file, m.config.ParityDir, &parityStats)
	}
	wg.Wait()

	// Summary by category
	fmt.Println("\n=== Verification Summary ===")

	// Data files
	fmt.Printf("\nData files:\n")
	if dataStats.errors == 0 && dataStats.missing == 0 {
		fmt.Printf("  ✓ All %d data files verified\n", dataStats.total)
	} else {
		fmt.Printf("  Total: %d files\n", dataStats.total)
		if dataStats.errors > 0 {
			fmt.Printf("  ✗ Checksum errors: %d\n", dataStats.errors)
		}
		if dataStats.missing > 0 {
			fmt.Printf("  ✗ Missing files: %d\n", dataStats.missing)
		}
	}

	// Metadata files
	fmt.Printf("\nMetadata files:\n")
	if metadataStats.errors == 0 && metadataStats.missing == 0 {
		fmt.Printf("  ✓ All %d metadata files verified\n", metadataStats.total)
	} else {
		fmt.Printf("  Total: %d files\n", metadataStats.total)
		if metadataStats.errors > 0 {
			fmt.Printf("  ✗ Checksum errors: %d\n", metadataStats.errors)
		}
		if metadataStats.missing > 0 {
			fmt.Printf("  ✗ Missing files: %d\n", metadataStats.missing)
		}
	}

	// Parity files
	fmt.Printf("\nParity files:\n")
	if parityStats.errors == 0 && parityStats.missing == 0 {
		fmt.Printf("  ✓ All %d parity files verified\n", parityStats.total)
	} else {
		fmt.Printf("  Total: %d files\n", parityStats.total)
		if parityStats.errors > 0 {
			fmt.Printf("  ✗ Checksum errors: %d\n", parityStats.errors)
		}
		if parityStats.missing > 0 {
			fmt.Printf("  ✗ Missing files: %d\n", parityStats.missing)
		}
	}

	// Overall summary
	totalErrors := dataStats.errors + dataStats.missing + metadataStats.errors + metadataStats.missing + parityStats.errors + parityStats.missing
	totalFiles := dataStats.total + metadataStats.total + parityStats.total
	fmt.Printf("\nOverall:\n")
	if totalErrors == 0 {
		fmt.Printf("  ✓ All %d files verified successfully\n", totalFiles)
	} else {
		fmt.Printf("  ✗ Total errors: %d\n", totalErrors)
	}

	// Check cloud files
	if m.config.RcloneRemote != "" {
		fmt.Println("\nChecking cloud files...")
		cloudErrors := 0

		// Get file list with checksums from rclone (specifically from parity/)
		remotePath := fmt.Sprintf("%s/parity/", m.config.RcloneRemote)
		cmd := exec.Command(getRclonePath(), "lsjson", remotePath, "--hash", "--recursive")
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
			// The remote files are listed from within parity/, so we use the local path directly
			remotePath := file.Path

			if remoteMD5, exists := remoteMap[remotePath]; exists {
				if remoteMD5 != file.MD5 {
					fmt.Printf("  ✗ Cloud MD5 mismatch: parity/%s\n", remotePath)
					cloudErrors++
				}
			} else {
				fmt.Printf("  ✗ Missing in cloud: parity/%s\n", remotePath)
				cloudErrors++
			}
		}

		if cloudErrors == 0 {
			fmt.Println("  ✓ All cloud files OK")
		} else {
			fmt.Printf("  ✗ Found %d cloud errors\n", cloudErrors)
			totalErrors += cloudErrors
		}
	}

	fmt.Println("\n=== Quick Check Complete ===")
	if totalErrors > 0 {
		return fmt.Errorf("verification failed with %d errors", totalErrors)
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

	// Track errors by category
	type verifyStats struct {
		total  int
		errors int
	}

	dataStats := verifyStats{}
	metadataStats := verifyStats{}
	parityStats := verifyStats{}

	// Verify function
	verifyFile := func(entry FileEntry, basePath string, stats *verifyStats) error {
		stats.total++

		// Special handling for metadata files in metadata directory
		actualPath := entry.Path
		if entry.Type == "metadata" && strings.HasPrefix(entry.Path, "metadata/") {
			actualPath = strings.TrimPrefix(entry.Path, "metadata/")
			basePath = m.config.MetadataDir
		}

		filePath := filepath.Join(basePath, actualPath)

		log.Printf("Verifying %s...", entry.Path)

		// Check if file is a restic data file (SHA256 is optional for these)
		isResticData := strings.HasPrefix(entry.Path, "data/")

		if isResticData && entry.SHA256 == "" {
			// For restic data files without SHA256, only verify MD5
			md5sum, err := calculateMD5Only(filePath)
			if err != nil {
				return fmt.Errorf("error reading file: %w", err)
			}
			if md5sum != entry.MD5 {
				return fmt.Errorf("MD5 mismatch")
			}
		} else {
			// For all other files, verify both checksums
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
		}

		return nil
	}

	// Verify inner manifest
	fmt.Println("\nVerifying metadata files...")
	if err := verifyFile(manifest.InnerManifest, m.config.MetadataDir, &metadataStats); err != nil {
		fmt.Printf("  ✗ Inner manifest verification failed: %v\n", err)
		metadataStats.errors++
	}

	// Verify metadata files
	for _, file := range manifest.MetadataFiles {
		if err := verifyFile(file, m.config.RepoPath, &metadataStats); err != nil {
			fmt.Printf("  ✗ Metadata file %s verification failed: %v\n", file.Path, err)
			metadataStats.errors++
		}
	}

	// Verify data files
	fmt.Println("\nVerifying data files...")
	totalFiles := len(manifest.DataFiles)
	for i, file := range manifest.DataFiles {
		if err := verifyFile(file, m.config.RepoPath, &dataStats); err != nil {
			fmt.Printf("  ✗ %s: %v\n", file.Path, err)
			dataStats.errors++
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

		cmd := exec.Command(getRclonePath(), "copy", paritySrc, parityDst, "--progress")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("  Warning: failed to download parity files: %v\n", err)
		}
	}

	// Verify parity files
	fmt.Println("\nVerifying parity files...")
	for _, file := range manifest.ParityFiles {
		if err := verifyFile(file, m.config.ParityDir, &parityStats); err != nil {
			fmt.Printf("  ✗ Parity file %s verification failed: %v\n", file.Path, err)
			parityStats.errors++
		}
	}

	// Summary by category
	fmt.Println("\n=== Deep Verification Summary ===")

	// Data files
	fmt.Printf("\nData files:\n")
	if dataStats.errors == 0 {
		fmt.Printf("  ✓ All %d data files verified\n", dataStats.total)
	} else {
		fmt.Printf("  Total: %d files\n", dataStats.total)
		fmt.Printf("  ✗ Checksum errors: %d\n", dataStats.errors)
	}

	// Metadata files
	fmt.Printf("\nMetadata files:\n")
	if metadataStats.errors == 0 {
		fmt.Printf("  ✓ All %d metadata files verified\n", metadataStats.total)
	} else {
		fmt.Printf("  Total: %d files\n", metadataStats.total)
		fmt.Printf("  ✗ Checksum errors: %d\n", metadataStats.errors)
	}

	// Parity files
	fmt.Printf("\nParity files:\n")
	if parityStats.errors == 0 {
		fmt.Printf("  ✓ All %d parity files verified\n", parityStats.total)
	} else {
		fmt.Printf("  Total: %d files\n", parityStats.total)
		fmt.Printf("  ✗ Checksum errors: %d\n", parityStats.errors)
	}

	// Overall summary
	totalErrors := dataStats.errors + metadataStats.errors + parityStats.errors
	totalCheckedFiles := dataStats.total + metadataStats.total + parityStats.total
	fmt.Printf("\nOverall:\n")
	if totalErrors == 0 {
		fmt.Printf("  ✓ All %d files verified successfully\n", totalCheckedFiles)
	} else {
		fmt.Printf("  ✗ Total errors: %d\n", totalErrors)
		return fmt.Errorf("verification failed with %d errors", totalErrors)
	}

	return nil
}

// Recover handles file recovery
func (m *Manager) Recover() error {
	log.Println("Starting recovery process...")

	// Try to load inner manifest
	innerPath := filepath.Join(m.config.MetadataDir, InnerManifestName)
	innerData, err := os.ReadFile(innerPath)

	if err != nil {
		log.Println("Inner manifest missing, will recover it from parity...")
		// Check if we have chunked parity files
		parityDir := filepath.Join(m.config.ParityDir, "shards")
		if files, err := os.ReadDir(parityDir); err == nil && len(files) > 0 {
			// Check first parity file size to determine format
			firstParity := filepath.Join(parityDir, "parity_0000.shard")
			if info, err := os.Stat(firstParity); err == nil && info.Size() == 65536 {
				// Chunked format
				if err := m.recoverFromParityChunked(); err != nil {
					return fmt.Errorf("failed to recover from chunked parity: %w", err)
				}
			} else {
				// Old format
				if err := m.recoverFromParity(); err != nil {
					return fmt.Errorf("failed to recover from parity: %w", err)
				}
			}
		} else {
			return fmt.Errorf("no parity files found for recovery")
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

// recoverFromParityChunked recovers files from chunked parity format
func (m *Manager) recoverFromParityChunked() error {
	const chunkSize = 64 * 1024 // Must match encoding chunk size

	log.Println("Recovering from chunked parity shards...")

	// Load outer manifest to know the structure
	outerPath := filepath.Join(m.config.ParityDir, OuterManifestName)
	outerData, err := os.ReadFile(outerPath)
	if err != nil {
		return fmt.Errorf("outer manifest required for recovery: %w", err)
	}

	var outerManifest OuterManifest
	if err := json.Unmarshal(outerData, &outerManifest); err != nil {
		return fmt.Errorf("failed to parse outer manifest: %w", err)
	}

	// Try to load inner manifest for erasure scheme
	var tempScheme *ErasureScheme
	innerPath := filepath.Join(m.config.MetadataDir, InnerManifestName)
	if innerData, err := os.ReadFile(innerPath); err == nil {
		var innerManifest InnerManifest
		if err := json.Unmarshal(innerData, &innerManifest); err == nil {
			tempScheme = innerManifest.ErasureScheme
		}
	}

	// If no scheme, try loading erasure_scheme.json directly
	if tempScheme == nil {
		schemePath := filepath.Join(m.config.MetadataDir, ErasureSchemeName)
		if schemeData, err := os.ReadFile(schemePath); err == nil {
			tempScheme = &ErasureScheme{}
			if err := json.Unmarshal(schemeData, tempScheme); err != nil {
				return fmt.Errorf("failed to parse erasure scheme: %w", err)
			}
		} else {
			// Infer from manifest - data files + 1 metadata zip
			dataCount := len(outerManifest.DataFiles) + 1
			parityCount := len(outerManifest.ParityFiles)
			tempScheme = &ErasureScheme{
				DataShards:   dataCount,
				ParityShards: parityCount,
			}
		}
	}

	// Create Reed-Solomon decoder
	dec, err := reedsolomon.New(tempScheme.DataShards, tempScheme.ParityShards)
	if err != nil {
		return fmt.Errorf("failed to create decoder: %w", err)
	}

	// Build ordered list of all files (data files + metadata zip)
	allFiles := []FileEntry{}

	// Add all data files first
	allFiles = append(allFiles, outerManifest.DataFiles...)

	// Find and add the metadata zip (should be in MetadataFiles)
	var metadataZipEntry *FileEntry
	for _, f := range outerManifest.MetadataFiles {
		if strings.HasPrefix(f.Path, "metadata/") && !strings.Contains(f.Path, "inner_manifest") && !strings.Contains(f.Path, "erasure_scheme") {
			// This should be the metadata zip (named by SHA256)
			metadataZipEntry = &f
			allFiles = append(allFiles, f)
			break
		}
	}

	// Pad to match data shards
	for len(allFiles) < tempScheme.DataShards {
		allFiles = append(allFiles, FileEntry{Path: "", Size: 0}) // Empty padding
	}

	// Check which files need recovery
	missingFiles := make(map[int]FileEntry) // shard index -> file info
	for i, file := range allFiles {
		if file.Path == "" {
			continue // Skip padding
		}

		var filePath string
		if strings.HasPrefix(file.Path, "metadata/") {
			// Metadata files are in the metadata directory
			filePath = filepath.Join(m.config.MetadataDir, strings.TrimPrefix(file.Path, "metadata/"))
		} else if strings.HasPrefix(file.Path, "data/") {
			// Data files are in the repo
			filePath = filepath.Join(m.config.RepoPath, file.Path)
		} else {
			// Other files in repo root
			filePath = filepath.Join(m.config.RepoPath, file.Path)
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			missingFiles[i] = file
			log.Printf("File missing (shard %d): %s", i, file.Path)
		}
	}

	if len(missingFiles) == 0 {
		log.Println("No files need recovery")
		return nil
	}

	// Open parity files
	parityFiles := make([]*os.File, tempScheme.ParityShards)
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	for i := 0; i < tempScheme.ParityShards; i++ {
		path := filepath.Join(parityDir, fmt.Sprintf("parity_%04d.shard", i))
		f, err := os.Open(path)
		if err != nil {
			log.Printf("Warning: cannot open parity file %d: %v", i, err)
			continue
		}
		defer f.Close()
		parityFiles[i] = f
	}

	// Determine total chunks needed (based on largest file)
	var maxSize int64
	for _, file := range allFiles {
		if file.Size > maxSize {
			maxSize = file.Size
		}
	}
	totalChunks := int((maxSize + chunkSize - 1) / chunkSize)

	log.Printf("Recovering %d files using %d chunks", len(missingFiles), totalChunks)

	// Process each chunk
	for chunkIdx := 0; chunkIdx < totalChunks; chunkIdx++ {
		offset := int64(chunkIdx) * chunkSize

		// Prepare shards for this chunk
		shards := make([][]byte, tempScheme.DataShards+tempScheme.ParityShards)

		// Read data shards
		for i := 0; i < tempScheme.DataShards; i++ {
			if i >= len(allFiles) || allFiles[i].Path == "" {
				// Padding shard
				shards[i] = make([]byte, chunkSize)
				continue
			}

			// Check if this file is missing
			if _, isMissing := missingFiles[i]; isMissing {
				// Will be reconstructed
				continue
			}

			// Read chunk from existing file
			var filePath string
			if strings.HasPrefix(allFiles[i].Path, "metadata/") {
				filePath = filepath.Join(m.config.MetadataDir, strings.TrimPrefix(allFiles[i].Path, "metadata/"))
			} else if strings.HasPrefix(allFiles[i].Path, "data/") {
				filePath = filepath.Join(m.config.RepoPath, allFiles[i].Path)
			} else {
				filePath = filepath.Join(m.config.RepoPath, allFiles[i].Path)
			}

			shards[i] = m.readChunk(filePath, offset, chunkSize)
		}

		// Read parity shards
		for i := 0; i < tempScheme.ParityShards; i++ {
			if parityFiles[i] != nil {
				shard := make([]byte, chunkSize)
				n, err := parityFiles[i].ReadAt(shard, offset)
				if err != nil && err != io.EOF {
					log.Printf("Warning: error reading parity %d chunk %d: %v", i, chunkIdx, err)
				}
				// Zero-pad if needed
				if n < int(chunkSize) {
					for j := n; j < int(chunkSize); j++ {
						shard[j] = 0
					}
				}
				shards[tempScheme.DataShards+i] = shard
			}
		}

		// Reconstruct missing shards for this chunk
		if err := dec.Reconstruct(shards); err != nil {
			log.Printf("Warning: failed to reconstruct chunk %d: %v", chunkIdx, err)
			continue
		}

		// Write recovered chunks to missing files
		for shardIdx, file := range missingFiles {
			if shardIdx >= len(shards) || shards[shardIdx] == nil {
				continue
			}

			// Determine output path
			var filePath string
			if strings.HasPrefix(file.Path, "metadata/") {
				filePath = filepath.Join(m.config.MetadataDir, strings.TrimPrefix(file.Path, "metadata/"))
			} else if strings.HasPrefix(file.Path, "data/") {
				filePath = filepath.Join(m.config.RepoPath, file.Path)
			} else {
				filePath = filepath.Join(m.config.RepoPath, file.Path)
			}

			// Create directory if needed
			if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
				return fmt.Errorf("failed to create directory for %s: %w", file.Path, err)
			}

			// Open or create file
			f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("failed to open %s for recovery: %w", file.Path, err)
			}

			// Calculate how much to write (don't exceed file size)
			writeSize := chunkSize
			if offset+int64(writeSize) > file.Size {
				writeSize = int(file.Size - offset)
			}

			// Write the chunk
			if writeSize > 0 {
				if _, err := f.WriteAt(shards[shardIdx][:writeSize], offset); err != nil {
					f.Close()
					return fmt.Errorf("failed to write recovered chunk to %s: %w", file.Path, err)
				}
			}

			f.Close()
		}
	}

	// Verify recovered files
	log.Println("Verifying recovered files...")
	var recoveredMetadataZip string
	for _, file := range missingFiles {
		var filePath string
		if strings.HasPrefix(file.Path, "metadata/") {
			filePath = filepath.Join(m.config.MetadataDir, strings.TrimPrefix(file.Path, "metadata/"))
			// Check if this is the metadata zip
			if metadataZipEntry != nil && file.Path == metadataZipEntry.Path {
				recoveredMetadataZip = filePath
			}
		} else if strings.HasPrefix(file.Path, "data/") {
			filePath = filepath.Join(m.config.RepoPath, file.Path)
		} else {
			filePath = filepath.Join(m.config.RepoPath, file.Path)
		}

		if info, err := os.Stat(filePath); err != nil {
			return fmt.Errorf("recovery failed for %s: file still missing", file.Path)
		} else if info.Size() != file.Size {
			return fmt.Errorf("recovery failed for %s: size mismatch (got %d, want %d)",
				file.Path, info.Size(), file.Size)
		}

		log.Printf("✓ Recovered: %s (%d bytes)", file.Path, file.Size)
	}

	// If we recovered the metadata zip, extract it
	if recoveredMetadataZip != "" {
		log.Println("Extracting recovered metadata zip...")
		if err := m.extractMetadataZip(recoveredMetadataZip); err != nil {
			return fmt.Errorf("failed to extract metadata zip: %w", err)
		}
		log.Println("✓ Metadata extracted successfully")
	}

	return nil
}

// extractMetadataZip extracts the metadata zip file to restore repository metadata
func (m *Manager) extractMetadataZip(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open metadata zip: %w", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		// Open the file in the zip
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open %s in zip: %w", file.Name, err)
		}
		defer rc.Close()

		// Determine output path
		var outputPath string
		fileName := file.Name

		// Strip "metadata/" prefix if present
		if strings.HasPrefix(fileName, "metadata/") {
			fileName = strings.TrimPrefix(fileName, "metadata/")
			if fileName == InnerManifestName || fileName == ErasureSchemeName {
				// These go in the metadata directory
				outputPath = filepath.Join(m.config.MetadataDir, fileName)
			} else {
				// Should not happen - metadata/ prefix should only be for inner manifest and erasure scheme
				outputPath = filepath.Join(m.config.RepoPath, file.Name)
			}
		} else {
			// Everything else goes in the repo path
			outputPath = filepath.Join(m.config.RepoPath, fileName)
		}

		// Create directory if needed
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(outputPath, file.Mode()); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", outputPath, err)
			}
			continue
		}

		// Create parent directory
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			return fmt.Errorf("failed to create parent directory for %s: %w", outputPath, err)
		}

		// Create the file
		outFile, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", outputPath, err)
		}

		// Copy the contents
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		if err != nil {
			return fmt.Errorf("failed to extract %s: %w", file.Name, err)
		}

		// Set modification time
		if err := os.Chtimes(outputPath, file.Modified, file.Modified); err != nil {
			log.Printf("Warning: failed to set modification time for %s: %v", outputPath, err)
		}

		log.Printf("Extracted: %s", file.Name)
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
	innerPath := filepath.Join(m.config.MetadataDir, InnerManifestName)
	innerData, _ := os.ReadFile(innerPath)

	var tempScheme *ErasureScheme
	if innerData != nil {
		var innerManifest InnerManifest
		if err := json.Unmarshal(innerData, &innerManifest); err == nil {
			tempScheme = innerManifest.ErasureScheme
		}
	}

	if tempScheme == nil {
		// Try to infer from outer manifest - data files + 1 metadata zip
		dataCount := len(outerManifest.DataFiles) + 1
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

	// Load all available shards (data files + metadata zip)
	shards := make([][]byte, tempScheme.TotalShards)
	shardIndex := 0

	// Load data files first
	for _, file := range outerManifest.DataFiles {
		filePath := filepath.Join(m.config.RepoPath, file.Path)
		if data, err := os.ReadFile(filePath); err == nil {
			shards[shardIndex] = make([]byte, tempScheme.ShardSize)
			copy(shards[shardIndex], data)
			log.Printf("Loaded data file %s as shard %d", file.Path, shardIndex)
		} else {
			log.Printf("Data file %s missing (shard %d): %v", file.Path, shardIndex, err)
		}
		shardIndex++
	}

	// Load metadata zip (should be the last data shard)
	var metadataZipPath string
	for _, file := range outerManifest.MetadataFiles {
		if strings.HasPrefix(file.Path, "metadata/") && !strings.Contains(file.Path, "inner_manifest") && !strings.Contains(file.Path, "erasure_scheme") {
			// This should be the metadata zip
			metadataZipPath = filepath.Join(m.config.MetadataDir, strings.TrimPrefix(file.Path, "metadata/"))
			if data, err := os.ReadFile(metadataZipPath); err == nil {
				shards[shardIndex] = make([]byte, tempScheme.ShardSize)
				copy(shards[shardIndex], data)
				log.Printf("Loaded metadata zip %s as shard %d", file.Path, shardIndex)
			} else {
				log.Printf("Metadata zip %s missing (shard %d): %v", file.Path, shardIndex, err)
			}
			break
		}
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

	// Recover missing files
	shardIndex = 0
	missingFiles := []FileEntry{}

	// Check data files
	for i, file := range outerManifest.DataFiles {
		filePath := filepath.Join(m.config.RepoPath, file.Path)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			log.Printf("Data file missing: %s", file.Path)
			missingFiles = append(missingFiles, file)

			// Recover data file
			if shards[i] != nil && int64(len(shards[i])) >= file.Size {
				recoveredData := shards[i][:file.Size]

				// Create directory if needed
				if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
					return fmt.Errorf("failed to create directory for %s: %w", file.Path, err)
				}

				// Write recovered file
				if err := os.WriteFile(filePath, recoveredData, 0644); err != nil {
					return fmt.Errorf("failed to write recovered file %s: %w", file.Path, err)
				}
				log.Printf("✓ Recovered data file: %s", file.Path)
			}
		}
	}

	// Check metadata zip
	var recoveredMetadataZip string
	if metadataZipPath != "" {
		if _, err := os.Stat(metadataZipPath); os.IsNotExist(err) {
			log.Println("Metadata zip missing, recovering...")

			// Find metadata zip entry
			for _, file := range outerManifest.MetadataFiles {
				if strings.HasPrefix(file.Path, "metadata/") && !strings.Contains(file.Path, "inner_manifest") && !strings.Contains(file.Path, "erasure_scheme") {
					// Recover metadata zip (it's the last data shard)
					metadataShardIdx := len(outerManifest.DataFiles)
					if shards[metadataShardIdx] != nil && int64(len(shards[metadataShardIdx])) >= file.Size {
						recoveredData := shards[metadataShardIdx][:file.Size]

						// Create directory if needed
						if err := os.MkdirAll(filepath.Dir(metadataZipPath), 0755); err != nil {
							return fmt.Errorf("failed to create metadata directory: %w", err)
						}

						// Write recovered metadata zip
						if err := os.WriteFile(metadataZipPath, recoveredData, 0644); err != nil {
							return fmt.Errorf("failed to write recovered metadata zip: %w", err)
						}
						log.Printf("✓ Recovered metadata zip: %s", file.Path)
						recoveredMetadataZip = metadataZipPath
					}
					break
				}
			}
		}
	}

	// If we recovered the metadata zip, extract it
	if recoveredMetadataZip != "" {
		log.Println("Extracting recovered metadata zip...")
		if err := m.extractMetadataZip(recoveredMetadataZip); err != nil {
			return fmt.Errorf("failed to extract metadata zip: %w", err)
		}
		log.Println("✓ Metadata extracted successfully")
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

	// Check if we have chunked parity files
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	if files, err := os.ReadDir(parityDir); err == nil && len(files) > 0 {
		// Check first parity file size to determine format
		firstParity := filepath.Join(parityDir, "parity_0000.shard")
		if info, err := os.Stat(firstParity); err == nil && info.Size() == 65536 {
			// Chunked format
			return m.recoverFromParityChunked()
		}
	}

	// Old format
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

		cmd := exec.Command(getRclonePath(), "copy", src, dst)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to upload %s: %v", file, err)
		}
	}

	// Upload parity directory
	parityDir := filepath.Join(m.config.ParityDir, "shards")
	parityDst := fmt.Sprintf("%s/.restic/parity/shards/", m.config.RcloneRemote)

	cmd := exec.Command(getRclonePath(), "copy", parityDir, parityDst, "--progress")
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

// Progress tracker methods

func (p *ProgressTracker) StartTask(task string, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.noProgress {
		return
	}

	p.currentTask = task
	p.totalItems = total
	p.currentItem = 0
	p.startTime = time.Now()

	if p.useAdvanced {
		// Clear line and print task
		fmt.Printf("\r\033[K%s\n", task)
	} else if !p.quiet {
		fmt.Printf("%s", task)
		if total > 0 {
			fmt.Printf(" (%d items)", total)
		}
		fmt.Println()
	}
}

func (p *ProgressTracker) UpdateProgress(current int, detail string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.noProgress {
		return
	}

	p.currentItem = current

	if p.useAdvanced {
		// Calculate progress
		percent := 0.0
		if p.totalItems > 0 {
			percent = float64(current) / float64(p.totalItems) * 100
		}

		// Calculate ETA
		elapsed := time.Since(p.startTime)
		var eta string
		if current > 0 && p.totalItems > 0 {
			totalTime := elapsed * time.Duration(p.totalItems) / time.Duration(current)
			remaining := totalTime - elapsed
			eta = fmt.Sprintf(" ETA: %s", remaining.Round(time.Second))
		}

		// Build progress bar
		barWidth := 30
		filled := int(percent / 100 * float64(barWidth))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

		// Format detail to fixed width to prevent bar jumping
		detailStr := detail
		if len(detailStr) > 30 {
			detailStr = detailStr[:27] + "..."
		} else {
			detailStr = fmt.Sprintf("%-30s", detailStr)
		}

		// Use colors and special characters
		fmt.Printf("\r\033[K\033[1;32m[%s]\033[0m %.1f%% (%d/%d)%s %s",
			bar, percent, current, p.totalItems, eta, detailStr)
	} else if !p.quiet {
		// Simple progress - print dots
		if current%10 == 0 {
			fmt.Print(".")
			if current%100 == 0 {
				fmt.Printf(" %d/%d\n", current, p.totalItems)
			}
		}
	}
}

func (p *ProgressTracker) CompleteTask(summary string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.noProgress {
		return
	}

	elapsed := time.Since(p.startTime)

	if p.useAdvanced {
		// Clear line and print completion
		fmt.Printf("\r\033[K\033[1;32m✓\033[0m %s (completed in %s)\n", summary, elapsed.Round(time.Second))
	} else if !p.quiet {
		if p.currentItem > 0 && p.currentItem%100 != 0 {
			fmt.Println() // New line after dots
		}
		fmt.Printf("✓ %s (completed in %s)\n", summary, elapsed.Round(time.Second))
	}
}

func (p *ProgressTracker) Log(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.noProgress {
		return
	}

	if p.useAdvanced {
		// Clear current line before logging
		fmt.Print("\r\033[K")
	}

	log.Printf(format, args...)
}

func (p *ProgressTracker) Error(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.useAdvanced {
		// Clear current line and use red color for errors
		fmt.Printf("\r\033[K\033[1;31m✗\033[0m ")
	}

	log.Printf(format, args...)
}

// Helper functions

// runResticCommand executes a restic command with proper environment and stdin handling
func runResticCommand(repoPath string, args ...string) error {
	cmd := exec.Command("restic", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("RESTIC_REPOSITORY=%s", repoPath))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	// Sync to ensure all data is written
	return destFile.Sync()
}

// getRclonePath finds the best rclone binary to use
func getRclonePath() string {
	// Check for specific rclone paths that might work better
	possiblePaths := []string{
		"/opt/homebrew/bin/rclone", // Homebrew ARM64
		"/usr/local/bin/rclone",    // Homebrew Intel or manual install
		"rclone",                   // System PATH
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			// Verify it's executable and working
			cmd := exec.Command(path, "version")
			if output, err := cmd.Output(); err == nil {
				// Check if it works without Rosetta errors
				if !strings.Contains(string(output), "rosetta") {
					return path
				}
			}
		}
	}

	// Default to system rclone
	return "rclone"
}

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

// calculateMD5Only calculates only MD5 checksum for better performance
func calculateMD5Only(filePath string) (string, error) {
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
	flag.BoolVar(&config.Quiet, "quiet", false, "Use simple progress output (no terminal features)")
	flag.BoolVar(&config.NoProgress, "no-progress", false, "Disable all progress output")

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

	// Set up directories
	config.ParityDir = filepath.Join(config.RepoPath, "parity")
	config.MetadataDir = filepath.Join(config.RepoPath, "metadata")
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

	// Default to backing up /Volumes/fishbowl/pollmann with exclusions
	backupPath := "/Volumes/fishbowl/pollmann"
	excludeFile := filepath.Join(backupPath, ".resticignore")

	args := []string{"backup", backupPath}
	if _, err := os.Stat(excludeFile); err == nil {
		args = append(args, "--exclude-file", excludeFile)
	}

	if err := runResticCommand(repoPath, args...); err != nil {
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

	// Ensure metadata directory exists
	if err := os.MkdirAll(m.config.MetadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}

	// Calculate erasure scheme
	if err := m.CalculateErasureSchemeIncremental(); err != nil {
		return fmt.Errorf("erasure scheme calculation failed: %w", err)
	}

	// Save erasure scheme if it doesn't exist
	schemePath := filepath.Join(m.config.MetadataDir, ErasureSchemeName)
	if _, err := os.Stat(schemePath); os.IsNotExist(err) {
		schemeData, err := json.MarshalIndent(m.scheme, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal erasure scheme: %w", err)
		}
		if err := os.WriteFile(schemePath, schemeData, 0644); err != nil {
			return fmt.Errorf("failed to write erasure scheme: %w", err)
		}
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

	// Ensure metadata directory exists
	if err := os.MkdirAll(m.config.MetadataDir, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
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
	fmt.Println("Syncing entire repository to remote...")

	// Get the best rclone path
	rclonePath := getRclonePath()

	// Verify rclone is working
	if output, err := exec.Command(rclonePath, "version").Output(); err != nil {
		return fmt.Errorf("rclone not working: %w", err)
	} else {
		log.Printf("Using rclone: %s", strings.Split(string(output), "\n")[0])
	}

	// Sync entire repository (including parity)
	src := m.config.RepoPath
	dst := m.config.RcloneRemote

	cmd := exec.Command(rclonePath, "sync", src, dst, "--progress")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to sync repository: %w", err)
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
