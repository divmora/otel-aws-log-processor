package processor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/parquet-go/parquet-go"
)

// ProcessLineFunc is a function that processes a single log line
type ProcessLineFunc func(line string) (LogAdapter, error)

// ProcessJSONFunc is a function that processes a single raw JSON object
type ProcessJSONFunc func(data []byte) (LogAdapter, error)

// ReadAndParseFromS3 is a helper to stream and parse line-based logs
func ReadAndParseFromS3(logger *slog.Logger, s3Client *s3.S3, bucket, key string, maxBatchSize, maxConcurrent int, parseFunc ProcessLineFunc) ([]LogAdapter, error) {
	// Get object from S3
	result, err := s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer result.Body.Close()

	var reader io.Reader = result.Body

	// Handle gzip compression
	if strings.HasSuffix(key, ".gz") {
		gzReader, err := gzip.NewReader(result.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Create channels for parallel processing
	linesChan := make(chan string, maxBatchSize)
	entriesChan := make(chan LogAdapter, maxBatchSize)
	var wg sync.WaitGroup

	// Start workers
	numWorkers := maxConcurrent
	if numWorkers < 1 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range linesChan {
				if line == "" {
					continue
				}
				entry, err := parseFunc(line)
				if err == nil && entry != nil {
					entriesChan <- entry
				}
			}
		}()
	}

	// Start a goroutine to read lines and send to workers
	go func() {
		scanner := bufio.NewScanner(reader)
		// Increase buffer size
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			linesChan <- scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			logger.Error("Error scanning S3 object", "error", err)
		}

		close(linesChan)
	}()

	// Start a goroutine to close entriesChan when all workers are done
	go func() {
		wg.Wait()
		close(entriesChan)
	}()

	// Collect results
	entries := make([]LogAdapter, 0)
	for entry := range entriesChan {
		entries = append(entries, entry)
	}

	logger.Info("Parsed entries", "count", len(entries))
	return entries, nil
}

// ReadAndParseJSONFromS3 is a helper to stream and parse JSON logs (concatenated or new-line delimited)
func ReadAndParseJSONFromS3(logger *slog.Logger, s3Client *s3.S3, bucket, key string, maxBatchSize, maxConcurrent int, parseFunc ProcessJSONFunc) ([]LogAdapter, error) {
	// Get object from S3
	result, err := s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer result.Body.Close()

	var reader io.Reader = result.Body

	// Handle gzip compression
	if strings.HasSuffix(key, ".gz") {
		gzReader, err := gzip.NewReader(result.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Create channels for parallel processing
	// We pass raw JSON bytes to workers
	jsonChan := make(chan []byte, maxBatchSize)
	entriesChan := make(chan LogAdapter, maxBatchSize)
	var wg sync.WaitGroup

	// Start workers
	numWorkers := maxConcurrent
	if numWorkers < 1 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for data := range jsonChan {
				if len(data) == 0 {
					continue
				}
				entry, err := parseFunc(data)
				if err == nil && entry != nil {
					entriesChan <- entry
				}
			}
		}()
	}

	// Start a goroutine to decode JSON objects and send to workers
	go func() {
		decoder := json.NewDecoder(reader)
		for decoder.More() {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				logger.Error("Error decoding JSON object", "error", err)
				// Determine if we should stop or continue.
				// For now, if we can't decode one object, we might lose sync if it's not NDJSON,
				// but json.Decoder tries to recover.
				// If error is EOF, loop will terminate by More() returning false usually.
				if err == io.EOF {
					break
				}
				continue
			}
			// Make a copy of bytes because RawMessage is a slice reference that might be reused/overwritten?
			// Actually RawMessage is just []byte. Unmarshal copies the data.
			// But decoder buffer might be reused. It is safer to copy if we pass to another goroutine?
			// json.RawMessage from Decode usually allocates a new slice.
			// To be safe:
			data := make([]byte, len(raw))
			copy(data, raw)
			jsonChan <- data
		}

		close(jsonChan)
	}()

	// Start a goroutine to close entriesChan when all workers are done
	go func() {
		wg.Wait()
		close(entriesChan)
	}()

	// Collect results
	entries := make([]LogAdapter, 0)
	for entry := range entriesChan {
		entries = append(entries, entry)
	}

	logger.Info("Parsed entries", "count", len(entries))
	return entries, nil
}

// ReadAndParseParquetFromS3 streams and parses parquet logs
func ReadAndParseParquetFromS3[T any](logger *slog.Logger, s3Client *s3.S3, bucket, key string, maxBatchSize, maxConcurrent int, parseFunc func(*T) (LogAdapter, error)) ([]LogAdapter, error) {
	// Get object from S3
	result, err := s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer result.Body.Close()

	// Download to memory for random access required by Parquet
	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 object body: %w", err)
	}

	reader := bytes.NewReader(data)
	parquetReader := parquet.NewGenericReader[T](reader)

	rowChan := make(chan *T, maxBatchSize)
	entriesChan := make(chan LogAdapter, maxBatchSize)
	var wg sync.WaitGroup

	numWorkers := maxConcurrent
	if numWorkers < 1 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for row := range rowChan {
				entry, err := parseFunc(row)
				if err == nil && entry != nil {
					entriesChan <- entry
				}
			}
		}()
	}

	go func() {
		defer close(rowChan)
		rows := make([]T, maxBatchSize)
		for {
			n, err := parquetReader.Read(rows)
			for i := 0; i < n; i++ {
				// Copy row because we pass a pointer to worker, and rows slice is reused
				rowCopy := rows[i]
				rowChan <- &rowCopy
			}
			if err != nil {
				if err != io.EOF {
					logger.Error("Error reading parquet", "error", err)
				}
				break
			}
		}
	}()

	go func() {
		wg.Wait()
		close(entriesChan)
	}()

	entries := make([]LogAdapter, 0)
	for entry := range entriesChan {
		entries = append(entries, entry)
	}

	logger.Info("Parsed entries", "count", len(entries))
	return entries, nil
}
