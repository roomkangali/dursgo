package reporter

import (
	"encoding/json"
	"os"
)

// WriteJSONReport takes report data, formats it into JSON, and writes it to a file.
// This function serializes the provided report data into a human-readable JSON format
// with indentation and saves it to the specified output path.
// It handles potential errors during JSON marshaling and file writing.
func WriteJSONReport(reportData *Report, outputPath string) error {
	jsonData, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, jsonData, 0644)
}
