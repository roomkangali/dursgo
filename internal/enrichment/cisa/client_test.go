package cisa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{
			name:    "Valid directory",
			dir:     t.TempDir(),
			wantErr: false,
		},
		{
			name:    "Invalid directory",
			dir:     "/nonexistent/directory",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.dir)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				// Pastikan untuk menutup client setelah selesai
				if client != nil {
					err := client.Close()
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestClient_Close(t *testing.T) {
	// Test close on nil client
	var client *Client
	err := client.Close()
	assert.NoError(t, err, "Close should handle nil client")

	// Test close on valid client
	tempDir := t.TempDir()
	client, err = NewClient(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	err = client.Close()
	assert.NoError(t, err)
}

