# Modul Enrichment DursGo

Modul ini menyediakan fungsionalitas untuk memperkaya data kerentanan dengan informasi tambahan dari berbagai sumber eksternal.

## Fitur

- **CISA KEV Integration**: Mendeteksi kerentanan yang tercantum dalam [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **Caching**: Menyimpan data secara lokal untuk mengurangi permintaan jaringan
- **Thread-safe**: Aman digunakan secara konkuren

## Penggunaan

### Inisialisasi

```go
import "github.com/yourusername/DursGo/internal/enrichment"

// Buat enricher baru
enricher, err := enrichment.NewEnricher("/path/to/cache/dir")
if err != nil {
    log.Fatalf("Gagal menginisialisasi enricher: %v", err)
}
defer enricher.Close()
```

### Enrich Vulnerability

```go
vuln := &enrichment.Vulnerability{
    ID:          "vuln-123",
    Type:        "SQL Injection",
    URL:         "http://example.com/search",
    Parameter:   "q",
    Details:     "Blind SQL injection in search parameter",
    Severity:    "High",
    CVE:         "CVE-2021-44228",
}

// Lakukan enrichment
if err := enricher.Enrich(context.Background(), vuln); err != nil {
    log.Printf("Peringatan: Gagal melakukan enrichment: %v", err)
}

// Periksa hasil enrichment
if vuln.Enrichment != nil && vuln.Enrichment.CISAKEV != nil {
    log.Printf("Kerentanan ini ada dalam CISA KEV: %v", vuln.Enrichment.CISAKEV.InCatalog)
}
```

## Konfigurasi

### CISA KEV

- **Cache TTL**: Default 24 jam
- **URL Katalog**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

## Contoh

Lihat [contoh penggunaan](/examples/enrichment_example.go) untuk contoh lengkap.

## Lisensi

[LISENSI PROYEK ANDA]
