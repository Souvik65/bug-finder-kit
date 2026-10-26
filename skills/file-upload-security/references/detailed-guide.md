# File Upload Hardening — Technical Reference Guide

## 1. Magic Bytes (File Signatures) Reference Table

When verifying file headers on the server, check the leading bytes before processing:

| Extension | MIME Type | Magic Bytes (Hex) | ASCII Representation |
|---|---|---|---|
| `.png` | `image/png` | `89 50 4E 47 0D 0A 1A 0A` | `‰PNG....` |
| `.jpg` / `.jpeg` | `image/jpeg` | `FF D8 FF` | `ÿØÿ` |
| `.gif` | `image/gif` | `47 49 46 38 37 61` or `47 49 46 38 39 61` | `GIF87a` / `GIF89a` |
| `.pdf` | `application/pdf` | `25 50 44 46` | `%PDF` |
| `.zip` | `application/zip` | `50 4B 03 04` | `PK..` |
| `.webp` | `image/webp` | `52 49 46 46 ... 57 45 42 50` | `RIFF....WEBP` |

---

## 2. Web Server Hardening Templates

### Apache `.htaccess` to Prevent PHP Execution in Upload Directories
Place this `.htaccess` file directly inside your `uploads/` folder:

```apache
# 1. Disable execution of scripts
<FilesMatch "(?i)\.(php|php3|php4|php5|phtml|phar|inc|pl|py|cgi|sh|bash)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>

# 2. Prevent overriding with another .htaccess
<Files ".htaccess">
    Order Allow,Deny
    Deny from all
</Files>

# 3. Disable script interpretation engines
<IfModule mod_php7.c>
    php_flag engine off
</IfModule>
<IfModule mod_php.c>
    php_flag engine off
</IfModule>

# 4. Enforce nosniff
Header set X-Content-Type-Options "nosniff"
```

### Nginx Configuration for Dedicated Upload Directory
```nginx
server {
    server_name example.com;

    # Serve static assets from uploads folder with execution disabled
    location ^~ /uploads/ {
        alias /var/www/uploads/;
        
        # Disable all script handlers
        location ~ \.(php|phtml|phar|sh|pl|py)$ {
            return 403;
        }

        # Force download for unrecognized files
        add_header X-Content-Type-Options "nosniff" always;
        add_header Content-Security-Policy "default-src 'none'" always;
    }
}
```

---

## 3. Zip Slip Mitigation across Languages

### Python ZipFile Safe Extraction
```python
import os
import zipfile

def safe_extract(zip_path, target_dir):
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for member in zf.infolist():
            # Resolve absolute path of the target
            target_path = os.path.abspath(os.path.join(target_dir, member.filename))
            target_base = os.path.abspath(target_dir)

            # Ensure extraction target stays strictly within base directory
            if not target_path.startswith(target_base + os.sep):
                raise SecurityException(f"Zip Slip attempt detected: {member.filename}")

            zf.extract(member, target_dir)
```

### Go Archive Extraction
```go
func safeExtract(reader *zip.Reader, dest string) error {
    for _, f := range reader.File {
        filePath := filepath.Join(dest, f.Name)
        
        // Check for directory traversal
        if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(dest)+string(os.PathSeparator)) {
            return fmt.Errorf("illegal file path in zip: %s", f.Name)
        }
        
        // Extract safely
    }
    return nil
}
```

---

## 4. Cloud Object Storage Pattern (AWS S3 Pre-Signed URLs)

The most secure architecture for file uploads is avoiding direct server processing altogether:

1. Client asks application backend for an upload token/URL (`POST /api/upload/request`).
2. Backend authenticates user, generates a random S3 key, and creates a pre-signed `PUT` URL with restricted `Content-Type` and size limits.
3. Client uploads file directly to AWS S3 / Cloud Storage.
4. S3 triggers an asynchronous Lambda / worker to scan for malware, re-encode images, and generate thumbnails.
5. Application server is never exposed to untrusted binary processing or disk write hazards.
