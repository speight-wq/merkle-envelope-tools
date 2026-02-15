#!/bin/bash
# build.sh - Create single-file distributions
# Concatenates lib/*.js into each HTML file for offline use

set -e

DIST_DIR="dist"
LIB_ORDER="lib/crypto.js lib/encoding.js lib/secp256k1.js lib/sighash.js lib/headers.js"

mkdir -p "$DIST_DIR"

# Concatenate all lib files
echo "Concatenating library files..."
cat $LIB_ORDER > "$DIST_DIR/combined.js"

# Function to embed libs into HTML
embed_libs() {
  local input=$1
  local output=$2
  local libs=$3
  
  echo "Building $output..."
  
  # Read the combined libs
  local lib_content
  lib_content=$(cat $libs)
  
  # Read input file
  local html
  html=$(cat "$input")
  
  # Remove <script src="lib/..."> lines
  html=$(echo "$html" | sed '/<script src="lib\//d')
  
  # Insert libs before </head>
  # Using awk for multi-line insertion
  echo "$html" | awk -v libs="$lib_content" '
    /<\/head>/ {
      print "<script>"
      print libs
      print "</script>"
    }
    { print }
  ' > "$output"
}

# Build each HTML file
for html_file in generator.html headers-generator.html verifier.html signer.html tests.html; do
  if [ -f "$html_file" ]; then
    embed_libs "$html_file" "$DIST_DIR/$html_file" "$DIST_DIR/combined.js"
  fi
done

# Clean up
rm "$DIST_DIR/combined.js"

# Report sizes
echo ""
echo "Build complete. File sizes:"
echo "----------------------------"
ls -lh "$DIST_DIR"/*.html 2>/dev/null | awk '{print $9, $5}'

echo ""
echo "Original lib/ sizes:"
wc -l lib/*.js | tail -1
