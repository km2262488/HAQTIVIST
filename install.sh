```bash
#!/bin/bash

echo "🚀 Installing haqtivist..."

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "❌ Go not found. Installing Go..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt &> /dev/null; then
            sudo apt update && sudo apt install golang-go -y
        elif command -v pkg &> /dev/null; then
            pkg install golang
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install go
    elif [[ "$OSTYPE" == "msys" ]]; then
        echo "Please install Go manually from https://go.dev/dl/"
        exit 1
    fi
fi

# Create directory
mkdir -p ~/haqtivist
cd ~/haqtivist

# Download script (if hosted)
# curl -o haqtivist.go https://raw.githubusercontent.com/yourrepo/haqtivist/main/haqtivist.go

echo "📝 Please create haqtivist.go file with the script content"
read -p "Press Enter when done..."

# Compile
echo "🔨 Compiling haqtivist..."
go build -ldflags="-s -w" -o haqtivist haqtivist.go

# Move to PATH
if [[ "$OSTYPE" != "msys" ]]; then
    sudo mv haqtivist /usr/local/bin/
    echo "✅ haqtivist installed to /usr/local/bin"
else
    echo "✅ haqtivist.exe created in $(pwd)"
fi

echo "✨ Installation complete!"
echo "Usage: haqtivist -target https://example.com -threads 50"
```
