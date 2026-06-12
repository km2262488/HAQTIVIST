# Kompilasi untuk Linux/Mac
go build -o haqtivist haqtivist.go

# Kompilasi untuk Windows
go build -o haqtivist.exe haqtivist.go

# Testing website sendiri
./haqtivist -target http://localhost:8080 -threads 50 -duration 30

# Testing dengan POST data
./haqtivist -target https://yoursite.com/api -method POST -data "key=value" -threads 100

# Testing dengan random IP spoofing
./haqtivist -target https://yoursite.com -random-ip -threads 200

# Testing dengan custom headers
./haqtivist -target https://yoursite.com -header "X-Custom: value" -header "Authorization: Bearer token"

# Testing dengan delay (menghindari detection)
./haqtivist -target https://yoursite.com -delay 100 -threads 50

# Verbose mode untuk debugging
./haqtivist -target https://yoursite.com -verbose -duration 60

