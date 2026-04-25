# Build Setup

## 1. Windows Build Setup

### Prerequisites
- Install via scoop: `vcpkg`, `strawberryperl`
- Run: `vcpkg install openssl:x64-windows`
- Run: `perl -MCPAN -e "install Locale::Maketext::Simple"`

### Environment Variables
```
OPENSSL_DIR=C:\Users\<Username>\scoop\apps\vcpkg\current\installed\x64-windows
OPENSSL_NO_VENDOR=1
PATH += C:\Strawberry\perl\bin
```

Restart terminal, then `cargo build` should work.
