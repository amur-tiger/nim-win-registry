# nim-win-registry
A Windows Registry wrapper for Nim. Nim procs for the raw
[C function definitions](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724868(v=vs.85).aspx) are defined
in `registrydef.nim`. `registry.nim` provides a more high-level API for interacting with the registry, but doesn't
support specialized cases like interacting with the security settings. It should cover most cases for storing
application settings, though. The higher-level wrapper is modeled after the
[C#-API](https://msdn.microsoft.com/en-us/library/microsoft.win32.registrykey(v=vs.110).aspx) for the registry. It
also checks for error codes automatically and throws exceptions if an error occured.

Sample Usage:

```nim
let key = HKEY_CURRENT_USER.openSubKey("SOFTWARE\\YourCompany\\YourSoftware", true)
echo key.getValue("version", "1.0.0")
key.setValue("version", "1.1.0")
key.close()
```

If you opened a key, do not forget to close it if you don't need it anymore.