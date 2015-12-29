import registrydef, strutils, typetraits, winlean

type
    RegistryError* = object of Exception

const
    FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100
    FORMAT_MESSAGE_IGNORE_INSERTS = 0x200
    FORMAT_MESSAGE_FROM_SYSTEM = 0x1000

    ERROR_SUCCESS = 0
    ERROR_FILE_NOT_FOUND = 2
    USER_LANGUAGE = 0x0400
    
    MAX_KEY_LEN = 255
    MAX_VALUE_LEN = 16383

proc getErrorMessage(code: int32): string {.raises: [].} =
    var msgbuf: pointer
    when useWinUnicode:
        discard formatMessageW(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_ALLOCATE_BUFFER or
            FORMAT_MESSAGE_IGNORE_INSERTS, nil, code, USER_LANGUAGE, msgbuf.addr, 0, nil)
        result = $cast[WideCString](msgbuf)
    else:
        discard formatMessageA(FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_ALLOCATE_BUFFER or
            FORMAT_MESSAGE_IGNORE_INSERTS, nil, code, USER_LANGUAGE, msgbuf.addr, 0, nil)
        result = $cast[CString](msgbuf)
    localFree(msgbuf)

proc raiseError(code: int32) {.inline, raises: [RegistryError].} =
    raise newException(RegistryError, $code & ": " & getErrorMessage(code))

proc close*(this: RegistryKey) {.raises: [RegistryError].} =
    ## Closes the key and flushes it to disk if its contents have been modified.

    let code = regCloseKey(this)
    if code != ERROR_SUCCESS:
        raiseError(code)

proc createSubKey*(this: RegistryKey, subkey: string not nil, writable: bool): RegistryKey {.raises: [RegistryError].} =
    ## Creates a new subkey or opens an existing subkey with the specified access.

    var createdHandle: RegistryKey
    when useWinUnicode:
        let code = regCreateKeyExW(this, newWideCString(subkey), 0, nil, 0,
            if writable: KEY_WRITE else: KEY_READ, nil, createdHandle.addr, nil)
    else:
        let code = regCreateKeyExA(this, newCString(subkey), 0, nil, 0,
            if writable: KEY_WRITE else: KEY_READ, nil, createdHandle.addr, nil)

    if code != ERROR_SUCCESS:
        raiseError(code)

    return createdHandle

proc createSubKey*(this: RegistryKey, subkey: string not nil): RegistryKey {.raises: [RegistryError].} =
    ## Creates a new subkey or opens an existing subkey for write access.
    return this.createSubKey(subkey, true)

proc deleteSubKey*(this: RegistryKey, subkey: string not nil, raiseOnMissingSubKey: bool) {.raises: [RegistryError].} =
    ## Deletes the specified subkey, and specifies whether an exception is raised if the subkey is not found.

    when useWinUnicode:
        let code = regDeleteKeyW(this, newWideCString(subkey))
    else:
        let code = regDeleteKeyA(this, newCString(subkey))

    if code != ERROR_SUCCESS and (raiseOnMissingSubKey or code != ERROR_FILE_NOT_FOUND):
        raiseError(code)

proc deleteSubKey*(this: RegistryKey, subkey: string not nil) {.raises: [RegistryError].} =
    ## Deletes the specified subkey.
    this.deleteSubKey(subkey, true)

proc deleteSubKeyTree*(this: RegistryKey, subkey: string not nil, raiseOnMissingSubKey: bool)
    {.raises: [RegistryError].} =
    ## Deletes the specified subkey and any child subkeys recursively, and
    ## specifies whether an exception is raised if the subkey is not found.

    when useWinUnicode:
        let code = regDeleteTreeW(this, newWideCString(subkey))
    else:
        let code = regDeleteTreeA(this, newCString(subkey))

    if code != ERROR_SUCCESS and (raiseOnMissingSubKey or code != ERROR_FILE_NOT_FOUND):
        raiseError(code)

proc deleteSubKeyTree*(this: RegistryKey, subkey: string not nil) {.raises: [RegistryError].} =
    ## Deletes a subkey and any child subkeys recursively.
    this.deleteSubKeyTree(subkey, true)

proc deleteValue*(this: RegistryKey, name: string, raiseOnMissingValue: bool) {.raises: [RegistryError].} =
    ## Deletes the specified value from this key, and specifies whether
    ## an exception is raised if the value is not found.

    when useWinUnicode:
        let code = regDeleteKeyValueW(this, nil, newWideCString(name))
    else:
        let code = regDeleteKeyValueA(this, nil, newCString(name))

    if code != ERROR_SUCCESS and (raiseOnMissingValue or code != ERROR_FILE_NOT_FOUND):
        raiseError(code)

proc deleteValue*(this: RegistryKey, name: string) {.raises: [RegistryError].} =
    ## Deletes the specified value from this key.
    this.deleteValue(name, true)

proc flush*(this: RegistryKey) {.raises: [RegistryError].} =
    ## Writes all the attributes of the specified open registry key into the registry.

    let code = regFlushKey(this)
    if code != ERROR_SUCCESS:
        raiseError(code)

iterator getSubKeyNames*(this: RegistryKey): string {.raises: [RegistryError].} =
    ## Retrieves an iterator of strings that runs over all the subkey names.

    var keyCount: int32
    when useWinUnicode:
        let code = regQueryInfoKeyW(this, nil, nil, nil, keyCount.addr, nil, nil, nil, nil, nil, nil, nil)
        if code != ERROR_SUCCESS:
            raiseError(code)

        var nameBuffer: WideCString
        unsafeNew(nameBuffer, (MAX_KEY_LEN + 1) * sizeof(Utf16Char))

        for i in 0..<keyCount:
            var nameLen: int32 = MAX_KEY_LEN
            let code = regEnumKeyExW(this, int32(i), nameBuffer, nameLen.addr, nil, nil, nil, nil)
            if code != ERROR_SUCCESS:
                raiseError(code)

            nameBuffer[nameLen] = Utf16Char(0)
            yield $nameBuffer
    else:
        let code = regQueryInfoKeyA(this, nil, nil, nil, keyCount.addr, nil, nil, nil, nil, nil, nil, nil)
        if code != ERROR_SUCCESS:
            raiseError(code)

        var nameBuffer: CString
        unsafeNew(nameBuffer, MAX_KEY_LEN + 1)
        
        for i in 0..<keyCount:
            var nameLen: int32 = MAX_KEY_LEN
            let code = regEnumKeyExA(this, int32(i), nameBuffer, nameLen.addr, nil, nil, nil, nil)
            if code != ERROR_SUCCESS:
                raiseError(code)

            nameBuffer[nameLen] = 0
            yield $nameBuffer

proc tryGetValue*[T](this: RegistryKey, name: string, value: var T): bool
    {.raises: [RegistryError, ValueError, OverflowError].} =
    ## Retrieves the value associated with the specified name.
    ## Attempts to convert values to the correct type, if applicable.

    var kind: RegistryValueType
    var size: int32
    when useWinUnicode:
        let code = regQueryValueExW(this, newWideCString(name), nil, kind.addr, nil, size.addr)
    else:
        let code = regQueryValueExA(this, newCString(name), nil, kind.addr, nil, size.addr)

    if code == ERROR_FILE_NOT_FOUND:
        return false
    if code != ERROR_SUCCESS:
        raiseError(code)

    case kind:
    of REG_DWORD:
        var tmp: int32
        size = int32(sizeof(tmp))

        when useWinUnicode:
            let code = regGetValueW(this, nil, newWideCString(name), 0x0000ffff, nil,
                cast[pointer](tmp.addr), size.addr)
        else:
            let code = regGetValueA(this, nil, newCString(name), 0x0000ffff, nil,
                cast[pointer](tmp.addr), size.addr)

        if code == ERROR_FILE_NOT_FOUND:
            return false
        if code != ERROR_SUCCESS:
            raiseError(code)

        when T is SomeNumber:
            value = T(tmp)
            return true
        elif T is string:
            value = $tmp
            return true
        else:
            {.fatal: "The type " & T.name & " is not supported yet.".}
    of REG_QWORD:
        var tmp: int64
        size = int32(sizeof(tmp))

        when useWinUnicode:
            let code = regGetValueW(this, nil, newWideCString(name), 0x0000ffff, nil,
                cast[pointer](tmp.addr), size.addr)
        else:
            let code = regGetValueA(this, nil, newCString(name), 0x0000ffff, nil,
                cast[pointer](tmp.addr), size.addr)

        if code == ERROR_FILE_NOT_FOUND:
            return false
        if code != ERROR_SUCCESS:
            raiseError(code)

        when T is SomeNumber:
            value = T(tmp)
            return true
        elif T is string:
            value = $tmp
            return true
        else:
            {.fatal: "The type " & T.name & " is not supported yet.".}
    of REG_BINARY:
        var tmp: float64
        size = int32(sizeof(tmp))

        when useWinUnicode:
            let code = regGetValueW(this, nil, newWideCString(name), 0x0000ffff, nil,
                cast[pointer](tmp.addr), size.addr)
        else:
            let code = regGetValueA(this, nil, newCString(name), 0x0000ffff, nil,
                cast[pointer](tmp.addr), size.addr)

        if code == ERROR_FILE_NOT_FOUND:
            return false
        if code != ERROR_SUCCESS:
            raiseError(code)

        when T is SomeNumber:
            value = T(tmp)
            return true
        elif T is string:
            value = $tmp
            return true
        else:
            {.fatal: "The type " & T.name & " is not supported yet.".}
    of REG_SZ, REG_EXPAND_SZ:
        when useWinUnicode:
            var buffer: WideCString
            unsafeNew(buffer, size + sizeof(Utf16Char))
            buffer[size div sizeof(Utf16Char) - 1] = Utf16Char(0)

            let code = regGetValueW(this, nil, newWideCString(name), 0x0000ffff, nil,
                cast[pointer](buffer), size.addr)
        else:
            var buffer: CString
            unsafeNew(buffer, size + 1)
            buffer[size - 1] = 0

            let code = regGetValueA(this, nil, newCString(name), 0x0000ffff, nil,
                cast[pointer](buffer), size.addr)

        if code == ERROR_FILE_NOT_FOUND:
            return false
        if code != ERROR_SUCCESS:
            raiseError(code)

        when T is SomeOrdinal:
            value = parseInt($buffer)
            return true
        elif T is SomeReal:
            value = parseFloat($buffer)
            return true
        elif T is string:
            value = $buffer
            return true
        else:
            {.fatal: "The type " & T.name & " is not supported yet.".}
    else:
        raise newException(RegistryError, "The registry value is of type " & $kind & ", which is not supported")

proc getValue*[T](this: RegistryKey, name: string, default: T): T
    {.raises: [RegistryError, ValueError, OverflowError].} =
    ## Retrieves the value associated with the specified name. If the name is not found, returns
    ## the default value that you provide. Attempts to convert values to the correct type, if applicable.

    if not this.tryGetValue(name, result):
        result = default

proc getValueKind*(this: RegistryKey, name: string): RegistryValueType {.raises: [RegistryError].} =
    ## Retrieves the registry data type of the value associated with the specified name.

    when useWinUnicode:
        let code = regQueryValueExW(this, newWideCString(name), nil, result.addr, nil, nil)
    else:
        let code = regQueryValueExA(this, newCString(name), nil, result.addr, nil, nil)

    if code != ERROR_SUCCESS:
        raiseError(code)

iterator getValueNames*(this: RegistryKey): string {.raises: [RegistryError].} =
    ## Retrieves an iterator of strings that runs over all the value names associated with this key.

    var valCount: int32
    when useWinUnicode:
        let code = regQueryInfoKeyW(this, nil, nil, nil, nil, nil, nil, valCount.addr, nil, nil, nil, nil)
        if code != ERROR_SUCCESS:
            raiseError(code)

        var nameBuffer: WideCString
        unsafeNew(nameBuffer, (MAX_VALUE_LEN + 1) * sizeof(Utf16Char))

        for i in 0..<valCount:
            var nameLen: int32 = MAX_VALUE_LEN
            let code = regEnumValueW(this, int32(i), nameBuffer, nameLen.addr, nil, nil, nil, nil)
            if code != ERROR_SUCCESS:
                raiseError(code)

            nameBuffer[nameLen] = Utf16Char(0)
            yield $nameBuffer
    else:
        let code = regQueryInfoKeyA(this, nil, nil, nil, nil, nil, nil, valCount.addr, nil, nil, nil, nil)
        if code != ERROR_SUCCESS:
            raiseError(code)

        var nameBuffer: CString
        unsafeNew(nameBuffer, MAX_VALUE_LEN + 1)

        for i in 0..<valCount:
            var nameLen: int32 = MAX_VALUE_LEN
            let code = regEnumValueA(this, int32(i), nameBuffer, nameLen.addr, nil, nil, nil, nil)
            if code != ERROR_SUCCESS:
                raiseError(code)

            nameBuffer[nameLen] = 0
            yield $nameBuffer

proc openSubKey*(this: RegistryKey, name: string, writable: bool): RegistryKey {.raises: [RegistryError].} =
    ## Retrieves a specified subkey, and specifies whether write access is to be applied to the key.

    when useWinUnicode:
        let code = regOpenKeyExW(this, newWideCString(name), 0, if writable: KEY_WRITE else: KEY_READ, result.addr)
    else:
        let code = regOpenKeyExA(this, newCString(name), 0, if writable: KEY_WRITE else: KEY_READ, result.addr)

    if code != ERROR_SUCCESS:
        raiseError(code)

proc openSubKey*(this: RegistryKey, name: string): RegistryKey {.raises: [RegistryError].} =
    ## Retrieves a subkey as read-only.
    return this.openSubKey(name, false)

proc setValue*[T](this: RegistryKey, name: string, value: T, valueKind: RegistryValueType) {.raises: [RegistryError].} =
    ## Sets the specified name/value pair in the registry key, using the specified registry data type.

    when useWinUnicode:
        let code = regSetKeyValueW(this, nil, newWideCString(name), valueKind,
            when value is string: cast[ptr int32](newWideCString(value)) else: value.addr, int32(sizeof(value)))
    else:
        let code = regSetKeyValueExA(this, nil, newCString(name), valueKind,
            when value is string: cast[ptr int32](newCString(value)) else: value.addr, int32(sizeof(value)))

    if code != ERROR_SUCCESS:
        raiseError(code)

proc setValue*[T](this: RegistryKey, name: string, value: T) {.raises: [RegistryError].} =
    ## Sets the specified name/value pair.

    when T is SomeOrdinal:
        this.setValue(name, value, REG_DWORD)
    else:
        when T is SomeReal:
            this.setValue(name, value, REG_BINARY)
        else:
            when T is string:
                this.setValue(name, value, REG_SZ)
            else:
                #{.fatal: "A value of type " & T.name & " cannot be written directly to the registry.".}
                {.fatal: "A value of this type cannot be written directly to the registry.".}
