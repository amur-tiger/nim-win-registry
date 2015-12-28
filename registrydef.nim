import winlean

{.deadCodeElim: on.}

const
    REG_LIB = "Advapi32"

type
    RegistryKey* = Handle
    
    RegistrySecurityAccess* = enum
        KEY_QUERY_VALUE = 0x0001,
        KEY_SET_VALUE = 0x0002,
        KEY_CREATE_SUB_KEY = 0x0004,
        KEY_ENUMERATE_SUB_KEYS = 0x0008,
        KEY_NOTIFY = 0x0010,
        KEY_CREATE_LINK = 0x0020,
        KEY_WOW64_64KEY = 0x0100,
        KEY_WOW64_32KEY = 0x0200,
        KEY_WRITE = 0x20006,
        KEY_READ = 0x20019,
        KEY_ALL_ACCESS = 0xf003f

    RegistryValueType* = enum
        REG_NONE = 0i32,
        REG_SZ = 1i32,
        REG_EXPAND_SZ = 2i32,
        REG_BINARY = 3i32,
        REG_DWORD = 4i32,
        REG_DWORD_BIG_ENDIAN = 5i32,
        REG_LINK = 6i32,
        REG_MULTI_SZ = 7i32,
        REG_RESOURCE_LIST = 8i32,
        REG_FULL_RESOURCE_DESCRIPTOR = 9i32,
        REG_RESOURCE_REQUIREMENTS_LIST = 10i32,
        REG_QWORD = 11i32

    ACL = object
        aclRevision: uint8
        sbz1: uint8
        aclSize: uint16
        aceCount: uint16
        sbz2: uint16

    SECURITY_INFORMATION = DWORD

    SECURITY_DESCRIPTOR = object
        revision: uint8
        sbz1: uint8
        control: uint16
        owner: pointer
        group: pointer
        sacl: ptr ACL
        dacl: ptr ACL

when useWinUnicode:
    type
        VALENT = object
            veValuename: WideCString
            veValuelen: DWORD
            veValueptr: DWORD
            veType: DWORD
else:
    type
        VALENT = object
            veValuename: CString
            veValuelen: DWORD
            veValueptr: DWORD
            veType: DWORD

const
    HKEY_CLASSES_ROOT* = RegistryKey(0x80000000)
    HKEY_CURRENT_USER* = RegistryKey(0x80000001)
    HKEY_LOCAL_MACHINE* = RegistryKey(0x80000002)
    HKEY_USERS* = RegistryKey(0x80000003)
    HKEY_PERFORMANCE_DATA* = RegistryKey(0x80000004)
    HKEY_CURRENT_CONFIG* = RegistryKey(0x80000005)
    HKEY_DYN_DATA* {.deprecated.} = RegistryKey(0x80000006)

proc regCloseKey*(hKey: RegistryKey): int32 {.stdcall, dynlib: REG_LIB, importc: "RegCloseKey".}

when useWinUnicode:
    proc regConnectRegistryW*(lpMachineName: WideCString, hKey: RegistryKey, phkResult: ptr RegistryKey): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegConnectRegistryW".}
else:
    proc regConnectRegistryA*(lpMachineName: CString, hKey: RegistryKey, phkResult: ptr RegistryKey): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegConnectRegistryA".}

when useWinUnicode:
    proc regCopyTreeW*(hKeySrc: RegistryKey, lpSubKey: WideCString, hKeyDest: RegistryKey): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegCopyTreeW".}
else:
    proc regCopyTreeA*(hKeySrc: RegistryKey, lpSubKey: CString, hKeyDest: RegistryKey): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegCopyTreeA".}

when useWinUnicode:
    proc regCreateKeyExW*(hKey: RegistryKey, lpSubKey: WideCString, reserved: int32, lpClass: WideCString, dwOptions: int32,
        samDesired: RegistrySecurityAccess, lpSecurityAttributes: ptr SECURITY_ATTRIBUTES, phkResult: ptr RegistryKey,
        lpdwDisposition: ptr DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegCreateKeyExW".}
else:
    proc regCreateKeyExA*(hKey: RegistryKey, lpSubKey: CString, reserved: int32, lpClass: CString, dwOptions: int32,
        samDesired: RegistrySecurityAccess, lpSecurityAttributes: ptr SECURITY_ATTRIBUTES, phkResult: ptr RegistryKey,
        lpdwDisposition: ptr DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegCreateKeyExA".}

when useWinUnicode:
    proc regCreateKeyTransactedW*(hKey: RegistryKey, lpSubKey: WideCString, reserved: DWORD, lpClass: WideCString,
        dwOptions: DWORD, samDesired: RegistrySecurityAccess, lpSecurityAttributes: ptr SECURITY_ATTRIBUTES, phkResult: ptr RegistryKey,
        lpdwDisposition: ptr DWORD, hTransaction: Handle, pExtendedParameter: pointer): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegCreateKeyTransactedW".}
else:
    proc regCreateKeyTransactedA*(hKey: RegistryKey, lpSubKey: CString, reserved: DWORD, lpClass: CString,
        dwOptions: DWORD, samDesired: RegistrySecurityAccess, lpSecurityAttributes: ptr SECURITY_ATTRIBUTES, phkResult: ptr RegistryKey,
        lpdwDisposition: ptr DWORD, hTransaction: Handle, pExtendedParameter: pointer): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegCreateKeyTransactedA".}

when useWinUnicode:
    proc regDeleteKeyW*(hKey: RegistryKey, lpSubKey: WideCString): int32 {.stdcall, dynlib: REG_LIB, importc: "RegDeleteKeyW".}
else:
    proc regDeleteKeyA*(hKey: RegistryKey, lpSubKey: CString): int32 {.stdcall, dynlib: REG_LIB, importc: "RegDeleteKeyA".}

when useWinUnicode:
    proc regDeleteKeyExW*(hKey: RegistryKey, lpSubKey: WideCString, samDesired: RegistrySecurityAccess, reserved: DWORD): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteKeyExW".}
else:
    proc regDeleteKeyExA*(hKey: RegistryKey, lpSubKey: CString, samDesired: RegistrySecurityAccess, reserved: DWORD): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteKeyExA".}

when useWinUnicode:
    proc regDeleteKeyTransactedW*(hKey: RegistryKey, lpSubKey: WideCString, samDesired: RegistrySecurityAccess, reserved: DWORD,
        hTransaction: Handle, pExtendedParameter: pointer): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteKeyTransactedW".}
else:
    proc regDeleteKeyTransactedA*(hKey: RegistryKey, lpSubKey: CString, samDesired: RegistrySecurityAccess, reserved: DWORD,
        hTransaction: Handle, pExtendedParameter: pointer): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteKeyTransactedA".}

when useWinUnicode:
    proc regDeleteKeyValueW*(hKey: RegistryKey, lpSubKey: WideCString, lpValueName: WideCString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteKeyValueW".}
else:
    proc regDeleteKeyValueA*(hKey: RegistryKey, lpSubKey: CString, lpValueName: CString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteKeyValueA".}

when useWinUnicode:
    proc regDeleteTreeW*(hKey: RegistryKey, lpSubKey: WideCString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteTreeW".}
else:
    proc regDeleteTreeA*(hKey: RegistryKey, lpSubKey: CString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteTreeA".}

when useWinUnicode:
    proc regDeleteValueW*(hKey: RegistryKey, lpValueName: WideCString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteValueW".}
else:
    proc regDeleteValueA*(hKey: RegistryKey, lpValueName: CString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegDeleteValueA".}

proc regDisablePredefinedCache*(): int32 {.stdcall, dynlib: REG_LIB, importc: "RegDisablePredefinedCache".}

proc regDisablePredefinedCacheEx*(): int32 {.stdcall, dynlib: REG_LIB, importc: "RegDisablePredefinedCacheEx".}

proc regDisableReflectionKey*(hBase: RegistryKey): int32 {.stdcall, dynlib: REG_LIB, importc: "RegDisableReflectionKey".}

proc regEnableReflectionKey*(hBase: RegistryKey): int32 {.stdcall, dynlib: REG_LIB, importc: "RegEnableReflectionKey".}

when useWinUnicode:
    proc regEnumKeyExW*(hKey: RegistryKey, dwIndex: DWORD, lpName: WideCString, lpcName: ptr DWORD, lpReserved: ptr DWORD,
        lpClass: WideCString, lpcClass: ptr DWORD, lpftLastWriteTime: ptr FILETIME): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegEnumKeyExW".}
else:
    proc regEnumKeyExA*(hKey: RegistryKey, dwIndex: DWORD, lpName: CString, lpcName: ptr DWORD, lpReserved: ptr DWORD,
        lpClass: CString, lpcClass: ptr DWORD, lpftLastWriteTime: ptr FILETIME): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegEnumKeyExA".}

when useWinUnicode:
    proc regEnumValueW*(hKey: RegistryKey, dwIndex: DWORD, lpValueName: WideCString, lpcchValueName: ptr DWORD,
        lpReserved: ptr DWORD, lpType: ptr DWORD, lpData: ptr uint8, lpcbData: ptr DWORD): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegEnumValueW".}
else:
    proc regEnumValueA*(hKey: RegistryKey, dwIndex: DWORD, lpValueName: CString, lpcchValueName: ptr DWORD,
        lpReserved: ptr DWORD, lpType: ptr DWORD, lpData: ptr uint8, lpcbData: ptr DWORD): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegEnumValueA".}

proc regFlushKey*(hKey: RegistryKey): int32 {.stdcall, dynlib: REG_LIB, importc: "RegFlushKey".}

proc regGetKeySecurity*(hKey: RegistryKey, securityInformation: SECURITY_INFORMATION,
    pSecurityDescriptor: ptr SECURITY_DESCRIPTOR, lpcbSecurityDescriptor: ptr DWORD): int32
    {.stdcall, dynlib: REG_LIB, importc: "RegGetKeySecurity".}

when useWinUnicode:
    proc regGetValueW*(hKey: RegistryKey, lpSubKey: WideCString, lpValue: WideCString, dwFlags: DWORD, pdwType: ptr DWORD,
        pvData: pointer, pcbData: ptr DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegGetValueW".}
else:
    proc regGetValueA*(hKey: RegistryKey, lpSubKey: CString, lpValue: CString, dwFlags: DWORD, pdwType: ptr DWORD,
        pvData: pointer, pcbData: ptr DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegGetValueA".}

when useWinUnicode:
    proc regLoadKeyW*(hKey: RegistryKey, lpSubKey: WideCString, lpFile: WideCString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegLoadKeyW".}
else:
    proc regLoadKeyA*(hKey: RegistryKey, lpSubKey: CString, lpFile: CString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegLoadKeyA".}

when useWinUnicode:
    proc regLoadMUIStringW*(hKey: RegistryKey, pszValue: WideCString, pszOutBuf: WideCString, cbOutBuf: DWORD,
        pcbData: ptr DWORD, flags: DWORD, pszDirectory: WideCString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegLoadMUIStringW".}
else:
    proc regLoadMUIStringA*(hKey: RegistryKey, pszValue: CString, pszOutBuf: CString, cbOutBuf: DWORD,
        pcbData: ptr DWORD, flags: DWORD, pszDirectory: CString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegLoadMUIStringA".}

proc regNotifyChangeKeyValue*(hKey: RegistryKey, bWatchSubtree: WINBOOL, dwNotifyFilter: DWORD, hEvent: Handle,
    fAsynchronous: WINBOOL): int32 {.stdcall, dynlib: REG_LIB, importc: "RegNotifyChangeKeyValue".}

proc regOpenCurrentUser*(samDesired: RegistrySecurityAccess, phkResult: ptr RegistryKey): int32
    {.stdcall, dynlib: REG_LIB, importc: "RegOpenCurrentUser".}

when useWinUnicode:
    proc regOpenKeyExW*(hKey: RegistryKey, lpSubKey: WideCString, ulOptions: DWORD, samDesired: RegistrySecurityAccess,
        phkResult: ptr RegistryKey): int32 {.stdcall, dynlib: REG_LIB, importc: "RegOpenKeyExW".}
else:
    proc regOpenKeyExA*(hKey: RegistryKey, lpSubKey: CString, ulOptions: DWORD, samDesired: RegistrySecurityAccess,
        phkResult: ptr RegistryKey): int32 {.stdcall, dynlib: REG_LIB, importc: "RegOpenKeyExA".}

when useWinUnicode:
    proc regOpenKeyTransactedW*(hKey: RegistryKey, lpSubKey: WideCString, ulOptions: DWORD, samDesired: RegistrySecurityAccess,
        phkResult: ptr RegistryKey, hTransaction: Handle, pExtendedParameter: pointer): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegOpenKeyTransactedW".}
else:
    proc regOpenKeyTransactedA*(hKey: RegistryKey, lpSubKey: CString, ulOptions: DWORD, samDesired: RegistrySecurityAccess,
        phkResult: ptr RegistryKey, hTransaction: Handle, pExtendedParameter: pointer): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegOpenKeyTransactedA".}

proc regOpenUserClassesRoot*(hToken: Handle, dwOptions: DWORD, samDesired: RegistrySecurityAccess, phkResult: ptr RegistryKey): int32
    {.stdcall, dynlib: REG_LIB, importc: "RegOpenUserClassesRoot".}

proc regOverridePredefKey*(hKey: RegistryKey, hNewHKey: RegistryKey): int32
    {.stdcall, dynlib: REG_LIB, importc: "RegOverridePredefKey".}

when useWinUnicode:
    proc regQueryInfoKeyW*(hKey: RegistryKey, lpClass: WideCString, lpcClass: ptr DWORD, lpReserved: ptr DWORD,
        lpcSubKeys: ptr DWORD, lpcMaxSubKeyLen: ptr DWORD, lpcMaxClassLen: ptr DWORD, lpcValues: ptr DWORD,
        lpcMaxValueNameLen: ptr DWORD, lpcValueLen: ptr DWORD, lpcbSecurityDescription: ptr DWORD,
        lpftLastWriteTime: ptr FILETIME): int32 {.stdcall, dynlib: REG_LIB, importc: "RegQueryInfoKeyW".}
else:
    proc regQueryInfoKeyA*(hKey: RegistryKey, lpClass: CString, lpcClass: ptr DWORD, lpReserved: ptr DWORD,
        lpcSubKeys: ptr DWORD, lpcMaxSubKeyLen: ptr DWORD, lpcMaxClassLen: ptr DWORD, lpcValues: ptr DWORD,
        lpcMaxValueNameLen: ptr DWORD, lpcValueLen: ptr DWORD, lpcbSecurityDescription: ptr DWORD,
        lpftLastWriteTime: ptr FILETIME): int32 {.stdcall, dynlib: REG_LIB, importc: "RegQueryInfoKeyA".}

when useWinUnicode:
    proc regQueryMultipleValuesW*(hKey: RegistryKey, val_list: ptr VALENT, num_vals: DWORD, lpValueBuf: WideCString,
        ldwTotsize: ptr DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegQueryMultipleValuesW".}
else:
    proc regQueryMultipleValuesA*(hKey: RegistryKey, val_list: ptr VALENT, num_vals: DWORD, lpValueBuf: CString,
        ldwTotsize: ptr DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegQueryMultipleValuesA".}

proc regQueryReflectionKey*(hBase: RegistryKey, bIsReflectionDisabled: ptr WINBOOL): int32
    {.stdcall, dynlib: REG_LIB, importc: "RegQueryReflectionKey".}

when useWinUnicode:
    proc regQueryValueExW*(hKey: RegistryKey, lpValueName: WideCString, lpReserved: ptr DWORD,
        lpType: ptr RegistryValueType, lpData: ptr int8, lpcbData: ptr DWORD): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegQueryValueExW".}
else:
    proc regQueryValueExA*(hKey: RegistryKey, lpValueName: CString, lpReserved: ptr DWORD,
        lpType: ptr RegistryValueType, lpData: ptr int8, lpcbData: ptr DWORD): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegQueryValueExA".}

when useWinUnicode:
    proc regReplaceKeyW*(hKey: RegistryKey, lpSubKey: WideCString, lpNewFile: WideCString, lpOldFile: WideCString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegReplaceKeyW".}
else:
    proc regReplaceKeyA*(hKey: RegistryKey, lpSubKey: CString, lpNewFile: CString, lpOldFile: CString): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegReplaceKeyA".}

when useWinUnicode:
    proc regRestoreKeyW*(hKey: RegistryKey, lpFile: WideCString, dwFlags: DWORD): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegRestoreKeyW".}
else:
    proc regRestoreKeyA*(hKey: RegistryKey, lpFile: CString, dwFlags: DWORD): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegRestoreKeyA".}

when useWinUnicode:
    proc regSaveKeyW*(hKey: RegistryKey, lpFile: WideCString, lpSecurityAttributes: ptr SECURITY_ATTRIBUTES): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegSaveKeyW".}
else:
    proc regSaveKeyA*(hKey: RegistryKey, lpFile: CString, lpSecurityAttributes: ptr SECURITY_ATTRIBUTES): int32
        {.stdcall, dynlib: REG_LIB, importc: "RegSaveKeyA".}

when useWinUnicode:
    proc regSaveKeyExW*(hKey: RegistryKey, lpFile: WideCString, lpSecurityAttributes: ptr SECURITY_ATTRIBUTES,
        flags: DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegSaveKeyExW".}
else:
    proc regSaveKeyExA*(hKey: RegistryKey, lpFile: CString, lpSecurityAttributes: ptr SECURITY_ATTRIBUTES,
        flags: DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegSaveKeyExA".}

when useWinUnicode:
    proc regSetKeyValueW*(hKey: RegistryKey, lpSubKey: WideCString, lpValueName: WideCString, dwType: RegistryValueType,
        lpData: ptr DWORD, cbData: DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegSetKeyValueW".}
else:
    proc regSetKeyValueA*(hKey: RegistryKey, lpSubKey: CString, lpValueName: CString, dwType: RegistryValueType,
        lpData: ptr DWORD, cbData: DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegSetKeyValueA".}

proc regSetKeySecurity*(hKey: RegistryKey, securityInformation: SECURITY_INFORMATION,
    pSecurityDescriptor: ptr SECURITY_DESCRIPTOR): int32 {.stdcall, dynlib: REG_LIB, importc: "RegSetKeySecurity".}

when useWinUnicode:
    proc regSetValueExW*(hKey: RegistryKey, lpValueName: WideCString, reserved: DWORD, dwType: RegistryValueType,
        lpData: ptr int8, cbData: DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegSetValueExW".}
else:
    proc regSetValueExA*(hKey: RegistryKey, lpValueName: CString, reserved: DWORD, dwType: RegistryValueType,
        lpData: ptr int8, cbData: DWORD): int32 {.stdcall, dynlib: REG_LIB, importc: "RegSetValueExA".}

when useWinUnicode:
    proc regUnLoadKeyW*(hKey: RegistryKey, lpSubKey: WideCString): int32 {.stdcall, dynlib: REG_LIB, importc: "RegUnLoadKeyW".}
else:
    proc regUnLoadKeyA*(hKey: RegistryKey, lpSubKey: CString): int32 {.stdcall, dynlib: REG_LIB, importc: "RegUnLoadKeyA".}