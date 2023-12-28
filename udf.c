#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>

NTSTATUS ResizeUnicodeString(UNICODE_STRING* unicodeString, USHORT newMaxLength)
{
    // Allocate a new buffer
    WCHAR* newBuffer = (WCHAR*)ExAllocatePoolWithTag(
        NonPagedPool,
        newMaxLength,
        'hsw');  // Replace 'Your' with an appropriate tag

    if (!newBuffer)
    {
        // Memory allocation failed
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Copy the contents of the old buffer to the new buffer
    RtlCopyMemory(newBuffer, unicodeString->Buffer, unicodeString->Length);

    // Free the old buffer
    if (unicodeString->Buffer)
    {
        ExFreePool(unicodeString->Buffer);
    }

    // Update UNICODE_STRING fields with the new buffer and size
    unicodeString->Buffer = newBuffer;
    unicodeString->MaximumLength = newMaxLength;

    return STATUS_SUCCESS;
}

BOOLEAN SubstringInUnicodeString(UNICODE_STRING* mainString, UNICODE_STRING* substring) {
    ULONG index;
    ULONG substringIndex = 0;

    for (index = 0; index < mainString->Length / sizeof(WCHAR); ++index) {
        if (mainString->Buffer[index] == substring->Buffer[substringIndex]) {
            // Match found, check the rest of the substring
            ++substringIndex;
            if (substringIndex == substring->Length / sizeof(WCHAR)) {
                // Entire substring matched
                return TRUE;
            }
        }
        else {
            // Reset substring index if there is a mismatch
            substringIndex = 0;
        }
    }

    // Substring not found
    return FALSE;
}

BOOLEAN StartsWithUnicodeString(UNICODE_STRING* mainString, UNICODE_STRING* substring) {
    ULONG index;

    for (index = 0; index < substring->Length / sizeof(WCHAR); ++index) {
        if (mainString->Buffer[index] != substring->Buffer[index]) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN EndsWithUnicodeString(UNICODE_STRING* mainString, UNICODE_STRING* substring) {
    ULONG mainStringIndex;
    ULONG index;

    mainStringIndex = mainString->Length / sizeof(WCHAR) - 1;

    for (index = substring->Length / sizeof(WCHAR) - 1; index > 0; --index) {
        if (mainString->Buffer[mainStringIndex] != substring->Buffer[index]) {
            return FALSE;
        }
        --mainStringIndex;
    }

    return TRUE;
}

BOOLEAN isExecutableExtension(UNICODE_STRING* fullname, UNICODE_STRING* executableExtension) {
    LONG index;
    LONG start;
    LONG end = executableExtension->Length / sizeof(WCHAR) - 1;
    LONG fullnameIndex;
    LONG testIndex;
    BOOLEAN test = FALSE;

    index = end;
    while (index >= 0 && end > 0) {
        start = index;
        if (index == 0)
            test = TRUE;
        else if (executableExtension->Buffer[index] == ';')
            test = TRUE;

        if (test) {
            if (start < end) {
                fullnameIndex = fullname->Length / sizeof(WCHAR) - 1;
                for (testIndex = end; testIndex > start; --testIndex) {
                    if (fullname->Buffer[fullnameIndex] != executableExtension->Buffer[testIndex]) {
                        //move to next before ;
                        test = FALSE;
                        end = start - 1;
                        goto next;
                    }
                    --fullnameIndex;
                }
                //Entire substring matched
                return TRUE;
            }
            else {
                test = FALSE;
                end = start - 1;
            }
        }
    next:
        --index;
    }

    return FALSE;
}

BOOLEAN isContainSubstr(PUNICODE_STRING fullname, PUNICODE_STRING allowedPath) {
    LONG index;
    LONG end = allowedPath->Length / sizeof(WCHAR) - 1;
    LONG start;
    LONG fullnameIndex;
    LONG substringIndex;
    BOOLEAN test = FALSE;

    index = end;
    while (index >= 0 && end > 0) {
        start = index;
        if (index == 0)
            test = TRUE;
        else if (allowedPath->Buffer[index] == ';')
            test = TRUE;

        if (test) {
            if (start < end) {
                substringIndex = start + 1;
                for (fullnameIndex = 0; fullnameIndex < fullname->Length / sizeof(WCHAR); ++fullnameIndex) {
                    if (fullname->Buffer[fullnameIndex] == allowedPath->Buffer[substringIndex]) {
                        // Match found, check the rest of the substring
                        ++substringIndex;
                        if (substringIndex > end) {
                            // Entire substring matched
                            return TRUE;
                        }
                    }
                    else {
                        // Reset substring index if there is a mismatch
                        substringIndex = start + 1;
                    }
                }
            }
            test = FALSE;
            end = start - 1;
        }
        --index;
    }
    return FALSE;
}