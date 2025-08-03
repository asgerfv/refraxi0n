## Refraxi0n : Deobfuscate Runtime/Dynamic IATs using x32dbg and Ghidra

The following code was developed for my UCD FCCI Case Study 2025, called `Deobfuscating Runtime IATs in advanced malware`.

This code is published to aid the malware reversing community in combating advanced malware that might obfuscate their code using Dynamic IAT.


## What?

Deobfuscates the `Dynamic IAT` or `Runtime IAT` technique, which handles two variations:

**Indirect Function Call**:

E.g. from:

```
void FUN_004b100c(void)
{
  (*DAT_004c54ac)("UseFunctionPointerFromIAT\n");
  return;
}
```

to:

```
void FUN_004b100c(void)
{
  (*kernel32_OutputDebugStringA)("UseFunctionPointerFromIAT\n");
  return;
}
```


**Double Indirect Function Calls**

E.g. from:

```
void FUN_004b1019(void)
{
  (*(code *)DAT_004c5498[1])("UseFunctionPointerFromPointerToIAT\n");
  (*(code *)*DAT_004c5498)();
  return;
}
```

to:

```
void FUN_004b1019(void)
{
  (*(code *)IAT_Resolved__kernel32Ptr_t_004c5498->kernel32_OutputDebugStringA)
            ("UseFunctionPointerFromPointerToIAT\n");
  (*(code *)IAT_Resolved__kernel32Ptr_t_004c5498->kernel32_IsDebuggerPresent)();
  return;
}
```



## How?

By having two distinct plugins: One for x32dbg which dumps the dynamic IAT(s) to a .txt file, and one for Ghidra that reads said .txt file, and populates new structs based on it. The result is indirect - and double indirect - function calls being changed from `undefined` to human readable API function names.


## How well does it perform?

Both the included test sample and in-the-wild malware is deobfuscated quite well, to a point where I haven't observed cases that it couldn't handle.


## License?

https://unlicense.org/
