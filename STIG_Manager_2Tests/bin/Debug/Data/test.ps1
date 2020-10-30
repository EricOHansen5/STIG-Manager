
#V-94563, Copy operations must be disabled on the virtual machine.
Get-VM | Get-AdvancedSetting -Name isolation.tools.copy.disable

#V-94565, Drag and drop operations must be disabled on the virtual machine.
Get-VM | Get-AdvancedSetting -Name isolation.tools.dnd.disable 
