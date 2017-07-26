#!/usr/bin/python
"""
Tree of Savior IDAPython Script
Identify Lua C/C++ functions
"""

import idaapi
import idautils
import idc

#i164556
LuaGetTableByName = 0x00C5A370
LuaAssignCFunction = 0x00C5A640

MakeNameEx(LuaGetTableByName, "LuaGetTableByName", SN_NOWARN);
MakeNameEx(LuaAssignCFunction, "LuaAssignCFunction", SN_NOWARN);

occ = RfirstB(LuaGetTableByName);
while (occ != BADADDR):
    stateAddr = PrevHead(occ)
    tableAddr = PrevHead(stateAddr)

    if (GetMnem(tableAddr) != "push"):
        occ = RnextB (LuaGetTableByName, occ);
        continue

    nameOffset = GetOperandValue(tableAddr, 0);
    if (nameOffset == 0):
        occ = RnextB (LuaGetTableByName, occ);
        continue

    name = GetString(nameOffset)

    while (True):
        #look for C functions
        CFuncAddr = NextHead(occ);
        CFuncNameAddr = NextHead(CFuncAddr)
        stateAddr = NextHead(CFuncNameAddr)
        assignAddr = NextHead(stateAddr)

        if (GetOperandValue(assignAddr, 0) != LuaAssignCFunction):
            break

        funcName = GetString(GetOperandValue(CFuncNameAddr, 0))
        funcOffset = GetOperandValue(CFuncAddr, 0);
        MakeNameEx(funcOffset, name + "::" + funcName, SN_NOWARN)
        print(name + "::" + funcName + " => " + hex(CFuncAddr))

        #adjust stack
        occ = NextHead(assignAddr)

    occ = RnextB (LuaGetTableByName, occ);
