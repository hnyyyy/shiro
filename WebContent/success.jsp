<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %> 
    
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
</head>
<body>
	
	<h4>Success Page</h4>
	
	<shiro:hasAnyRoles name="user">
	<a href="user.jsp">To UserPage</a>
	<br><br>
	</shiro:hasAnyRoles>
	
	<shiro:hasAnyRoles name="admin">
	<a href="admin.jsp">To AdminPage</a>
	<br><br>
	</shiro:hasAnyRoles>	
	
	<a href="test">Test Shiro Annotation</a>
	<br><br>
		
	<a href="shiro-logout">Logout</a>
	
</body>
</html>