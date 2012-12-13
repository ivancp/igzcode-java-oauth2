<!DOCTYPE>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>OAuth2 Client TestCases</title>
</head>
<body>

	<form action="/auth" method="post" enctype="application/json" >
		Try to obtain a new AccessToken 
		<input type="submit" value="GET">
	</form>
	
	<form action="/getresource" method="get" enctype="application/json" >
		Try to access a GET protected resource
		<input type="text" name="status" value="valid">
		<input type="submit" value="GET">
	</form>
	
	<form action="/postresource" method="get" enctype="application/json" >
		Try to access a POST protected resource
		<input type="text" name="status" value="valid2">
		<input type="submit" value="POST">
	</form>
	
	<form action="/postasync" method="get" enctype="application/json" >
		Try to access a POST protected resource with various asynchronous calls
		Number of calls: <input type="number" name="n" value="5">
		<input type="submit" value="Do calls">
	</form>
	
</body>
</html>