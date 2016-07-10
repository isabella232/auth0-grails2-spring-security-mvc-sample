<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8"/>
    <title>Login</title>
    <asset:stylesheet src="bootstrap.css"/>
    <asset:stylesheet src="jquery.growl.css"/>
    <script src="http://code.jquery.com/jquery.js"></script>
    <script src="http://cdn.auth0.com/js/lock-9.min.js"></script>
    <asset:javascript src="jquery.growl.js"/>
</head>
<body>
<div class="container">
    <script type="text/javascript">
        $(function () {
            $.growl({title: "Welcome!", message: "Please log in"});
        });
        $(function () {
            var lock = new Auth0Lock('${model.clientId}', '${model.domain}');
            lock.showSignin({
                authParams: {
                    state: '${model.state}',
                    // change scopes to whatever you like
                    // claims are added to JWT id_token - openid profile gives everything
                    scope: 'openid user_id name nickname email picture'
                },
                callbackURL: "${createLink(action: 'callback', controller: 'callback', absolute: true)}",
                responseType: 'code',
                popup: false
            });
        });
    </script>
</div>
</body>
</html>
