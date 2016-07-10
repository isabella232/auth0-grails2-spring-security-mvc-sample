class UrlMappings {

    static mappings = {
        login: "/login" {
            controller = 'login'
            action = 'login'
        }
        logout: "/logout" {
            controller = 'logout'
            action = 'logout'
        }
        callback: "/callback" {
            controller = 'callback'
            action = 'callback'
        }
        home: "/portal/home" {
            controller = 'home'
            action = 'home'
        }
        "/"(view:"/index")
        "500"(view:'/error')
        "404"(view:'/notFound')
    }

}
