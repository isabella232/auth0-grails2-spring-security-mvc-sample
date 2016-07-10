package auth0.grails2.mvc.sample

import com.auth0.spring.security.mvc.Auth0UserDetails
import com.auth0.web.Auth0Config
import com.auth0.web.Auth0User
import com.auth0.web.SessionUtils
import org.codehaus.groovy.grails.web.util.WebUtils
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder

class HomeController {

    static defaultAction = "home"

    @Autowired
    Auth0Config auth0Config

    def home() {
        log.info("Home page")
        def req = WebUtils.retrieveGrailsWebRequest().getCurrentRequest()
        Auth0UserDetails principal = (Auth0UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        for(GrantedAuthority grantedAuthority: principal.getAuthorities()) {
            String authority = grantedAuthority.getAuthority();
            log.info(authority);
            if (("ROLE_ADMIN".equals(authority))) {
                // just a simple callout to demonstrate role based authorization at service level
                // non-Admin user would be rejected trying to call this service
                log.info("Yes, admin!");
            }
        }
        Auth0User user = SessionUtils.getAuth0User(req)
        log.info("User name: " + user.getName());
        def model = [:]
        model['user'] = user
        render(view: "home", model: [model: model])
        return "home"
    }

}

