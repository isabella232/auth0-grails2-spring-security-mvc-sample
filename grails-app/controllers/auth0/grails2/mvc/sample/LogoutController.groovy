package auth0.grails2.mvc.sample

import com.auth0.web.Auth0Config
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.codehaus.groovy.grails.web.util.WebUtils
import org.springframework.beans.factory.annotation.Autowired

class LogoutController {

    static defaultAction = "logout"

    @Autowired
    Auth0Config auth0Config

    def logout() {
        log.info("Performing logout")
        GrailsWebRequest webUtils = WebUtils.retrieveGrailsWebRequest()
        def req = webUtils.getCurrentRequest()
        if (req.getSession() != null) {
            req.getSession().invalidate()
        }
        def logoutPath = auth0Config.getOnLogoutRedirectTo()
        redirect(uri: logoutPath)
    }

}
