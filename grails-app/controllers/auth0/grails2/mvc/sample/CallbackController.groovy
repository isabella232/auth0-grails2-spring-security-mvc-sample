package auth0.grails2.mvc.sample

import com.auth0.web.Auth0CallbackHandler
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.codehaus.groovy.grails.web.util.WebUtils
import org.springframework.beans.factory.annotation.Autowired

class CallbackController {

    static defaultAction = "callback"

    @Autowired
    Auth0CallbackHandler callback

    def callback() {
        GrailsWebRequest webUtils = WebUtils.retrieveGrailsWebRequest()
        def req = webUtils.getCurrentRequest()
        def res = response
        callback.handle(req, res)
    }
}
