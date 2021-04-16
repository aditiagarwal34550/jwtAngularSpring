package com.bezkoder.springjwt.security.jwt;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

	private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

	@Override
        public void commence(HttpServletRequest request, HttpServletResponse response,
                        AuthenticationException authException) throws IOException, ServletException {

                   final String expired = (String) request.getAttribute("expired");
        final String malformed = (String) request.getAttribute("malformed");
        final String signature = (String) request.getAttribute("signature");
        final String unsupported = (String) request.getAttribute("unsupported");
        final String illegalargument = (String) request.getAttribute("illegalargument");
        final String exception = (String) request.getAttribute("exception");
        if(expired != null){

            response.sendError(response.SC_UNAUTHORIZED,expired);
        }else if (malformed !=null){

            response.sendError(response.SC_UNAUTHORIZED,malformed);
        }else if (signature !=null){
            response.sendError(response.SC_UNAUTHORIZED,signature);
        }else if (unsupported !=null){
            response.sendError(response.SC_UNAUTHORIZED,unsupported);
        }else if (illegalargument !=null){
            response.sendError(response.SC_UNAUTHORIZED,illegalargument);
        }else if(exception !=null ){
            response.sendError(response.SC_UNAUTHORIZED,exception);
        } else {
               System.out.println("NO ERROR");
        }

        }

}
