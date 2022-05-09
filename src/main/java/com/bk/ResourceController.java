package com.bk;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created By: bhushan.karmarkar12@gmail.com
 * Date: 06/05/22
 */
@RestController
public class ResourceController {

    @PreAuthorize("hasRole('USER')")
    @GetMapping(value="/getUser")
    @ResponseBody
    public String getUser() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return securityContext.getAuthentication().getName();
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping(value="/getAdmin")
    @ResponseBody
    public String getAdmin() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return securityContext.getAuthentication().getName();
    }
}
