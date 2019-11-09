#!/usr/bin/env python
# -*- coding:utf-8 -*-
from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.module_loading import import_string
from django.views.decorators.csrf import csrf_exempt
from pylti.common import LTIException, verify_request_common


def get_reverse(objs):
    try:
        return reverse(objs)
    except:
        pass
    raise Exception('We got a URL reverse issue: %s.' % str(objs))

def denied(r):
    return render(r, 'denied.html')

@csrf_exempt
def auth(request):
    '''POST handler for the LTI login POST back call'''
    if request.method == 'POST':
        # Extracts the LTI payload information
        params = {key: request.POST[key] for key in request.POST}
        # Maps the settings defined for the LTI consumer
        consumers = settings.PYLTI_CONFIG['consumers']
        # Builds the tool URL from the request
        url = request.build_absolute_uri()
        # Extracts the request headers from the request
        headers = request.META
        # Get the default next URL from the LTI config
        next_template = settings.PYLTI_CONFIG.get('next_url')
        try:
            # Validate the incoming LTI
            verify_request_common(consumers, url,\
                                  request.method, headers,\
                                  params)
            # Map and call the login method hook if defined in the settings
            login_method_hook = settings.PYLTI_CONFIG.get('method_hooks',{}).get('valid_lti_request',None)
            if(login_method_hook):
                # If there is a return URL from the configured call the redirect URL
                # is updated with the one that is returned. This is to enable redirecting to 
                # constructed URLs
                ############ K3ru: updated lines ################################
                update_template = import_string(login_method_hook)(params, request)
                print("Update URL: ", update_template)
                if update_template:
                    next_template = update_template
                    print("USER post_update: ", request.user.username)
            return render(request, next_template)
            ################### End updated lines ###############################
        except LTIException:
            # Map and call the invalid login method hook if defined in the settings
            invalid_login_method_hook = settings.PYLTI_CONFIG.get('method_hooks',{}).get('invalid_lti_request',None)
            if(invalid_login_method_hook):
                import_string(invalid_login_method_hook)(params)
            return HttpResponseRedirect(get_reverse('django_lti_auth:denied'))
    else:
        return HttpResponseRedirect(get_reverse('django_lti_auth:denied'))
