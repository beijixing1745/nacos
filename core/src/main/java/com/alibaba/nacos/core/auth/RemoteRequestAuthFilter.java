/*
 * Copyright 1999-2020 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.core.auth;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.remote.request.Request;
import com.alibaba.nacos.api.remote.request.RequestMeta;
import com.alibaba.nacos.api.remote.response.Response;
import com.alibaba.nacos.auth.GrpcProtocolAuthService;
import com.alibaba.nacos.auth.annotation.Secured;
import com.alibaba.nacos.auth.config.NacosAuthConfig;
import com.alibaba.nacos.auth.config.NacosAuthConfigHolder;
import com.alibaba.nacos.auth.serveridentity.ServerIdentityResult;
import com.alibaba.nacos.common.utils.ExceptionUtil;
import com.alibaba.nacos.core.context.RequestContext;
import com.alibaba.nacos.core.context.RequestContextHolder;
import com.alibaba.nacos.core.remote.AbstractRequestFilter;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.api.AuthResult;
import com.alibaba.nacos.plugin.auth.api.IdentityContext;
import com.alibaba.nacos.plugin.auth.api.Permission;
import com.alibaba.nacos.plugin.auth.api.Resource;
import com.alibaba.nacos.plugin.auth.constant.ApiType;
import com.alibaba.nacos.plugin.auth.constant.Constants;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;

/**
 * request auth filter for remote.
 *
 * @author liuzunfei
 * @version $Id: RemoteRequestAuthFilter.java, v 0.1 2020年09月14日 12:38 PM liuzunfei Exp $
 */
@Component
public class RemoteRequestAuthFilter extends AbstractRequestFilter {
    
    private final NacosAuthConfig authConfig;
    
    private final GrpcProtocolAuthService protocolAuthService;
    
    private final InnerApiAuthEnabled innerApiAuthEnabled;
    
    public RemoteRequestAuthFilter(InnerApiAuthEnabled innerApiAuthEnabled) {
        this.innerApiAuthEnabled = innerApiAuthEnabled;
        this.authConfig = NacosAuthConfigHolder.getInstance()
                .getNacosAuthConfigByScope(NacosServerAuthConfig.NACOS_SERVER_AUTH_SCOPE);
        this.protocolAuthService = new GrpcProtocolAuthService(authConfig);
        this.protocolAuthService.initialize();
    }
    
    @Override
    public Response filter(Request request, RequestMeta meta, Class handlerClazz) throws NacosException {
        
        try {
            
            Method method = getHandleMethod(handlerClazz);
            if (method.isAnnotationPresent(Secured.class)) {
                Secured secured = method.getAnnotation(Secured.class);
                // During Upgrading, Old Nacos server might not with server identity for some Inner API, follow old version logic.
                if (ApiType.INNER_API.equals(secured.apiType()) && !innerApiAuthEnabled.isEnabled()) {
                    return null;
                }
                // Inner API must do check server identity. So judge api type not inner api and whether auth is enabled.
                if (ApiType.INNER_API != secured.apiType() && !authConfig.isAuthEnabled()) {
                    return null;
                }
                if (Loggers.AUTH.isDebugEnabled()) {
                    Loggers.AUTH.debug("auth start, request: {}", request.getClass().getSimpleName());
                }
                ServerIdentityResult identityResult = protocolAuthService.checkServerIdentity(request, secured);
                switch (identityResult.getStatus()) {
                    case FAIL:
                        Response defaultResponseInstance = getDefaultResponseInstance(handlerClazz);
                        defaultResponseInstance.setErrorInfo(NacosException.NO_RIGHT, identityResult.getMessage());
                        return defaultResponseInstance;
                    case MATCHED:
                        return null;
                    default:
                        break;
                }
                if (!protocolAuthService.enableAuth(secured)) {
                    return null;
                }
                String clientIp = meta.getClientIp();
                request.putHeader(Constants.Identity.X_REAL_IP, clientIp);
                Resource resource = protocolAuthService.parseResource(request, secured);
                IdentityContext identityContext = protocolAuthService.parseIdentity(request);
                AuthResult result = protocolAuthService.validateIdentity(identityContext, resource);
                RequestContext requestContext = RequestContextHolder.getContext();
                requestContext.getAuthContext().setIdentityContext(identityContext);
                requestContext.getAuthContext().setResource(resource);
                requestContext.getAuthContext().setAuthResult(result);
                if (!result.isSuccess()) {
                    throw new AccessException(result.format());
                }
                String action = secured.action().toString();
                result = protocolAuthService.validateAuthority(identityContext, new Permission(resource, action));
                if (!result.isSuccess()) {
                    throw new AccessException(result.format());
                }
            }
        } catch (AccessException e) {
            if (Loggers.AUTH.isDebugEnabled()) {
                Loggers.AUTH.debug("access denied, request: {}, reason: {}", request.getClass().getSimpleName(),
                        e.getErrMsg());
            }
            Response defaultResponseInstance = getDefaultResponseInstance(handlerClazz);
            defaultResponseInstance.setErrorInfo(NacosException.NO_RIGHT, e.getErrMsg());
            return defaultResponseInstance;
        } catch (Exception e) {
            Response defaultResponseInstance = getDefaultResponseInstance(handlerClazz);
            defaultResponseInstance.setErrorInfo(NacosException.SERVER_ERROR, ExceptionUtil.getAllExceptionMsg(e));
            return defaultResponseInstance;
        }
        
        return null;
    }
}
