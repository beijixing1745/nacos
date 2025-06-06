/*
 * Copyright 1999-2025 Alibaba Group Holding Ltd.
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

package com.alibaba.nacos.console.handler.impl.remote;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.auth.config.NacosAuthConfigHolder;
import com.alibaba.nacos.common.http.client.NacosRestTemplate;
import com.alibaba.nacos.console.config.NacosConsoleAuthConfig;
import com.alibaba.nacos.plugin.auth.api.LoginIdentityContext;
import com.alibaba.nacos.plugin.auth.api.RequestResource;
import com.alibaba.nacos.plugin.auth.spi.client.AbstractClientAuthService;

import java.util.List;
import java.util.Properties;

/**
 * Client Auth Plugin implementation for console remote maintainer client.
 *
 * @author xiweng.yy
 */
public class ConsoleMaintainerClientAuthPlugin extends AbstractClientAuthService {
    
    private LoginIdentityContext identityContext = new LoginIdentityContext();
    
    @Override
    public Boolean login(Properties properties) {
        NacosConsoleAuthConfig authConfig = (NacosConsoleAuthConfig) NacosAuthConfigHolder.getInstance()
                .getNacosAuthConfigByScope(NacosConsoleAuthConfig.NACOS_CONSOLE_AUTH_SCOPE);
        if (authConfig.isSupportServerIdentity()) {
            identityContext.setParameter(authConfig.getServerIdentityKey(), authConfig.getServerIdentityValue());
        }
        return true;
    }
    
    @Override
    public void setServerList(List<String> serverList) {
    }
    
    @Override
    public void setNacosRestTemplate(NacosRestTemplate nacosRestTemplate) {
    }
    
    @Override
    public LoginIdentityContext getLoginIdentityContext(RequestResource resource) {
        return identityContext;
    }
    
    @Override
    public void shutdown() throws NacosException {
    
    }
}
