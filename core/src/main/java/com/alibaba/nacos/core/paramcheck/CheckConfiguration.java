/*
 * Copyright 1999-2023 Alibaba Group Holding Ltd.
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

package com.alibaba.nacos.core.paramcheck;

import com.alibaba.nacos.core.code.ControllerMethodsCache;
import com.alibaba.nacos.core.web.NacosWebBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * ParamCheckerFilter registration.
 *
 * @author 985492783@qq.com
 * @date 2023/11/7 17:52
 */
@Configuration
@NacosWebBean
public class CheckConfiguration {
    
    @Bean
    public FilterRegistrationBean<ParamCheckerFilter> checkerFilterRegistration(ParamCheckerFilter checkerFilter) {
        FilterRegistrationBean<ParamCheckerFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(checkerFilter);
        registration.addUrlPatterns("/*");
        registration.setName("checkerFilter");
        registration.setOrder(8);
        return registration;
    }
    
    @Bean
    public ParamCheckerFilter checkerFilter(ControllerMethodsCache methodsCache) {
        return new ParamCheckerFilter(methodsCache);
    }
}
