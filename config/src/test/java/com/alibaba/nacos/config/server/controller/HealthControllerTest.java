/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
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

package com.alibaba.nacos.config.server.controller;

import com.alibaba.nacos.config.server.constant.Constants;
import com.alibaba.nacos.core.cluster.MemberLookup;
import com.alibaba.nacos.core.cluster.ServerMemberManager;
import com.alibaba.nacos.persistence.datasource.DataSourceService;
import com.alibaba.nacos.sys.env.EnvUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import jakarta.servlet.ServletContext;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = MockServletContext.class)
@WebAppConfiguration
class HealthControllerTest {
    
    @InjectMocks
    HealthController healthController;
    
    @Mock
    DataSourceService dataSourceService;
    
    private MockMvc mockmvc;
    
    @Mock
    private ServerMemberManager memberManager;
    
    @Mock
    private ServletContext servletContext;
    
    @Mock
    private MemberLookup memberLookup;
    
    @BeforeEach
    void setUp() {
        EnvUtil.setEnvironment(new StandardEnvironment());
        Map<String, Object> infos = new HashMap<>();
        infos.put("addressServerHealth", true);
        when(memberLookup.info()).thenReturn(infos);
        when(memberManager.getLookup()).thenReturn(memberLookup);
        when(servletContext.getContextPath()).thenReturn("/nacos");
        ReflectionTestUtils.setField(healthController, "memberManager", memberManager);
        ReflectionTestUtils.setField(healthController, "dataSourceService", dataSourceService);
        mockmvc = MockMvcBuilders.standaloneSetup(healthController).build();
    }
    
    @Test
    void testGetHealth() throws Exception {
        
        when(dataSourceService.getHealth()).thenReturn("UP");
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get(Constants.HEALTH_CONTROLLER_PATH);
        String actualValue = mockmvc.perform(builder).andReturn().getResponse().getContentAsString();
        assertEquals("UP", actualValue);
        
    }
    
    @Test
    void testGetHealthWhenTheLookUpIsNull() throws Exception {
        when(dataSourceService.getHealth()).thenReturn("UP");
        when(memberManager.getLookup()).thenReturn(null);
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get(Constants.HEALTH_CONTROLLER_PATH);
        String actualValue = mockmvc.perform(builder).andReturn().getResponse().getContentAsString();
        assertEquals("DOWN:address server down. ", actualValue);
    }
    
    @Test
    void testGetHealthWhenTheLoopUpNotUseAddressServer() throws Exception {
        when(dataSourceService.getHealth()).thenReturn("UP");
        when(memberManager.getLookup()).thenReturn(memberLookup);
        when(memberLookup.useAddressServer()).thenReturn(false);
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get(Constants.HEALTH_CONTROLLER_PATH);
        String actualValue = mockmvc.perform(builder).andReturn().getResponse().getContentAsString();
        assertEquals("UP", actualValue);
    }
    
    @Test
    void testGetHealthWhenTheLoopUpInfoIsNull() throws Exception {
        when(dataSourceService.getHealth()).thenReturn("UP");
        when(memberManager.getLookup()).thenReturn(memberLookup);
        when(memberLookup.useAddressServer()).thenReturn(true);
        when(memberLookup.info()).thenReturn(null);
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get(Constants.HEALTH_CONTROLLER_PATH);
        String actualValue = mockmvc.perform(builder).andReturn().getResponse().getContentAsString();
        assertEquals("DOWN:address server down. ", actualValue);
    }
    
    @Test
    void testGetHealthWhenTheLoopUpInfoIsEmpty() throws Exception {
        when(dataSourceService.getHealth()).thenReturn("UP");
        when(memberManager.getLookup()).thenReturn(memberLookup);
        when(memberLookup.useAddressServer()).thenReturn(true);
        when(memberLookup.info()).thenReturn(new HashMap<>());
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get(Constants.HEALTH_CONTROLLER_PATH);
        String actualValue = mockmvc.perform(builder).andReturn().getResponse().getContentAsString();
        assertEquals("DOWN:address server down. ", actualValue);
    }
    
    @Test
    void testGetHealthWhenTheLoopUpInfoIsDown() throws Exception {
        when(dataSourceService.getHealth()).thenReturn("UP");
        when(memberManager.getLookup()).thenReturn(memberLookup);
        when(memberLookup.useAddressServer()).thenReturn(true);
        
        final HashMap<String, Object> info = new HashMap<>();
        info.put("addressServerHealth", "false");
        when(memberLookup.info()).thenReturn(info);
        
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get(Constants.HEALTH_CONTROLLER_PATH);
        String actualValue = mockmvc.perform(builder).andReturn().getResponse().getContentAsString();
        assertEquals("DOWN:address server down. ", actualValue);
    }
    
    @Test
    void testGetHealthWhenTheLoopUpInfoIsUP() throws Exception {
        when(dataSourceService.getHealth()).thenReturn("UP");
        when(memberManager.getLookup()).thenReturn(memberLookup);
        when(memberLookup.useAddressServer()).thenReturn(true);
        
        final HashMap<String, Object> info = new HashMap<>();
        info.put("addressServerHealth", "true");
        when(memberLookup.info()).thenReturn(info);
        
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get(Constants.HEALTH_CONTROLLER_PATH);
        String actualValue = mockmvc.perform(builder).andReturn().getResponse().getContentAsString();
        assertEquals("UP", actualValue);
    }
    
    @Test
    void testGetHealthWhenTheLoopUpInfoParseError() throws Exception {
        when(dataSourceService.getHealth()).thenReturn("UP");
        when(memberManager.getLookup()).thenReturn(memberLookup);
        when(memberLookup.useAddressServer()).thenReturn(true);
        
        final HashMap<String, Object> info = new HashMap<>();
        info.put("addressServerHealth", "not boolean value");
        when(memberLookup.info()).thenReturn(info);
        
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get(Constants.HEALTH_CONTROLLER_PATH);
        String actualValue = mockmvc.perform(builder).andReturn().getResponse().getContentAsString();
        assertEquals("DOWN:address server down. ", actualValue);
    }
}
