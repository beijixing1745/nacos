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

package com.alibaba.nacos.naming.controllers;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.naming.CommonParams;
import com.alibaba.nacos.common.notify.Event;
import com.alibaba.nacos.common.notify.NotifyCenter;
import com.alibaba.nacos.common.notify.listener.SmartSubscriber;
import com.alibaba.nacos.common.trace.event.naming.UpdateServiceTraceEvent;
import com.alibaba.nacos.naming.BaseTest;
import com.alibaba.nacos.naming.core.ServiceOperatorV2Impl;
import com.alibaba.nacos.naming.core.SubscribeManager;
import com.alibaba.nacos.naming.pojo.Subscriber;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

@ExtendWith(MockitoExtension.class)
class ServiceControllerTest extends BaseTest {
    
    @InjectMocks
    private ServiceController serviceController;
    
    @Mock
    private ServiceOperatorV2Impl serviceOperatorV2;
    
    @Mock
    private SubscribeManager subscribeManager;
    
    private SmartSubscriber subscriber;
    
    private volatile Class<? extends Event> eventReceivedClass;
    
    @BeforeEach
    public void before() {
        super.before();
        subscriber = new SmartSubscriber() {
            @Override
            public List<Class<? extends Event>> subscribeTypes() {
                List<Class<? extends Event>> result = new LinkedList<>();
                result.add(UpdateServiceTraceEvent.class);
                return result;
            }
            
            @Override
            public void onEvent(Event event) {
                eventReceivedClass = event.getClass();
            }
        };
        NotifyCenter.registerSubscriber(subscriber);
    }
    
    @AfterEach
    void tearDown() throws Exception {
        NotifyCenter.deregisterSubscriber(subscriber);
        NotifyCenter.deregisterPublisher(UpdateServiceTraceEvent.class);
        eventReceivedClass = null;
    }
    
    @Test
    void testList() throws Exception {
        
        Mockito.when(serviceOperatorV2.listService(Mockito.anyString(), Mockito.anyString(), Mockito.anyString()))
                .thenReturn(Collections.singletonList("DEFAULT_GROUP@@providers:com.alibaba.nacos.controller.test:1"));
        
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.addParameter("pageNo", "1");
        servletRequest.addParameter("pageSize", "10");
        
        ObjectNode objectNode = serviceController.list(servletRequest);
        assertEquals(1, objectNode.get("count").asInt());
    }
    
    @Test
    void testCreate() {
        try {
            String res = serviceController.create(TEST_NAMESPACE, TEST_SERVICE_NAME, 0, "", "");
            assertEquals("ok", res);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    @Test
    void testRemove() {
        try {
            String res = serviceController.remove(TEST_NAMESPACE, TEST_SERVICE_NAME);
            assertEquals("ok", res);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    @Test
    void testDetail() {
        try {
            ObjectNode result = Mockito.mock(ObjectNode.class);
            Mockito.when(serviceOperatorV2.queryService(Mockito.anyString(), Mockito.anyString())).thenReturn(result);
            
            ObjectNode objectNode = serviceController.detail(TEST_NAMESPACE, TEST_SERVICE_NAME);
            assertEquals(result, objectNode);
        } catch (NacosException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    @Test
    void testUpdate() throws Exception {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.addParameter(CommonParams.SERVICE_NAME, TEST_SERVICE_NAME);
        servletRequest.addParameter("protectThreshold", "0.01");
        try {
            String res = serviceController.update(servletRequest);
            assertEquals("ok", res);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
        TimeUnit.MILLISECONDS.sleep(1200L);
        assertEquals(UpdateServiceTraceEvent.class, eventReceivedClass);
    }
    
    @Test
    void testSearchService() {
        try {
            Mockito.when(serviceOperatorV2.searchServiceName(Mockito.anyString(), Mockito.anyString()))
                    .thenReturn(Collections.singletonList("result"));
            
            ObjectNode objectNode = serviceController.searchService(TEST_NAMESPACE, "");
            assertEquals(1, objectNode.get("count").asInt());
        } catch (NacosException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
        
        try {
            Mockito.when(serviceOperatorV2.searchServiceName(Mockito.anyString(), Mockito.anyString()))
                    .thenReturn(Arrays.asList("re1", "re2"));
            Mockito.when(serviceOperatorV2.listAllNamespace()).thenReturn(Arrays.asList("re1", "re2"));
            
            ObjectNode objectNode = serviceController.searchService(null, "");
            assertEquals(4, objectNode.get("count").asInt());
        } catch (NacosException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    @Test
    void testSubscribers() {
        Mockito.when(subscribeManager.getSubscribers(Mockito.anyString(), Mockito.anyString(), Mockito.anyBoolean()))
                .thenReturn(Collections.singletonList(Mockito.mock(Subscriber.class)));
        
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.addParameter(CommonParams.SERVICE_NAME, TEST_SERVICE_NAME);
        
        ObjectNode objectNode = serviceController.subscribers(servletRequest);
        assertEquals(1, objectNode.get("count").asInt());
    }
}
