/*
 *   Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package com.alibaba.nacos.client.config;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.config.ConfigType;
import com.alibaba.nacos.api.config.listener.ConfigFuzzyWatchChangeEvent;
import com.alibaba.nacos.api.config.listener.FuzzyWatchEventWatcher;
import com.alibaba.nacos.api.config.listener.Listener;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.client.config.filter.impl.ConfigResponse;
import com.alibaba.nacos.client.config.impl.ClientWorker;
import com.alibaba.nacos.client.config.impl.ConfigFuzzyWatchContext;
import com.alibaba.nacos.client.config.impl.ConfigServerListManager;
import com.alibaba.nacos.client.config.impl.ConfigTransportClient;
import com.alibaba.nacos.client.config.impl.LocalConfigInfoProcessor;
import com.alibaba.nacos.client.env.NacosClientProperties;
import com.alibaba.nacos.common.utils.FuzzyGroupKeyPattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;

import static com.alibaba.nacos.api.common.Constants.ANY_PATTERN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NacosConfigServiceTest {
    
    private NacosConfigService nacosConfigService;
    
    private ClientWorker mockWoker;
    
    private void setFinal(Field field, Object ins, Object newValue) throws Exception {
        field.setAccessible(true);
        field.set(ins, newValue);
        field.setAccessible(false);
        
    }
    
    @BeforeEach
    void mock() throws Exception {
        final Properties properties = new Properties();
        properties.put("serverAddr", "1.1.1.1");
        nacosConfigService = new NacosConfigService(properties);
        mockWoker = Mockito.mock(ClientWorker.class);
        setFinal(NacosConfigService.class.getDeclaredField("worker"), nacosConfigService, mockWoker);
    }
    
    @AfterEach
    void clean() {
        LocalConfigInfoProcessor.cleanAllSnapshot();
    }
    
    @Test
    void testGetConfigFromServer() throws NacosException {
        final String dataId = "1";
        final String group = "2";
        final String tenant = "public";
        final int timeout = 3000;
        ConfigResponse response = new ConfigResponse();
        response.setContent("aa");
        response.setConfigType("bb");
        Mockito.when(mockWoker.getServerConfig(dataId, group, tenant, timeout, false)).thenReturn(response);
        final String config = nacosConfigService.getConfig(dataId, group, timeout);
        assertEquals("aa", config);
        Mockito.verify(mockWoker, Mockito.times(1)).getServerConfig(dataId, group, tenant, timeout, false);
        
    }
    
    @Test
    void testGetConfigFromFailOver() throws NacosException {
        final String dataId = "1failover";
        final String group = "2";
        final String tenant = "public";
        
        MockedStatic<LocalConfigInfoProcessor> localConfigInfoProcessorMockedStatic = Mockito.mockStatic(
                LocalConfigInfoProcessor.class);
        try {
            String contentFailOver = "failOverContent" + System.currentTimeMillis();
            localConfigInfoProcessorMockedStatic.when(
                    () -> LocalConfigInfoProcessor.getFailover(any(), eq(dataId), eq(group), eq(tenant)))
                    .thenReturn(contentFailOver);
            final int timeout = 3000;
            
            final String config = nacosConfigService.getConfig(dataId, group, timeout);
            assertEquals(contentFailOver, config);
        } finally {
            localConfigInfoProcessorMockedStatic.close();
        }
    }
    
    @Test
    void testGetConfigFromLocalCache() throws NacosException {
        final String dataId = "1localcache";
        final String group = "2";
        final String tenant = "public";
        
        MockedStatic<LocalConfigInfoProcessor> localConfigInfoProcessorMockedStatic = Mockito.mockStatic(
                LocalConfigInfoProcessor.class);
        try {
            String contentFailOver = "localCacheContent" + System.currentTimeMillis();
            //fail over null
            localConfigInfoProcessorMockedStatic.when(
                    () -> LocalConfigInfoProcessor.getFailover(any(), eq(dataId), eq(group), eq(tenant)))
                    .thenReturn(null);
            //snapshot content
            localConfigInfoProcessorMockedStatic.when(
                    () -> LocalConfigInfoProcessor.getSnapshot(any(), eq(dataId), eq(group), eq(tenant)))
                    .thenReturn(contentFailOver);
            //form server error.
            final int timeout = 3000;
            Mockito.when(mockWoker.getServerConfig(dataId, group, tenant, timeout, false))
                    .thenThrow(new NacosException());
            
            final String config = nacosConfigService.getConfig(dataId, group, timeout);
            assertEquals(contentFailOver, config);
        } finally {
            localConfigInfoProcessorMockedStatic.close();
        }
        
    }
    
    @Test
    void testGetConfig403() throws NacosException {
        final String dataId = "1localcache403";
        final String group = "2";
        final String tenant = "public";
        
        MockedStatic<LocalConfigInfoProcessor> localConfigInfoProcessorMockedStatic = Mockito.mockStatic(
                LocalConfigInfoProcessor.class);
        try {
            //fail over null
            localConfigInfoProcessorMockedStatic.when(
                    () -> LocalConfigInfoProcessor.getFailover(any(), eq(dataId), eq(group), eq(tenant)))
                    .thenReturn(null);
            
            //form server error.
            final int timeout = 3000;
            Mockito.when(mockWoker.getServerConfig(dataId, group, tenant, timeout, false))
                    .thenThrow(new NacosException(NacosException.NO_RIGHT, "no right"));
            try {
                nacosConfigService.getConfig(dataId, group, timeout);
                assertTrue(false);
            } catch (NacosException e) {
                assertEquals(NacosException.NO_RIGHT, e.getErrCode());
            }
        } finally {
            localConfigInfoProcessorMockedStatic.close();
        }
    }
    
    @Test
    void testGetConfigAndSignListener() throws NacosException {
        final String dataId = "1";
        final String group = "2";
        final String tenant = "";
        final String content = "123";
        final int timeout = 3000;
        final Listener listener = new Listener() {
            @Override
            public Executor getExecutor() {
                return null;
            }
            
            @Override
            public void receiveConfigInfo(String configInfo) {
            
            }
        };
        
        Properties properties = new Properties();
        properties.put(PropertyKeyConst.SERVER_ADDR, "aaa");
        final NacosClientProperties nacosProperties = NacosClientProperties.PROTOTYPE.derive(properties);
        ConfigServerListManager mgr = new ConfigServerListManager(nacosProperties);
        mgr.start();
        ConfigTransportClient client = new ConfigTransportClient(nacosProperties, mgr) {
            @Override
            public void startInternal() throws NacosException {
                // NOOP
            }
            
            @Override
            public String getName() {
                return "TestConfigTransportClient";
            }
            
            @Override
            public void notifyListenConfig() {
                // NOOP
            }
            
            @Override
            public void executeConfigListen() {
                // NOOP
            }
            
            @Override
            public void removeCache(String dataId, String group) {
                // NOOP
            }
            
            @Override
            public ConfigResponse queryConfig(String dataId, String group, String tenant, long readTimeous,
                    boolean notify) throws NacosException {
                ConfigResponse configResponse = new ConfigResponse();
                configResponse.setContent(content);
                configResponse.setDataId(dataId);
                configResponse.setGroup(group);
                configResponse.setTenant(tenant);
                return configResponse;
            }
            
            @Override
            public boolean publishConfig(String dataId, String group, String tenant, String appName, String tag,
                    String betaIps, String content, String encryptedDataKey, String casMd5, String type)
                    throws NacosException {
                return false;
            }
            
            @Override
            public boolean removeConfig(String dataId, String group, String tenant, String tag) throws NacosException {
                return false;
            }
        };
        Mockito.when(mockWoker.getAgent()).thenReturn(client);
        
        final String config = nacosConfigService.getConfigAndSignListener(dataId, group, timeout, listener);
        assertEquals(content, config);
        
        Mockito.verify(mockWoker, Mockito.times(1))
                .addTenantListenersWithContent(dataId, group, content, null, Collections.singletonList(listener));
        assertEquals(content, config);
        
        Mockito.verify(mockWoker, Mockito.times(1))
                .addTenantListenersWithContent(dataId, group, content, null, Arrays.asList(listener));
    }
    
    @Test
    void testAddListener() throws NacosException {
        String dataId = "1";
        String group = "2";
        Listener listener = new Listener() {
            @Override
            public Executor getExecutor() {
                return null;
            }
            
            @Override
            public void receiveConfigInfo(String configInfo) {
            
            }
        };
        
        nacosConfigService.addListener(dataId, group, listener);
        Mockito.verify(mockWoker, Mockito.times(1)).addTenantListeners(dataId, group, Arrays.asList(listener));
    }
    
    @Test
    void testPublishConfig() throws NacosException {
        String dataId = "1";
        String group = "2";
        String content = "123";
        String namespace = "public";
        String type = ConfigType.getDefaultType().getType();
        Mockito.when(mockWoker.publishConfig(dataId, group, namespace, null, null, null, content, "", null, type))
                .thenReturn(true);
        
        final boolean b = nacosConfigService.publishConfig(dataId, group, content);
        assertTrue(b);
        
        Mockito.verify(mockWoker, Mockito.times(1))
                .publishConfig(dataId, group, namespace, null, null, null, content, "", null, type);
    }
    
    @Test
    void testPublishConfig2() throws NacosException {
        String dataId = "1";
        String group = "2";
        String content = "123";
        String namespace = "public";
        String type = ConfigType.PROPERTIES.getType();
        
        Mockito.when(mockWoker.publishConfig(dataId, group, namespace, null, null, null, content, "", null, type))
                .thenReturn(true);
        
        final boolean b = nacosConfigService.publishConfig(dataId, group, content, type);
        assertTrue(b);
        
        Mockito.verify(mockWoker, Mockito.times(1))
                .publishConfig(dataId, group, namespace, null, null, null, content, "", null, type);
    }
    
    @Test
    void testPublishConfigCas() throws NacosException {
        String dataId = "1";
        String group = "2";
        String content = "123";
        String namespace = "public";
        String casMd5 = "96147704e3cb8be8597d55d75d244a02";
        String type = ConfigType.getDefaultType().getType();
        
        Mockito.when(mockWoker.publishConfig(dataId, group, namespace, null, null, null, content, "", casMd5, type))
                .thenReturn(true);
        
        final boolean b = nacosConfigService.publishConfigCas(dataId, group, content, casMd5);
        assertTrue(b);
        
        Mockito.verify(mockWoker, Mockito.times(1))
                .publishConfig(dataId, group, namespace, null, null, null, content, "", casMd5, type);
    }
    
    @Test
    void testPublishConfigCas2() throws NacosException {
        String dataId = "1";
        String group = "2";
        String content = "123";
        String namespace = "public";
        String casMd5 = "96147704e3cb8be8597d55d75d244a02";
        String type = ConfigType.PROPERTIES.getType();
        
        Mockito.when(mockWoker.publishConfig(dataId, group, namespace, null, null, null, content, "", casMd5, type))
                .thenReturn(true);
        
        final boolean b = nacosConfigService.publishConfigCas(dataId, group, content, casMd5, type);
        assertTrue(b);
        
        Mockito.verify(mockWoker, Mockito.times(1))
                .publishConfig(dataId, group, namespace, null, null, null, content, "", casMd5, type);
    }
    
    @Test
    void testRemoveConfig() throws NacosException {
        String dataId = "1";
        String group = "2";
        String tenant = "public";
        
        Mockito.when(mockWoker.removeConfig(dataId, group, tenant, null)).thenReturn(true);
        
        final boolean b = nacosConfigService.removeConfig(dataId, group);
        assertTrue(b);
        
        Mockito.verify(mockWoker, Mockito.times(1)).removeConfig(dataId, group, tenant, null);
    }
    
    @Test
    void testRemoveListener() {
        String dataId = "1";
        String group = "2";
        Listener listener = new Listener() {
            @Override
            public Executor getExecutor() {
                return null;
            }
            
            @Override
            public void receiveConfigInfo(String configInfo) {
            
            }
        };
        
        nacosConfigService.removeListener(dataId, group, listener);
        Mockito.verify(mockWoker, Mockito.times(1)).removeTenantListener(dataId, group, listener);
    }
    
    @Test
    void testGetServerStatus() {
        Mockito.when(mockWoker.isHealthServer()).thenReturn(true);
        assertEquals("UP", nacosConfigService.getServerStatus());
        Mockito.verify(mockWoker, Mockito.times(1)).isHealthServer();
        
        Mockito.when(mockWoker.isHealthServer()).thenReturn(false);
        assertEquals("DOWN", nacosConfigService.getServerStatus());
        Mockito.verify(mockWoker, Mockito.times(2)).isHealthServer();
        
    }
    
    @Test
    void testFuzzyWatch1() throws NacosException {
        String groupNamePattern = "default_group";
        FuzzyWatchEventWatcher fuzzyWatchEventWatcher = new FuzzyWatchEventWatcher() {
            @Override
            public void onEvent(ConfigFuzzyWatchChangeEvent event) {
            
            }
            
            @Override
            public Executor getExecutor() {
                return null;
            }
        };
        ConfigFuzzyWatchContext context = Mockito.mock(ConfigFuzzyWatchContext.class);
        Mockito.when(mockWoker.addTenantFuzzyWatcher(anyString(), anyString(), any())).thenReturn(context);
        nacosConfigService.fuzzyWatch(groupNamePattern, fuzzyWatchEventWatcher);
        Mockito.verify(mockWoker, Mockito.times(1))
                .addTenantFuzzyWatcher(ANY_PATTERN, groupNamePattern, fuzzyWatchEventWatcher);
        Mockito.verify(context, Mockito.times(1)).createNewFuture();
    }
    
    @Test
    void testFuzzyWatch2() throws NacosException {
        String groupNamePattern = "default_group";
        String dataIdPattern = "dataId*";
        FuzzyWatchEventWatcher fuzzyWatchEventWatcher = new FuzzyWatchEventWatcher() {
            @Override
            public void onEvent(ConfigFuzzyWatchChangeEvent event) {
            
            }
            
            @Override
            public Executor getExecutor() {
                return null;
            }
        };
        ConfigFuzzyWatchContext context = Mockito.mock(ConfigFuzzyWatchContext.class);
        Mockito.when(mockWoker.addTenantFuzzyWatcher(anyString(), anyString(), any())).thenReturn(context);
        nacosConfigService.fuzzyWatch(dataIdPattern, groupNamePattern, fuzzyWatchEventWatcher);
        Mockito.verify(mockWoker, Mockito.times(1))
                .addTenantFuzzyWatcher(dataIdPattern, groupNamePattern, fuzzyWatchEventWatcher);
        Mockito.verify(context, Mockito.times(1)).createNewFuture();
    }
    
    @Test
    void testFuzzyWatch3() throws NacosException {
        String groupNamePattern = "group";
        String dataIdPattern = "dataId*";
        String namespace = "public";
        FuzzyWatchEventWatcher fuzzyWatchEventWatcher = new FuzzyWatchEventWatcher() {
            @Override
            public void onEvent(ConfigFuzzyWatchChangeEvent event) {
            
            }
            
            @Override
            public Executor getExecutor() {
                return null;
            }
        };
        String patternKey = FuzzyGroupKeyPattern.generatePattern(dataIdPattern, groupNamePattern, namespace);
        ConfigFuzzyWatchContext context = new ConfigFuzzyWatchContext("", patternKey);
        Mockito.when(mockWoker.addTenantFuzzyWatcher(anyString(), anyString(), any())).thenReturn(context);
        Future<Set<String>> setFuture = nacosConfigService.fuzzyWatchWithGroupKeys(groupNamePattern,
                fuzzyWatchEventWatcher);
        Mockito.verify(mockWoker, Mockito.times(1))
                .addTenantFuzzyWatcher(ANY_PATTERN, groupNamePattern, fuzzyWatchEventWatcher);
        Assertions.assertNotNull(setFuture);
    }
    
    @Test
    void testFuzzyWatch4() throws NacosException {
        String groupNamePattern = "group";
        String dataIdPattern = "dataId*";
        String namespace = "public";
        FuzzyWatchEventWatcher fuzzyWatchEventWatcher = new FuzzyWatchEventWatcher() {
            @Override
            public void onEvent(ConfigFuzzyWatchChangeEvent event) {
            
            }
            
            @Override
            public Executor getExecutor() {
                return null;
            }
        };
        String patternKey = FuzzyGroupKeyPattern.generatePattern(dataIdPattern, groupNamePattern, namespace);
        ConfigFuzzyWatchContext context = new ConfigFuzzyWatchContext("", patternKey);
        Mockito.when(mockWoker.addTenantFuzzyWatcher(anyString(), anyString(), any())).thenReturn(context);
        Future<Set<String>> setFuture = nacosConfigService.fuzzyWatchWithGroupKeys(dataIdPattern, groupNamePattern,
                fuzzyWatchEventWatcher);
        Mockito.verify(mockWoker, Mockito.times(1))
                .addTenantFuzzyWatcher(dataIdPattern, groupNamePattern, fuzzyWatchEventWatcher);
        Assertions.assertNotNull(setFuture);
    }

    @Test
    void testShutDown() {
        Assertions.assertDoesNotThrow(() -> {
            nacosConfigService.shutDown();
        });
    }
}
