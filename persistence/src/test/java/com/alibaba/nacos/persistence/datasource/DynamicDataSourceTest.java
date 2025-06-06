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

package com.alibaba.nacos.persistence.datasource;

import com.alibaba.nacos.persistence.configuration.DatasourceConfiguration;
import com.alibaba.nacos.sys.env.EnvUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class DynamicDataSourceTest {
    
    @InjectMocks
    private DynamicDataSource dataSource;
    
    @Mock
    private LocalDataSourceServiceImpl localDataSourceService;
    
    @Mock
    private ExternalDataSourceServiceImpl basicDataSourceService;
    
    @BeforeEach
    void setUp() {
        EnvUtil.setEnvironment(new MockEnvironment());
        dataSource = DynamicDataSource.getInstance();
    }
    
    @AfterEach
    void tearDown() {
        DatasourceConfiguration.setEmbeddedStorage(true);
        DatasourceConfiguration.setUseExternalDb(false);
        ReflectionTestUtils.setField(dataSource, "localDataSourceService", null);
        ReflectionTestUtils.setField(dataSource, "basicDataSourceService", null);
        EnvUtil.setEnvironment(null);
    }
    
    @Test
    void testGetDataSourceWithAlreadyInitialized() {
        ReflectionTestUtils.setField(dataSource, "localDataSourceService", localDataSourceService);
        ReflectionTestUtils.setField(dataSource, "basicDataSourceService", basicDataSourceService);
        DatasourceConfiguration.setEmbeddedStorage(true);
        assertInstanceOf(LocalDataSourceServiceImpl.class, dataSource.getDataSource());
        
        DatasourceConfiguration.setEmbeddedStorage(false);
        assertInstanceOf(ExternalDataSourceServiceImpl.class, dataSource.getDataSource());
    }
    
    @Test
    void testInitWithEmbeddedStorage() {
        DatasourceConfiguration.setEmbeddedStorage(true);
        assertInstanceOf(LocalDataSourceServiceImpl.class, dataSource.getDataSource());
    }
    
    @Test
    void testInitWithExternalStorage() {
        DatasourceConfiguration.setEmbeddedStorage(false);
        assertInstanceOf(ExternalDataSourceServiceImpl.class, dataSource.getDataSource());
    }
    
    @Test
    void testInitWithException() {
        EnvUtil.setEnvironment(null);
        assertThrows(RuntimeException.class, () -> dataSource.getDataSource());
    }
}
