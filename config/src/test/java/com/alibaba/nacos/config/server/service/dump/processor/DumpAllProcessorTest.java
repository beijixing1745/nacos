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

package com.alibaba.nacos.config.server.service.dump.processor;

import com.alibaba.nacos.common.utils.MD5Utils;
import com.alibaba.nacos.config.server.model.CacheItem;
import com.alibaba.nacos.config.server.model.ConfigInfoWrapper;
import com.alibaba.nacos.config.server.service.ConfigCacheService;
import com.alibaba.nacos.config.server.service.ConfigMigrateService;
import com.alibaba.nacos.config.server.service.dump.ExternalDumpService;
import com.alibaba.nacos.config.server.service.dump.disk.ConfigDiskServiceFactory;
import com.alibaba.nacos.config.server.service.dump.task.DumpAllTask;
import com.alibaba.nacos.config.server.service.repository.ConfigInfoGrayPersistService;
import com.alibaba.nacos.config.server.service.repository.ConfigInfoPersistService;
import com.alibaba.nacos.config.server.utils.GroupKey2;
import com.alibaba.nacos.config.server.utils.PropertyUtil;
import com.alibaba.nacos.persistence.datasource.DataSourceService;
import com.alibaba.nacos.persistence.datasource.DynamicDataSource;
import com.alibaba.nacos.api.model.Page;
import com.alibaba.nacos.plugin.datasource.constants.CommonConstant;
import com.alibaba.nacos.sys.env.EnvUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.BeanUtils;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@Disabled(value = "Github CI will crash in this class unit test. "
        + "It is suspected that the inability to write to the disk is related to the invocation of System.exit.")
class DumpAllProcessorTest {
    
    private static int newConfigCount = 1;
    
    @Mock
    DynamicDataSource dynamicDataSource;
    
    @Mock
    DataSourceService dataSourceService;
    
    @Mock
    ConfigInfoGrayPersistService configInfoGrayPersistService;
    
    ConfigMigrateService configMigrateService;
    
    DumpAllProcessor dumpAllProcessor;
    
    ExternalDumpService dumpService;
    
    MockedStatic<DynamicDataSource> dynamicDataSourceMockedStatic;
    
    MockedStatic<PropertyUtil> propertyUtilMockedStatic;
    
    @Mock
    ConfigInfoPersistService configInfoPersistService;
    
    MockedStatic<EnvUtil> envUtilMockedStatic;
    
    private String mockMem = "tmpmocklimitfile.txt";
    
    @BeforeEach
    void init() throws Exception {
        dynamicDataSourceMockedStatic = Mockito.mockStatic(DynamicDataSource.class);
        envUtilMockedStatic = Mockito.mockStatic(EnvUtil.class);
        propertyUtilMockedStatic = Mockito.mockStatic(PropertyUtil.class);
        propertyUtilMockedStatic.when(PropertyUtil::getAllDumpPageSize).thenReturn(100);
        dumpAllProcessor = new DumpAllProcessor(configInfoPersistService);
        when(EnvUtil.getNacosHome()).thenReturn(System.getProperty("user.home"));
        when(EnvUtil.getProperty(eq(CommonConstant.NACOS_PLUGIN_DATASOURCE_LOG), eq(Boolean.class),
                eq(false))).thenReturn(false);
        dynamicDataSourceMockedStatic.when(DynamicDataSource::getInstance).thenReturn(dynamicDataSource);
        
        when(dynamicDataSource.getDataSource()).thenReturn(dataSourceService);
        
        dumpService = new ExternalDumpService(configInfoPersistService, null,
                null, configInfoGrayPersistService, null, configMigrateService);
        
        dumpAllProcessor = new DumpAllProcessor(configInfoPersistService);
        envUtilMockedStatic.when(() -> EnvUtil.getProperty(eq("memory_limit_file_path"),
                eq("/sys/fs/cgroup/memory/memory.limit_in_bytes"))).thenReturn(mockMem);
        
    }
    
    @AfterEach
    void after() throws Exception {
        dynamicDataSourceMockedStatic.close();
        envUtilMockedStatic.close();
        propertyUtilMockedStatic.close();
    }
    
    private ConfigInfoWrapper createNewConfig(int id) {
        ConfigInfoWrapper configInfoWrapper = new ConfigInfoWrapper();
        String dataId = "dataIdTime" + newConfigCount;
        configInfoWrapper.setDataId(dataId);
        String group = "groupTime" + newConfigCount;
        configInfoWrapper.setGroup(group);
        String tenant = "tenantTime" + newConfigCount;
        configInfoWrapper.setTenant(tenant);
        String content = "content " + newConfigCount;
        configInfoWrapper.setContent(content);
        configInfoWrapper.setId(id);
        newConfigCount++;
        return configInfoWrapper;
    }
    
    @Test
    void testDumpAllOnStartUp() throws Exception {
        ConfigInfoWrapper configInfoWrapper1 = createNewConfig(1);
        ConfigInfoWrapper configInfoWrapper2 = createNewConfig(2);
        long timestamp = System.currentTimeMillis();
        configInfoWrapper1.setLastModified(timestamp);
        configInfoWrapper2.setLastModified(timestamp);
        Page<ConfigInfoWrapper> page = new Page<>();
        page.setTotalCount(2);
        page.setPagesAvailable(2);
        page.setPageNumber(1);
        List<ConfigInfoWrapper> list = Arrays.asList(configInfoWrapper1, configInfoWrapper2);
        page.setPageItems(list);
        
        Mockito.when(configInfoPersistService.findConfigMaxId()).thenReturn(2L);
        Mockito.when(configInfoPersistService.findAllConfigInfoFragment(0, PropertyUtil.getAllDumpPageSize(), true))
                .thenReturn(page);
        
        // For config 1, assign a latter time, to make sure that it would be updated.
        // For config 2, assign an earlier time, to make sure that it is not be updated.
        String md51 = MD5Utils.md5Hex(configInfoWrapper1.getContent(), "UTF-8");
        String md52 = MD5Utils.md5Hex(configInfoWrapper2.getContent(), "UTF-8");
        long latterTimestamp = timestamp + 999;
        long earlierTimestamp = timestamp - 999;
        String encryptedDataKey = "testEncryptedDataKey";
        ConfigCacheService.dumpWithMd5(configInfoWrapper1.getDataId(), configInfoWrapper1.getGroup(),
                configInfoWrapper1.getTenant(), configInfoWrapper1.getContent(), md51, latterTimestamp, "json",
                encryptedDataKey);
        ConfigCacheService.dumpWithMd5(configInfoWrapper2.getDataId(), configInfoWrapper2.getGroup(),
                configInfoWrapper2.getTenant(), configInfoWrapper2.getContent(), md52, earlierTimestamp, "json",
                encryptedDataKey);
        
        DumpAllTask dumpAllTask = new DumpAllTask(true);
        
        boolean process = dumpAllProcessor.process(dumpAllTask);
        assertTrue(process);
        
        //Check cache
        CacheItem contentCache1 = ConfigCacheService.getContentCache(
                GroupKey2.getKey(configInfoWrapper1.getDataId(), configInfoWrapper1.getGroup(),
                        configInfoWrapper1.getTenant()));
        assertEquals(md51, contentCache1.getConfigCache().getMd5());
        // check if config1 is updated
        assertTrue(timestamp < contentCache1.getConfigCache().getLastModifiedTs());
        //check disk
        String contentFromDisk1 = ConfigDiskServiceFactory.getInstance()
                .getContent(configInfoWrapper1.getDataId(), configInfoWrapper1.getGroup(),
                        configInfoWrapper1.getTenant());
        assertEquals(configInfoWrapper1.getContent(), contentFromDisk1);
        
        //Check cache
        CacheItem contentCache2 = ConfigCacheService.getContentCache(
                GroupKey2.getKey(configInfoWrapper2.getDataId(), configInfoWrapper2.getGroup(),
                        configInfoWrapper2.getTenant()));
        assertEquals(MD5Utils.md5Hex(configInfoWrapper2.getContent(), "UTF-8"),
                contentCache2.getConfigCache().getMd5());
        // check if config2 is updated
        assertEquals(timestamp, contentCache2.getConfigCache().getLastModifiedTs());
        //check disk
        String contentFromDisk2 = ConfigDiskServiceFactory.getInstance()
                .getContent(configInfoWrapper2.getDataId(), configInfoWrapper2.getGroup(),
                        configInfoWrapper2.getTenant());
        assertEquals(configInfoWrapper2.getContent(), contentFromDisk2);
    }
    
    /**
     * test dump all for all check task.
     */
    @Test
    void testDumpAllOnCheckAll() throws Exception {
        ConfigInfoWrapper configInfoWrapper1 = createNewConfig(1);
        ConfigInfoWrapper configInfoWrapper2 = createNewConfig(2);
        long timestamp = System.currentTimeMillis();
        configInfoWrapper1.setLastModified(timestamp);
        configInfoWrapper2.setLastModified(timestamp);
        Page<ConfigInfoWrapper> page = new Page<>();
        page.setTotalCount(2);
        page.setPagesAvailable(2);
        page.setPageNumber(1);
        List<ConfigInfoWrapper> list = Arrays.asList(configInfoWrapper1, configInfoWrapper2);
        page.setPageItems(list);
        
        Mockito.when(configInfoPersistService.findConfigMaxId()).thenReturn(2L);
        Mockito.when(configInfoPersistService.findAllConfigInfoFragment(0, PropertyUtil.getAllDumpPageSize(), false))
                .thenReturn(page);
        
        ConfigInfoWrapper configInfoWrapperSingle1 = new ConfigInfoWrapper();
        BeanUtils.copyProperties(configInfoWrapper1, configInfoWrapperSingle1);
        configInfoWrapperSingle1.setContent("content123456");
        Mockito.when(
                configInfoPersistService.findConfigInfo(configInfoWrapper1.getDataId(), configInfoWrapper1.getGroup(),
                        configInfoWrapper1.getTenant())).thenReturn(configInfoWrapperSingle1);
        
        ConfigInfoWrapper configInfoWrapperSingle2 = new ConfigInfoWrapper();
        BeanUtils.copyProperties(configInfoWrapper2, configInfoWrapperSingle2);
        configInfoWrapperSingle2.setContent("content123456222");
        Mockito.when(
                configInfoPersistService.findConfigInfo(configInfoWrapper2.getDataId(), configInfoWrapper2.getGroup(),
                        configInfoWrapper2.getTenant())).thenReturn(configInfoWrapperSingle2);
        
        // For config 1, assign a latter time, to make sure that it would not be updated.
        // For config 2, assign an earlier time, to make sure that it would be updated.
        String md51 = MD5Utils.md5Hex(configInfoWrapper1.getContent(), "UTF-8");
        String md52 = MD5Utils.md5Hex(configInfoWrapper2.getContent(), "UTF-8");
        long latterTimestamp = timestamp + 999;
        long earlierTimestamp = timestamp - 999;
        String encryptedDataKey = "testEncryptedDataKey";
        ConfigCacheService.dumpWithMd5(configInfoWrapper1.getDataId(), configInfoWrapper1.getGroup(),
                configInfoWrapper1.getTenant(), configInfoWrapper1.getContent(), md51, latterTimestamp, "json",
                encryptedDataKey);
        ConfigCacheService.dumpWithMd5(configInfoWrapper2.getDataId(), configInfoWrapper2.getGroup(),
                configInfoWrapper2.getTenant(), configInfoWrapper2.getContent(), md52, earlierTimestamp, "json",
                encryptedDataKey);
        
        DumpAllTask dumpAllTask = new DumpAllTask(false);
        boolean process = dumpAllProcessor.process(dumpAllTask);
        
        assertTrue(process);
        
        //Check cache
        CacheItem contentCache1 = ConfigCacheService.getContentCache(
                GroupKey2.getKey(configInfoWrapper1.getDataId(), configInfoWrapper1.getGroup(),
                        configInfoWrapper1.getTenant()));
        // check if config1 is not updated
        assertEquals(md51, contentCache1.getConfigCache().getMd5());
        assertEquals(latterTimestamp, contentCache1.getConfigCache().getLastModifiedTs());
        //check disk
        String contentFromDisk1 = ConfigDiskServiceFactory.getInstance()
                .getContent(configInfoWrapper1.getDataId(), configInfoWrapper1.getGroup(),
                        configInfoWrapper1.getTenant());
        assertEquals(configInfoWrapper1.getContent(), contentFromDisk1);
        
        //Check cache
        CacheItem contentCache2 = ConfigCacheService.getContentCache(
                GroupKey2.getKey(configInfoWrapper2.getDataId(), configInfoWrapper2.getGroup(),
                        configInfoWrapper2.getTenant()));
        // check if config2 is updated
        assertEquals(MD5Utils.md5Hex(configInfoWrapperSingle2.getContent(), "UTF-8"),
                contentCache2.getConfigCache().getMd5());
        assertEquals(configInfoWrapper2.getLastModified(), contentCache2.getConfigCache().getLastModifiedTs());
        //check disk
        String contentFromDisk2 = ConfigDiskServiceFactory.getInstance()
                .getContent(configInfoWrapper2.getDataId(), configInfoWrapper2.getGroup(),
                        configInfoWrapper2.getTenant());
        assertEquals(configInfoWrapperSingle2.getContent(), contentFromDisk2);
    }
    
}
