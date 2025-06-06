/*
 * Copyright 1999-2021 Alibaba Group Holding Ltd.
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

package com.alibaba.nacos.client.auth.ram.identify;

import com.alibaba.nacos.client.env.NacosClientProperties;
import com.alibaba.nacos.common.executor.ExecutorFactory;
import com.alibaba.nacos.common.executor.NameThreadFactory;
import com.alibaba.nacos.common.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Credential Watcher.
 *
 * @author Nacos
 */
public class CredentialWatcher {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialWatcher.class);
    
    private static final long REFRESH_INTERVAL = 10 * 1000L;
    
    private final CredentialService serviceInstance;
    
    private final String appName;
    
    private String propertyPath;
    
    private boolean stopped;
    
    private final ScheduledExecutorService executor;
    
    public CredentialWatcher(String appName, CredentialService serviceInstance) {
        this.appName = appName;
        this.serviceInstance = serviceInstance;
        loadCredential(true);
        
        executor = ExecutorFactory.newSingleScheduledExecutorService(
                new NameThreadFactory("com.alibaba.nacos.client.auth.ram.identify.watcher"));
        
        executor.scheduleWithFixedDelay(new Runnable() {
            private long modified = 0;
            
            @Override
            public void run() {
                synchronized (this) {
                    if (stopped) {
                        return;
                    }
                    boolean reload = false;
                    if (propertyPath == null) {
                        reload = true;
                    } else {
                        File file = new File(propertyPath);
                        long lastModified = file.lastModified();
                        if (modified != lastModified) {
                            reload = true;
                            modified = lastModified;
                        }
                    }
                    if (reload) {
                        loadCredential(false);
                    }
                }
            }
        }, REFRESH_INTERVAL, REFRESH_INTERVAL, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Stop watcher.
     */
    public void stop() {
        if (stopped) {
            return;
        }
        if (executor != null) {
            synchronized (executor) {
                stopped = true;
                executor.shutdown();
            }
        }
        LOGGER.info("[{}] {} is stopped", appName, this.getClass().getSimpleName());
    }
    
    private void loadCredential(boolean init) {
        loadPropertyPath(init);
        InputStream propertiesIs = loadPropertyPathToStream();
        Credentials credentials = new Credentials();
        boolean loadResult = Objects.isNull(propertiesIs) ? loadCredentialFromEnv(init, credentials)
                : loadCredentialFromProperties(propertiesIs, init, credentials);
        if (!loadResult) {
            return;
        }
        if (!credentials.valid()) {
            LOGGER
                    .warn("[1] Credential file missing required property {} Credential file missing {} or {}", appName,
                            IdentifyConstants.ACCESS_KEY, IdentifyConstants.SECRET_KEY);
            propertyPath = null;
            // return;
        }
        serviceInstance.setCredential(credentials);
    }
    
    private boolean loadCredentialFromProperties(InputStream propertiesIs, boolean init, Credentials credentials) {
        Properties properties = new Properties();
        try {
            properties.load(propertiesIs);
        } catch (IOException e) {
            LOGGER
                    .error("[26] Unable to load credential file, appName:" + appName + "Unable to load credential file "
                            + propertyPath, e);
            propertyPath = null;
            return false;
        } finally {
            try {
                propertiesIs.close();
            } catch (IOException e) {
                LOGGER.error("[27] Unable to close credential file, appName:" + appName
                        + "Unable to close credential file " + propertyPath, e);
            }
        }
        
        if (init) {
            LOGGER.info("[{}] Load credential file {}", appName, propertyPath);
        }
        
        String accessKey = null;
        String secretKey = null;
        String tenantId = null;
        if (!IdentifyConstants.DOCKER_CREDENTIAL_PATH.equals(propertyPath)) {
            if (properties.containsKey(IdentifyConstants.ACCESS_KEY)) {
                accessKey = properties.getProperty(IdentifyConstants.ACCESS_KEY);
            }
            if (properties.containsKey(IdentifyConstants.SECRET_KEY)) {
                secretKey = properties.getProperty(IdentifyConstants.SECRET_KEY);
            }
            if (properties.containsKey(IdentifyConstants.TENANT_ID)) {
                tenantId = properties.getProperty(IdentifyConstants.TENANT_ID);
            }
        } else {
            if (properties.containsKey(IdentifyConstants.DOCKER_ACCESS_KEY)) {
                accessKey = properties.getProperty(IdentifyConstants.DOCKER_ACCESS_KEY);
            }
            if (properties.containsKey(IdentifyConstants.DOCKER_SECRET_KEY)) {
                secretKey = properties.getProperty(IdentifyConstants.DOCKER_SECRET_KEY);
            }
            
            if (properties.containsKey(IdentifyConstants.DOCKER_TENANT_ID)) {
                tenantId = properties.getProperty(IdentifyConstants.DOCKER_TENANT_ID);
            }
        }
        setAccessKey(credentials, accessKey);
        setSecretKey(credentials, secretKey);
        setTenantId(credentials, tenantId);
        return true;
    }
    
    private boolean loadCredentialFromEnv(boolean init, Credentials credentials) {
        propertyPath = null;
        String accessKey = NacosClientProperties.PROTOTYPE.getProperty(IdentifyConstants.ENV_ACCESS_KEY);
        String secretKey = NacosClientProperties.PROTOTYPE.getProperty(IdentifyConstants.ENV_SECRET_KEY);
        if (accessKey == null && secretKey == null) {
            if (init) {
                LOGGER.info("{} No credential found", appName);
            }
            return false;
        }
        setAccessKey(credentials, accessKey);
        setSecretKey(credentials, secretKey);
        return true;
    }
    
    private void loadPropertyPath(boolean init) {
        if (propertyPath == null) {
            URL url = ClassLoader.getSystemResource(IdentifyConstants.PROPERTIES_FILENAME);
            if (url != null) {
                propertyPath = url.getPath();
            }
            if (propertyPath == null || propertyPath.isEmpty()) {
                
                String value = NacosClientProperties.PROTOTYPE.getProperty("spas.identity");
                if (StringUtils.isNotEmpty(value)) {
                    propertyPath = value;
                }
                if (propertyPath == null || propertyPath.isEmpty()) {
                    propertyPath =
                            IdentifyConstants.CREDENTIAL_PATH + (appName == null ? IdentifyConstants.CREDENTIAL_DEFAULT
                                    : appName);
                } else {
                    if (init) {
                        LOGGER.info("[{}] Defined credential file: -Dspas.identity={}", appName, propertyPath);
                    }
                }
            } else {
                if (init) {
                    LOGGER.info("[{}] Load credential file from classpath: {}", appName,
                            IdentifyConstants.PROPERTIES_FILENAME);
                }
            }
        }
    }
    
    private InputStream loadPropertyPathToStream() {
        InputStream propertiesIs = null;
        do {
            try {
                propertiesIs = new FileInputStream(propertyPath);
            } catch (FileNotFoundException e) {
                if (appName != null && !appName.equals(IdentifyConstants.CREDENTIAL_DEFAULT) && propertyPath
                        .equals(IdentifyConstants.CREDENTIAL_PATH + appName)) {
                    propertyPath = IdentifyConstants.CREDENTIAL_PATH + IdentifyConstants.CREDENTIAL_DEFAULT;
                    continue;
                }
                if (!IdentifyConstants.DOCKER_CREDENTIAL_PATH.equals(propertyPath)) {
                    propertyPath = IdentifyConstants.DOCKER_CREDENTIAL_PATH;
                    continue;
                }
            }
            break;
        } while (true);
        return propertiesIs;
    }
    
    private void setAccessKey(Credentials credentials, String accessKey) {
        if (!Objects.isNull(accessKey)) {
            credentials.setAccessKey(accessKey.trim());
        }
    }
    
    private void setSecretKey(Credentials credentials, String secretKey) {
        if (!Objects.isNull(secretKey)) {
            credentials.setSecretKey(secretKey.trim());
        }
    }
    
    private void setTenantId(Credentials credentials, String tenantId) {
        if (!Objects.isNull(tenantId)) {
            credentials.setTenantId(tenantId.trim());
        }
    }
}
