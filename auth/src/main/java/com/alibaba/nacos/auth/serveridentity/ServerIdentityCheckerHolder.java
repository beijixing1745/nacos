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

package com.alibaba.nacos.auth.serveridentity;

import com.alibaba.nacos.common.spi.NacosServiceLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.util.Collection;

/**
 * Server Identity Checker SPI holder.
 *
 * @author xiweng.yy
 */
public class ServerIdentityCheckerHolder {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(ServerIdentityCheckerHolder.class);
    
    private static final ServerIdentityCheckerHolder INSTANCE = new ServerIdentityCheckerHolder();
    
    private Class<? extends ServerIdentityChecker> checkerClass;
    
    private ServerIdentityCheckerHolder() {
        tryGetCheckerBySpi();
    }
    
    public static ServerIdentityCheckerHolder getInstance() {
        return INSTANCE;
    }
    
    /**
     * Build a new checker.
     *
     * @return new checker instance.
     */
    public ServerIdentityChecker newChecker() {
        try {
            return checkerClass.getDeclaredConstructor(new Class[0]).newInstance();
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            return new DefaultChecker();
        }
    }
    
    private synchronized void tryGetCheckerBySpi() {
        Collection<ServerIdentityChecker> checkers = NacosServiceLoader.load(ServerIdentityChecker.class);
        if (checkers.isEmpty()) {
            checkerClass = DefaultChecker.class;
            LOGGER.info("Not found ServerIdentityChecker implementation from SPI, use default.");
            return;
        }
        if (checkers.size() > 1) {
            checkerClass = showAllImplementations(checkers);
            return;
        }
        checkerClass = checkers.iterator().next().getClass();
        LOGGER.info("Found ServerIdentityChecker implementation {}", checkerClass.getClass().getCanonicalName());
    }
    
    private Class<? extends ServerIdentityChecker> showAllImplementations(Collection<ServerIdentityChecker> checkers) {
        ServerIdentityChecker result = checkers.iterator().next();
        for (ServerIdentityChecker each : checkers) {
            LOGGER.warn("Found ServerIdentityChecker implementation {}", each.getClass().getCanonicalName());
        }
        LOGGER.warn("Found more than one ServerIdentityChecker implementation from SPI, use the first one {}.",
                result.getClass().getCanonicalName());
        return result.getClass();
    }
}
