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

package com.alibaba.nacos.common.ability;

import com.alibaba.nacos.api.ability.constant.AbilityKey;
import com.alibaba.nacos.api.ability.constant.AbilityMode;
import com.alibaba.nacos.api.ability.constant.AbilityStatus;
import com.alibaba.nacos.common.notify.Event;
import com.alibaba.nacos.common.notify.NotifyCenter;
import com.alibaba.nacos.common.notify.listener.Subscriber;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AbstractAbilityControlManagerTest {
    
    private AbstractAbilityControlManager abilityControlManager;
    
    private Subscriber<AbstractAbilityControlManager.AbilityUpdateEvent> mockSubscriber;
    
    private boolean isOn = true;
    
    private AssertionError assertionError;
    
    private boolean notified = false;
    
    @BeforeEach
    void setUp() throws Exception {
        mockSubscriber = new Subscriber<AbstractAbilityControlManager.AbilityUpdateEvent>() {
            @Override
            public void onEvent(AbstractAbilityControlManager.AbilityUpdateEvent event) {
                notified = true;
                try {
                    assertEquals(AbilityKey.SERVER_FUZZY_WATCH, event.getAbilityKey());
                    assertEquals(isOn, event.isOn());
                    assertEquals(2, event.getAbilityTable().size());
                    assertEquals(isOn, event.getAbilityTable().get(AbilityKey.SERVER_FUZZY_WATCH.getName()));
                } catch (AssertionError error) {
                    assertionError = error;
                }
            }
            
            @Override
            public Class<? extends Event> subscribeType() {
                return AbstractAbilityControlManager.AbilityUpdateEvent.class;
            }
        };
        abilityControlManager = new MockAbilityControlManager();
        NotifyCenter.registerSubscriber(mockSubscriber);
    }
    
    @AfterEach
    void tearDown() throws Exception {
        NotifyCenter.deregisterSubscriber(mockSubscriber);
        assertionError = null;
        notified = false;
    }
    
    @Test
    void testEnableCurrentNodeAbility() throws InterruptedException {
        isOn = true;
        abilityControlManager.enableCurrentNodeAbility(AbilityKey.SERVER_FUZZY_WATCH);
        TimeUnit.MILLISECONDS.sleep(1100);
        assertTrue(notified);
        if (null != assertionError) {
            throw assertionError;
        }
    }
    
    @Test
    void testDisableCurrentNodeAbility() throws InterruptedException {
        isOn = false;
        abilityControlManager.disableCurrentNodeAbility(AbilityKey.SERVER_FUZZY_WATCH);
        TimeUnit.MILLISECONDS.sleep(1100);
        assertTrue(notified);
        if (null != assertionError) {
            throw assertionError;
        }
    }
    
    @Test
    void testIsCurrentNodeAbilityRunning() {
        assertEquals(AbilityStatus.SUPPORTED, abilityControlManager.isCurrentNodeAbilityRunning(AbilityKey.SERVER_FUZZY_WATCH));
        assertEquals(AbilityStatus.NOT_SUPPORTED, abilityControlManager.isCurrentNodeAbilityRunning(AbilityKey.SERVER_DISTRIBUTED_LOCK));
        assertEquals(AbilityStatus.UNKNOWN, abilityControlManager.isCurrentNodeAbilityRunning(AbilityKey.SDK_CLIENT_FUZZY_WATCH));
    }
    
    @Test
    void testGetCurrentNodeAbilities() {
        Map<String, Boolean> actual = abilityControlManager.getCurrentNodeAbilities(AbilityMode.SERVER);
        assertEquals(2, actual.size());
        assertTrue(actual.containsKey(AbilityKey.SERVER_FUZZY_WATCH.getName()));
        assertTrue(actual.containsKey(AbilityKey.SERVER_DISTRIBUTED_LOCK.getName()));
        actual = abilityControlManager.getCurrentNodeAbilities(AbilityMode.SDK_CLIENT);
        assertTrue(actual.isEmpty());
    }
    
    @Test
    void testGetPriority() {
        assertEquals(Integer.MIN_VALUE, abilityControlManager.getPriority());
    }
    
    @Test
    void testInitFailed() {
        assertThrows(IllegalStateException.class, () -> {
            abilityControlManager = new AbstractAbilityControlManager() {
                @Override
                protected Map<AbilityMode, Map<AbilityKey, Boolean>> initCurrentNodeAbilities() {
                    Map<AbilityKey, Boolean> abilities = Collections.singletonMap(AbilityKey.SDK_CLIENT_FUZZY_WATCH, true);
                    return Collections.singletonMap(AbilityMode.SERVER, abilities);
                }
                
                @Override
                public int getPriority() {
                    return 0;
                }
            };
        });
    }
    
    private static final class MockAbilityControlManager extends AbstractAbilityControlManager {
        
        @Override
        protected Map<AbilityMode, Map<AbilityKey, Boolean>> initCurrentNodeAbilities() {
            Map<AbilityKey, Boolean> abilities = new HashMap<>(2);
            abilities.put(AbilityKey.SERVER_FUZZY_WATCH, true);
            abilities.put(AbilityKey.SERVER_DISTRIBUTED_LOCK, false);
            return Collections.singletonMap(AbilityMode.SERVER, abilities);
        }
        
        @Override
        public int getPriority() {
            return Integer.MIN_VALUE;
        }
    }
}