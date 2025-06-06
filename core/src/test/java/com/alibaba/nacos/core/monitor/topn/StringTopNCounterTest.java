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

package com.alibaba.nacos.core.monitor.topn;

import com.alibaba.nacos.common.event.ServerConfigChangeEvent;
import com.alibaba.nacos.common.utils.Pair;
import com.alibaba.nacos.sys.env.EnvUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * unit test for TopNCounterMetricsContainer.
 *
 * @author <a href="mailto:liuyixiao0821@gmail.com">liuyixiao</a>
 */
class StringTopNCounterTest {
    
    private StringTopNCounter stringTopNCounter;
    
    @BeforeEach
    void setUp() {
        stringTopNCounter = new StringTopNCounter();
    }
    
    @AfterEach
    void tearDown() {
        stringTopNCounter.reset();
        EnvUtil.setEnvironment(new MockEnvironment());
        TopNConfig.getInstance().onEvent(new ServerConfigChangeEvent());
    }
    
    @Test
    void testSet() {
        stringTopNCounter.set("test1", 1);
        List<Pair<String, AtomicInteger>> actual = stringTopNCounter.getCounterOfTopN(10);
        assertTopNCounter(actual, 1, new String[] {"test1"}, new Integer[] {1});
    }
    
    @Test
    void testIncrement() {
        stringTopNCounter.set("test", 0);
        assertTopNCounter(stringTopNCounter.getCounterOfTopN(10), 1, new String[] {"test"}, new Integer[] {0});
        stringTopNCounter.increment("test");
        assertTopNCounter(stringTopNCounter.getCounterOfTopN(10), 1, new String[] {"test"}, new Integer[] {1});
    }
    
    @Test
    void testReset() {
        stringTopNCounter.set("test", 1);
        stringTopNCounter.set("test1", 2);
        stringTopNCounter.set("test2", 3);
        assertTopNCounter(stringTopNCounter.getCounterOfTopN(10), 3, new String[] {"test2", "test1", "test"}, new Integer[] {3, 2, 1});
        stringTopNCounter.reset();
        assertTopNCounter(stringTopNCounter.getCounterOfTopN(10), 0, new String[] {}, new Integer[] {});
    }
    
    @Test
    void testGetTopNCounter() {
        for (int i = 0; i < 20; i++) {
            stringTopNCounter.set("test" + i, i);
        }
        assertTopNCounter(stringTopNCounter.getCounterOfTopN(10), 10,
                new String[] {"test19", "test18", "test17", "test16", "test15", "test14", "test13", "test12", "test11", "test10"},
                new Integer[] {19, 18, 17, 16, 15, 14, 13, 12, 11, 10});
    }
    
    @Test
    void testForTopnDisabled() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("nacos.core.monitor.topn.enabled", "false");
        EnvUtil.setEnvironment(env);
        TopNConfig.getInstance().onEvent(new ServerConfigChangeEvent());
        stringTopNCounter.set("test", 1);
        stringTopNCounter.set("test1", 2);
        stringTopNCounter.set("test2", 3);
        assertTopNCounter(stringTopNCounter.getCounterOfTopN(10), 0, new String[] {}, new Integer[] {});
    }
    
    private void assertTopNCounter(List<Pair<String, AtomicInteger>> actual, int size, String[] keys, Integer[] value) {
        assertEquals(size, actual.size());
        for (int i = 0; i < size; i++) {
            assertTrue(Arrays.asList(keys).contains(actual.get(i).getFirst()));
            assertTrue(Arrays.asList(value).contains(actual.get(i).getSecond().get()));
        }
    }
}
