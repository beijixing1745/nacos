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

package com.alibaba.nacos.config.server.utils;

import com.alibaba.nacos.common.utils.NamespaceUtil;
import com.alibaba.nacos.config.server.constant.Constants;
import com.alibaba.nacos.config.server.model.ConfigListenState;
import com.alibaba.nacos.core.utils.StringPool;
import com.alibaba.nacos.common.utils.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.Writer;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.alibaba.nacos.config.server.constant.Constants.LINE_SEPARATOR;
import static com.alibaba.nacos.config.server.constant.Constants.WORD_SEPARATOR;

/**
 * MD5 util.
 *
 * @author Nacos
 */
@SuppressWarnings("PMD.ClassNamingShouldBeCamelRule")
public class MD5Util {
    
    /**
     * Compare Md5.
     */
    public static Map<String, ConfigListenState> compareMd5(HttpServletRequest request, HttpServletResponse response,
            Map<String, ConfigListenState> clientMd5Map) {
        return Md5ComparatorDelegate.getInstance().compareMd5(request, response, clientMd5Map);
    }
    
    /**
     * Compare old Md5.
     */
    public static String compareMd5OldResult(Map<String, ConfigListenState> changedGroupKeys) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, ConfigListenState> entry : changedGroupKeys.entrySet()) {
            String groupKey = entry.getKey();
            String[] dataIdGroupId = GroupKey2.parseKey(groupKey);
            sb.append(dataIdGroupId[0]);
            sb.append(':');
            sb.append(dataIdGroupId[1]);
            sb.append(';');
        }
        return sb.toString();
    }
    
    /**
     * Join and encode changedGroupKeys string.
     */
    public static String compareMd5ResultString(Map<String, ConfigListenState> changedGroupKeys) throws IOException {
        if (null == changedGroupKeys) {
            return "";
        }
        
        StringBuilder sb = new StringBuilder();
        
        for (Map.Entry<String, ConfigListenState> entry : changedGroupKeys.entrySet()) {
            String groupKey = entry.getKey();
            String[] dataIdGroupId = GroupKey2.parseKey(groupKey);
            sb.append(dataIdGroupId[0]);
            sb.append(WORD_SEPARATOR);
            sb.append(dataIdGroupId[1]);
            if (dataIdGroupId.length == 3) {
                if (StringUtils.isNotBlank(dataIdGroupId[2]) && !entry.getValue().isNamespaceTransfer()) {
                    sb.append(WORD_SEPARATOR);
                    sb.append(dataIdGroupId[2]);
                }
            }
            sb.append(LINE_SEPARATOR);
        }
        
        // To encode WORD_SEPARATOR and LINE_SEPARATOR invisible characters, encoded value is %02 and %01
        return URLEncoder.encode(sb.toString(), "UTF-8");
    }
    
    /**
     * Parse the transport protocol, which has two formats (W for field delimiter, L for each data delimiter) old: D w G
     * w MD5 l new: D w G w MD5 w T l.
     *
     * @param configKeysString protocol
     * @return protocol message
     */
    public static Map<String, ConfigListenState> getClientMd5Map(String configKeysString) {
        
        Map<String, ConfigListenState> md5Map = new HashMap<>(5);
        
        if (null == configKeysString || "".equals(configKeysString)) {
            return md5Map;
        }
        int start = 0;
        List<String> tmpList = new ArrayList<>(3);
        for (int i = start; i < configKeysString.length(); i++) {
            char c = configKeysString.charAt(i);
            if (c == WORD_SEPARATOR_CHAR) {
                tmpList.add(configKeysString.substring(start, i));
                start = i + 1;
                if (tmpList.size() > 3) {
                    // Malformed message and return parameter error.
                    throw new IllegalArgumentException("invalid protocol,too much key");
                }
            } else if (c == LINE_SEPARATOR_CHAR) {
                String endValue = "";
                if (start + 1 <= i) {
                    endValue = configKeysString.substring(start, i);
                }
                start = i + 1;
                
                String tenant;
                String md5;
                boolean ifNamespaceTransfer;
                // If it is the old message, the last digit is MD5. The post-multi-tenant message is tenant
                if (tmpList.size() == 2) {
                    tenant = "";
                    md5 = endValue;
                    ifNamespaceTransfer = NamespaceUtil.isNeedTransferNamespace(tenant);
                    tenant = NamespaceUtil.processNamespaceParameter(tenant);
                } else {
                    tenant = endValue;
                    md5 = tmpList.get(2);
                    ifNamespaceTransfer = NamespaceUtil.isNeedTransferNamespace(tenant);
                    tenant = NamespaceUtil.processNamespaceParameter(tenant);
                }
                ConfigListenState configListenState = new ConfigListenState(md5);
                configListenState.setNamespaceTransfer(ifNamespaceTransfer);
                
                String groupKey = GroupKey2.getKey(tmpList.get(0), tmpList.get(1), tenant);
                groupKey = StringPool.get(groupKey);
                md5Map.put(groupKey, configListenState);
                
                tmpList.clear();
                
                // Protect malformed messages
                if (md5Map.size() > 10000) {
                    throw new IllegalArgumentException("invalid protocol, too much listener");
                }
            }
        }
        return md5Map;
    }
    
    public static String toString(InputStream input, String encoding) throws IOException {
        return (null == encoding) ? toString(new InputStreamReader(input, Constants.ENCODE))
                : toString(new InputStreamReader(input, encoding));
    }
    
    /**
     * Reader to String.
     */
    public static String toString(Reader reader) throws IOException {
        CharArrayWriter sw = new CharArrayWriter();
        copy(reader, sw);
        return sw.toString();
    }
    
    /**
     * Copy data to buffer.
     */
    public static long copy(Reader input, Writer output) throws IOException {
        char[] buffer = new char[1024];
        long count = 0;
        for (int n = 0; (n = input.read(buffer)) >= 0; ) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }
    
    static final char WORD_SEPARATOR_CHAR = (char) 2;
    
    static final char LINE_SEPARATOR_CHAR = (char) 1;
    
}

