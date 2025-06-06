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

package com.alibaba.nacos.core.service;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.exception.api.NacosApiException;
import com.alibaba.nacos.api.model.response.Namespace;
import com.alibaba.nacos.api.model.v2.ErrorCode;
import com.alibaba.nacos.common.utils.NamespaceUtil;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.core.namespace.injector.NamespaceDetailInjectorHolder;
import com.alibaba.nacos.core.namespace.model.NamespaceTypeEnum;
import com.alibaba.nacos.core.namespace.model.TenantInfo;
import com.alibaba.nacos.core.namespace.repository.NamespacePersistService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * NamespaceOperationService.
 *
 * @author dongyafei
 * @date 2022/8/16
 */

@Service
public class NamespaceOperationService {
    
    private final NamespacePersistService namespacePersistService;
    
    private static final String DEFAULT_NAMESPACE_SHOW_NAME = "public";
    
    private static final String DEFAULT_NAMESPACE_DESCRIPTION = "Default Namespace";
    
    private static final int DEFAULT_QUOTA = 200;
    
    private static final String DEFAULT_CREATE_SOURCE = "nacos";
    
    private static final String DEFAULT_KP = "1";
    
    public NamespaceOperationService(NamespacePersistService namespacePersistService) {
        this.namespacePersistService = namespacePersistService;
    }
    
    public List<Namespace> getNamespaceList() {
        // TODO 获取用kp
        List<TenantInfo> tenantInfos = namespacePersistService.findTenantByKp(DEFAULT_KP);
        
        Namespace namespace0 = new Namespace(NamespaceUtil.getNamespaceDefaultId(), DEFAULT_NAMESPACE_SHOW_NAME,
                DEFAULT_NAMESPACE_DESCRIPTION, DEFAULT_QUOTA, 0, NamespaceTypeEnum.GLOBAL.getType());
        NamespaceDetailInjectorHolder.getInstance().injectDetail(namespace0);
        List<Namespace> namespaceList = new ArrayList<>();
        namespaceList.add(namespace0);
        
        for (TenantInfo tenantInfo : tenantInfos) {
            Namespace namespaceTmp = new Namespace(tenantInfo.getTenantId(), tenantInfo.getTenantName(),
                    tenantInfo.getTenantDesc(), DEFAULT_QUOTA, 0, NamespaceTypeEnum.CUSTOM.getType());
            NamespaceDetailInjectorHolder.getInstance().injectDetail(namespaceTmp);
            namespaceList.add(namespaceTmp);
        }
        return namespaceList;
    }
    
    /**
     * query namespace by namespace id.
     *
     * @param namespaceId namespace Id.
     * @return Namespace.
     */
    public Namespace getNamespace(String namespaceId) throws NacosException {
        return getNamespace(namespaceId, NamespaceTypeEnum.CUSTOM);
    }
    
    /**
     * query namespace by namespace id and type.
     *
     * @param namespaceId namespace Id.
     * @param type        namespace type.
     * @return Namespace.
     */
    public Namespace getNamespace(String namespaceId, NamespaceTypeEnum type) throws NacosException {
        Namespace result;
        if (StringUtils.isBlank(namespaceId) || namespaceId.equals(NamespaceUtil.getNamespaceDefaultId())) {
            result = new Namespace(namespaceId, DEFAULT_NAMESPACE_SHOW_NAME, DEFAULT_NAMESPACE_DESCRIPTION,
                    DEFAULT_QUOTA, 0, NamespaceTypeEnum.GLOBAL.getType());
            
        } else {
            String typeString = String.valueOf(type.getType());
            TenantInfo tenantInfo = namespacePersistService.findTenantByKp(typeString, namespaceId);
            if (null == tenantInfo) {
                throw new NacosApiException(HttpStatus.NOT_FOUND.value(), ErrorCode.NAMESPACE_NOT_EXIST,
                        "namespaceId [ " + namespaceId + " ] not exist");
            }
            result = new Namespace(namespaceId, tenantInfo.getTenantName(), tenantInfo.getTenantDesc(), DEFAULT_QUOTA,
                    0, NamespaceTypeEnum.CUSTOM.getType());
        }
        NamespaceDetailInjectorHolder.getInstance().injectDetail(result);
        return result;
    }
    
    /**
     * create namespace.
     *
     * @param namespaceId   namespace ID
     * @param namespaceName namespace Name
     * @param namespaceDesc namespace Desc
     * @return whether create ok
     */
    public Boolean createNamespace(String namespaceId, String namespaceName, String namespaceDesc)
            throws NacosException {
        return createNamespace(namespaceId, namespaceName, namespaceDesc, NamespaceTypeEnum.CUSTOM);
    }
    
    /**
     * create namespace.
     *
     * @param namespaceId   namespace ID
     * @param namespaceName namespace Name
     * @param namespaceDesc namespace Desc
     * @param type          namespace type, see {@link NamespaceTypeEnum}
     * @return whether create ok
     */
    public Boolean createNamespace(String namespaceId, String namespaceName, String namespaceDesc,
            NamespaceTypeEnum type) throws NacosException {
        isNamespaceExist(namespaceId);
        String typeString = String.valueOf(type.getType());
        namespacePersistService.insertTenantInfoAtomic(typeString, namespaceId, namespaceName, namespaceDesc,
                DEFAULT_CREATE_SOURCE, System.currentTimeMillis());
        return true;
    }
    
    /**
     * edit namespace.
     */
    public Boolean editNamespace(String namespaceId, String namespaceName, String namespaceDesc) {
        namespacePersistService.updateTenantNameAtomic(DEFAULT_KP, namespaceId, namespaceName, namespaceDesc);
        return true;
    }
    
    /**
     * remove namespace.
     */
    public Boolean removeNamespace(String namespaceId) {
        namespacePersistService.removeTenantInfoAtomic(DEFAULT_KP, namespaceId);
        return true;
    }
    
    /**
     * check namespace exist.
     */
    public boolean isNamespaceExist(String namespaceId) throws NacosApiException {
        if (NamespaceUtil.isDefaultNamespaceId(namespaceId)) {
            throw new NacosApiException(HttpStatus.BAD_REQUEST.value(), ErrorCode.NAMESPACE_ALREADY_EXIST,
                    "namespaceId [" + namespaceId + "] is default namespace id and already exist.");
        }
        if (namespacePersistService.tenantInfoCountByTenantId(namespaceId) > 0) {
            throw new NacosApiException(HttpStatus.BAD_REQUEST.value(), ErrorCode.NAMESPACE_ALREADY_EXIST,
                    "namespaceId [" + namespaceId + "] already exist.");
        }
        return false;
    }
}
