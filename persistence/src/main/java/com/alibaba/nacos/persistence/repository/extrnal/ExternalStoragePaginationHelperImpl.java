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

package com.alibaba.nacos.persistence.repository.extrnal;

import com.alibaba.nacos.api.model.Page;
import com.alibaba.nacos.persistence.repository.PaginationHelper;
import com.alibaba.nacos.persistence.repository.embedded.EmbeddedStorageContextHolder;
import com.alibaba.nacos.plugin.datasource.model.MapperResult;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.util.List;

/**
 * External Storage Pagination utils.
 *
 * @author <a href="mailto:liaochuntao@live.com">liaochuntao</a>
 */

public class ExternalStoragePaginationHelperImpl<E> implements PaginationHelper<E> {
    
    private final JdbcTemplate jdbcTemplate;
    
    public ExternalStoragePaginationHelperImpl(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }
    
    /**
     * Take paging.
     *
     * @param sqlCountRows query total SQL
     * @param sqlFetchRows query data sql
     * @param args         query parameters
     * @param pageNo       page number
     * @param pageSize     page size
     * @param rowMapper    {@link RowMapper}
     * @return Paginated data {@code <E>}
     */
    @Override
    public Page<E> fetchPage(final String sqlCountRows, final String sqlFetchRows, final Object[] args,
            final int pageNo, final int pageSize, final RowMapper rowMapper) {
        return fetchPage(sqlCountRows, sqlFetchRows, args, pageNo, pageSize, null, rowMapper);
    }
    
    @Override
    public Page<E> fetchPage(final String sqlCountRows, final String sqlFetchRows, Object[] args, final int pageNo,
            final int pageSize, final Long lastMaxId, final RowMapper rowMapper) {
        return doFetchPage(sqlCountRows, args, sqlFetchRows, args, pageNo, pageSize, rowMapper);
    }
    
    @Override
    public Page<E> fetchPageLimit(final String sqlCountRows, final String sqlFetchRows, final Object[] args,
            final int pageNo, final int pageSize, final RowMapper rowMapper) {
        return doFetchPage(sqlCountRows, null, sqlFetchRows, args, pageNo, pageSize, rowMapper);
    }
    
    @Override
    public Page fetchPageLimit(MapperResult countMapperResult, MapperResult mapperResult, int pageNo, int pageSize,
            RowMapper rowMapper) {
        return fetchPageLimit(countMapperResult.getSql(), countMapperResult.getParamList().toArray(),
                mapperResult.getSql(), mapperResult.getParamList().toArray(), pageNo, pageSize, rowMapper);
    }
    
    @Override
    public Page<E> fetchPageLimit(final String sqlCountRows, final Object[] args1, final String sqlFetchRows,
            final Object[] args2, final int pageNo, final int pageSize, final RowMapper rowMapper) {
        return doFetchPage(sqlCountRows, args1, sqlFetchRows, args2, pageNo, pageSize, rowMapper);
    }
    
    @Override
    public Page<E> fetchPageLimit(final String sqlFetchRows, final Object[] args, final int pageNo, final int pageSize,
            final RowMapper rowMapper) {
        checkPageInfo(pageNo, pageSize);
        // Create Page object
        final Page<E> page = new Page<>();
        List<E> result = jdbcTemplate.query(sqlFetchRows, args, rowMapper);
        for (E item : result) {
            page.getPageItems().add(item);
        }
        return page;
    }
    
    @Override
    public void updateLimit(final String sql, final Object[] args) {
        try {
            jdbcTemplate.update(sql, args);
        } finally {
            EmbeddedStorageContextHolder.cleanAllContext();
        }
    }
    
    private void checkPageInfo(final int pageNo, final int pageSize) {
        if (pageNo <= 0 || pageSize <= 0) {
            throw new IllegalArgumentException("pageNo and pageSize must be greater than zero");
        }
    }
    
    private Page<E> doFetchPage(final String sqlCountRows, final Object[] countAgrs, final String sqlFetchRows,
            final Object[] fetchArgs, final int pageNo, final int pageSize, final RowMapper rowMapper) {
        checkPageInfo(pageNo, pageSize);
        // Query the total number of current records
        Integer rowCountInt = null;
        if (null != countAgrs) {
            rowCountInt = jdbcTemplate.queryForObject(sqlCountRows, countAgrs, Integer.class);
        } else {
            rowCountInt = jdbcTemplate.queryForObject(sqlCountRows, Integer.class);
        }
        if (null == rowCountInt) {
            throw new IllegalArgumentException("fetchPageLimit error");
        }
        
        // Compute pages count
        int pageCount = rowCountInt / pageSize;
        if (rowCountInt > pageSize * pageCount) {
            pageCount++;
        }
        
        // Create Page object
        final Page<E> page = new Page<>();
        page.setPageNumber(pageNo);
        page.setPagesAvailable(pageCount);
        page.setTotalCount(rowCountInt);
        
        if (pageNo > pageCount) {
            return page;
        }
        List<E> result = jdbcTemplate.query(sqlFetchRows, fetchArgs, rowMapper);
        for (E item : result) {
            page.getPageItems().add(item);
        }
        return page;
    }
}
